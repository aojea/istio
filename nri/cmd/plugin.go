// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/cni/pkg/nodeagent"
	"istio.io/istio/cni/pkg/util"
	"istio.io/istio/pkg/log"
)

type plugin struct {
	client          clientset.Interface
	nsLister        corelisters.NamespaceLister
	nsListerSynced  cache.InformerSynced
	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced

	nri  stub.Stub
	mask stub.EventMask

	podCache *nodeagent.PodCache
	ztunnel  nodeagent.ZtunnelServer

	mu            sync.RWMutex
	podNetns      map[string]string   // cache all the pod uid and the associated network namespace
	podAmbientIPs map[string][]string // cache the ambient pod uid and the associated IPs
}

func NewPlugin(clientset kubernetes.Interface, namespaceInformer coreinformers.NamespaceInformer, podInformer coreinformers.PodInformer) (*plugin, error) {
	p := &plugin{
		client:          clientset,
		nsLister:        namespaceInformer.Lister(),
		nsListerSynced:  namespaceInformer.Informer().HasSynced,
		podLister:       podInformer.Lister(),
		podListerSynced: podInformer.Informer().HasSynced,

		podCache: nodeagent.NewPodNetnsCache(nodeagent.OpenNetns),
	}

	// only interested on namespaces that change its state while active.
	// pods that are created are handled by the NRI interface that is the source
	// of truth for Pods on the Node, the informer in the agent can lag with the informer
	// in the kubelet. The informer is using a label selector so the events will be Add or Delete.
	_, err := namespaceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns, ok := obj.(*v1.Namespace)
			if !ok {
				return
			}
			// add the pods that are not already in the service mesh
			notAmbienMode, err := labels.NewRequirement("istio.io/dataplane-mode", selection.NotEquals, []string{"ambient"})
			if err != nil {
				return
			}
			pods, err := p.podLister.List(labels.NewSelector().Add(*notAmbienMode))
			if err != nil {
				return
			}
			for _, pod := range pods {
				if pod.Namespace != ns.Name {
					continue
				}
				// get the network namespace
				p.mu.RLock()
				ns := p.podNetns[string(pod.UID)]
				p.mu.RUnlock()
				if ns == "" {
					continue
				}

				podIPs := []string{}
				for _, ip := range pod.Status.PodIPs {
					podIPs = append(podIPs, ip.IP)
				}
				err := p.AddPodToMesh(context.Background(), pod, podIPs, ns)
				if err != nil {
					log.Debugf("fail to add pod %s/%s to ambient mesh", pod.GetNamespace(), pod.GetName())
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			ns, ok := obj.(*v1.Namespace)
			if !ok {
				return
			}
			// remove the pods that did not opted-in to be in the service mesh
			notAmbienMode, err := labels.NewRequirement("istio.io/dataplane-mode", selection.NotEquals, []string{"ambient"})
			if err != nil {
				return
			}
			pods, err := p.podLister.List(labels.NewSelector().Add(*notAmbienMode))
			if err != nil {
				return
			}
			for _, pod := range pods {
				if pod.Namespace != ns.Name {
					continue
				}
				// remove pod from mesh
				err := p.RemovePodFromMesh(context.Background(), string(pod.UID), false)
				if err != nil {
					log.Debugf("fail to remove pod %s/%s from ambient mesh", pod.GetNamespace(), pod.GetName())
				}
			}
		},
	})
	if err != nil {
		return nil, err
	}

	// only interested on pods that change its state while running
	// pods that are created are handled by the NRI interface that is the source
	// of truth for Pods on the Node, the informer in the agent can lag with the informer
	// in the kubelet.
	_, err = podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			oldPod, ok := old.(*v1.Pod)
			if !ok {
				return
			}
			newPod, ok := new.(*v1.Pod)
			if !ok {
				return
			}

			// if there are no changes nothing to do here
			if oldPod.Labels["istio.io/dataplane-mode"] == newPod.Labels["istio.io/dataplane-mode"] {
				return
			}

			// add pod to mesh
			if newPod.Labels["istio.io/dataplane-mode"] == "ambient" {
				p.mu.RLock()
				ns := p.podNetns[string(newPod.UID)]
				p.mu.RUnlock()
				if ns == "" {
					return
				}

				podIPs := []string{}
				for _, ip := range newPod.Status.PodIPs {
					podIPs = append(podIPs, ip.IP)
				}
				err := p.AddPodToMesh(context.Background(), newPod, podIPs, ns)
				if err != nil {
					log.Debugf("fail to add pod %s/%s to ambient mesh", newPod.GetNamespace(), newPod.GetName())
				}
			} else {
				// remove pod from mesh
				err := p.RemovePodFromMesh(context.Background(), string(newPod.UID), false)
				if err != nil {
					log.Debugf("fail to remove pod %s/%s from ambient mesh", newPod.GetNamespace(), newPod.GetName())
				}
			}
		},
	})
	if err != nil {
		return nil, err
	}

	// NRI options
	opts := []stub.Option{
		stub.WithOnClose(p.onClose),
	}
	opts = append(opts, stub.WithPluginName(pluginName))
	opts = append(opts, stub.WithPluginIdx(pluginIdx))

	if p.nri, err = stub.New(p, opts...); err != nil {
		return nil, fmt.Errorf("failed to create plugin stub: %w", err)
	}

	z, err := nodeagent.NewZtunnelServer(ZtunnelUDSAddress, p.podCache, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create ztunnel server: %w", err)
	}
	p.ztunnel = z

	return p, nil
}

func getNetworkNamespace(pod *api.PodSandbox) string {
	// get the pod network namespace
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			return namespace.Path
		}
	}
	return ""
}

func (p *plugin) Start(ctx context.Context) error {
	if ok := cache.WaitForCacheSync(ctx.Done(), p.nsListerSynced, p.podListerSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	log.Debug("starting ztunnel server")
	go p.ztunnel.Run(ctx)

	if err := p.nri.Run(ctx); err != nil {
		return fmt.Errorf("plugin exited: %w", err)
	}

	return nil
}

func (p *plugin) Stop() {
	p.ztunnel.Close()
	p.nri.Stop()
}

func (p *plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log.Infof("Synchronized state with the runtime (%d pods)", len(pods))

	for _, pod := range pods {
		log.Infof("pod %s/%s: namespace=%s ips=%v", pod.GetNamespace(), pod.GetName(), getNetworkNamespace(pod), pod.GetIps())
		// get the pod network namespace
		ns := getNetworkNamespace(pod)
		p.mu.Lock()
		p.podNetns[pod.Uid] = ns
		p.mu.Unlock()
		// host network pods are skipped
		if ns == "" {
			continue
		}
		v1pod, ok := p.isAmbientPod(pod)
		if !ok {
			return nil, nil
		}
		err := p.AddPodToMesh(ctx, v1pod, pod.GetIps(), ns)
		if err != nil {
			log.Debugf("fail to add pod %s/%s to ambient mesh", pod.GetNamespace(), pod.GetName())
		}
	}

	return nil, nil
}

func (p *plugin) Shutdown(ctx context.Context) {
	log.Info("Runtime shutting down...")
}

func (p *plugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log.Infof("Started pod %s/%s: namespace=%s ips=%v", pod.GetNamespace(), pod.GetName(), getNetworkNamespace(pod), pod.GetIps())
	ns := getNetworkNamespace(pod)
	p.mu.Lock()
	p.podNetns[pod.Uid] = ns
	p.mu.Unlock()
	// host network pods are skipped
	if ns == "" {
		return nil
	}
	v1pod, ok := p.isAmbientPod(pod)
	if !ok {
		return nil
	}
	err := p.AddPodToMesh(ctx, v1pod, pod.GetIps(), ns)
	if err != nil {
		log.Debugf("fail to add pod %s/%s to ambient mesh", pod.GetNamespace(), pod.GetName())
		return err
	}
	return nil
}

func (p *plugin) StopPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log.Infof("Stopped pod %s/%s: ips=%v", pod.GetNamespace(), pod.GetName(), pod.GetIps())

	err := p.RemovePodFromMesh(ctx, pod.Uid, true)
	// don't block deletion the OS should handle it
	if err != nil {
		log.Debugf("fail to add pod %s/%s to ambient mesh", pod.GetNamespace(), pod.GetName())
	}

	p.mu.Lock()
	delete(p.podNetns, pod.Uid)
	p.mu.Unlock()

	return nil
}

func (p *plugin) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log.Infof("Removed pod %s/%s: ips=%v", pod.GetNamespace(), pod.GetName(), pod.GetIps())
	return nil
}

func (p *plugin) onClose() {
	log.Infof("Connection to the runtime lost, exiting...")
}

// TODO: this is just a hack to get the PoC going
func (p *plugin) isAmbientPod(pod *api.PodSandbox) (*v1.Pod, bool) {
	for i := 0; i < 30; i++ { // allow 3 seconds lag between informer and runtime
		time.Sleep(100 * time.Second)
		ns, err := p.nsLister.Get(pod.Namespace)
		if ns == nil || err != nil {
			continue
		}
		pod, err := p.podLister.Pods(pod.Namespace).Get(pod.Name)
		if pod == nil || err != nil {
			continue
		}
		if util.PodRedirectionEnabled(ns, pod) {
			return pod, true
		}
		return pod, false
	}
	return nil, false
}

// AddPodToMesh adds a pod to mesh by
// 1. Getting the netns (and making sure the netns is cached in the ztunnel state of the world snapshot)
// 2. Adding the pod's IPs to the hostnetns ipsets for node probe checks
// 3. Creating iptables rules inside the pod's netns
// 4. Notifying the connected ztunnel via GRPC to create a proxy for the pod
//
// You may ask why we pass the pod IPs separately from the pod manifest itself (which contains the pod IPs as a field)
// - this is because during add specifically, if CNI plugins have not finished executing,
// K8S may get a pod Add event without any IPs in the object, and the pod will later be updated with IPs.
//
// We always need the IPs, but this is fine because this AddPodToMesh can be called from the CNI plugin as well,
// which always has the firsthand info of the IPs, even before K8S does - so we pass them separately here because
// we actually may have them before K8S in the Pod object.
func (p *plugin) AddPodToMesh(ctx context.Context, pod *v1.Pod, podIPs []string, netNs string) error {
	log := log.WithLabels("ns", pod.Namespace, "name", pod.Name)
	log.Infof("adding pod to the mesh")
	openNetns, err := p.podCache.UpsertPodCache(pod, netNs)
	if err != nil {
		log.Errorf("faile to add pod to cache: %v", err)
	}

	p.mu.Lock()
	p.podAmbientIPs[string(pod.UID)] = podIPs
	ambientIPs := []string{}
	for _, ips := range p.podAmbientIPs {
		ambientIPs = append(ambientIPs, ips...)
	}
	p.mu.Unlock()
	log.Debug("calling SyncHostRules")
	err = SyncHostRules(ambientIPs)
	if err != nil {
		log.Errorf("failed to add host rules to detect kubelet probes: %v", err)
	}

	log.Debug("calling SyncRouteRules")
	err = SyncRouteRules(int(openNetns.Fd()))
	if err != nil {
		log.Errorf("failed to add pod redirection rules: %v", err)
		return err
	}

	log.Debug("calling CreateInpodRules")
	err = SyncRules(int(openNetns.Fd()))
	if err != nil {
		log.Errorf("failed to add pod redirection rules: %v", err)
		return err
	}

	// For *any* failures after calling `CreateInpodRules`, we must return PartialAdd error.
	// The pod was injected with iptables rules, so it must be annotated as "inpod" - even if
	// the following fails.
	// This is so that if it is removed from the mesh, the inpod rules will unconditionally
	// be removed.

	log.Debug("notifying subscribed node proxies")
	if err := p.ztunnel.PodAdded(ctx, pod, openNetns); err != nil {
		return nodeagent.NewErrPartialAdd(err)
	}
	return nil
}

// RemovePodFromMesh is called when a pod needs to be removed from the mesh.
//
// It:
// - Informs the connected ztunnel that the pod no longer needs to be proxied.
// - Removes the pod's netns file handle from the cache/state of the world snapshot.
// - Steps into the pod netns to remove the inpod iptables redirection rules.
func (p *plugin) RemovePodFromMesh(ctx context.Context, podUID string, isDelete bool) error {
	log := log.WithLabels("uid", podUID)
	log.WithLabels("delete", isDelete).Debugf("removing pod from the mesh")

	// Aggregate errors together, so that if part of the cleanup fails we still proceed with other steps.
	var errs []error

	// Whether pod is already deleted or not, we need to let go of our netns ref.
	openNetns := p.podCache.Take(podUID)
	if openNetns == nil {
		log.Debug("failed to find pod netns during removal")
	}

	p.mu.Lock()
	delete(p.podAmbientIPs, string(podUID))
	ambientIPs := []string{}
	for _, ips := range p.podAmbientIPs {
		ambientIPs = append(ambientIPs, ips...)
	}
	p.mu.Unlock()
	log.Debug("calling SyncHostRules")
	err := SyncHostRules(ambientIPs)
	if err != nil {
		log.Errorf("faile to add host rules to detect kubelet probes: %v", err)
	}

	// If the pod is already deleted or terminated, we do not need to clean up the pod network -- only the host side.
	if !isDelete {
		if openNetns != nil {
			// pod is removed from the mesh, but is still running. remove iptables rules
			log.Debugf("calling DeleteInpodRules")
			CleanRules(int(openNetns.Fd()))
		} else {
			log.Warn("pod netns already gone, not deleting inpod rules")
		}
	}

	log.Debug("removing pod from ztunnel")
	if err := p.ztunnel.PodDeleted(ctx, podUID); err != nil {
		log.Errorf("failed to delete pod from ztunnel: %v", err)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
