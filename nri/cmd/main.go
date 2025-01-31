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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog/v2"

	"istio.io/istio/pkg/log"
)

var (
	hostnameOverride  string
	kubeconfig        string
	bindAddress       string
	ZtunnelUDSAddress string

	pluginName = "istio-nri"
	pluginIdx  = "00"
)

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&bindAddress, "bind-address", ":9177", "The IP address and port for the agents to serve on")
	flag.StringVar(&hostnameOverride, "hostname-override", "", "If non-empty, will be used as the name of the Node that istio-nri is running on. If unset, the node name is assumed to be the same as the node's hostname.")
	flag.StringVar(&ZtunnelUDSAddress, "ztunnel-address", "/var/run/ztunnel/ztunnel.sock", "The UDS server address which ztunnel will connect to")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: istio-nri [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	// Create context that cancels on termination signal
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func(sigChan chan os.Signal, cancel context.CancelFunc) {
		sig := <-sigChan
		log.Infof("Exit signal received: %s", sig)
		cancel()
	}(sigChan, cancel)

	if err := run(ctx); err != nil {
		log.Fatalf(err.Error())
	}
}

func run(ctx context.Context) error {
	flag.Parse()

	nodeName, err := nodeutil.GetHostname(hostnameOverride)
	if err != nil {
		return err
	}

	var config *rest.Config
	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		// creates the in-cluster config
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		return fmt.Errorf("can not create client-go configuration: %v", err)
	}

	// use protobuf for better performance at scale
	// https://kubernetes.io/docs/reference/using-api/api-concepts/#alternate-representations-of-resources
	config.UserAgent = "istio-nri"
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("can not create client-go client: %v", err)
	}

	ambientMode, err := labels.NewRequirement("istio.io/dataplane-mode", selection.Equals, []string{"ambient"})
	if err != nil {
		return err
	}

	nsInformerFactory := informers.NewSharedInformerFactoryWithOptions(clientset, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = ambientMode.String()
		}))
	podInformerFactory := informers.NewSharedInformerFactoryWithOptions(clientset, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = "spec.nodeName=" + nodeName
		}))

	nsInformer := nsInformerFactory.Core().V1().Namespaces()
	podInformer := podInformerFactory.Core().V1().Pods()

	p, err := NewPlugin(clientset, nsInformer, podInformer)
	if err != nil {
		return err
	}

	nsInformerFactory.Start(ctx.Done())
	podInformerFactory.Start(ctx.Done())

	if err := p.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}
