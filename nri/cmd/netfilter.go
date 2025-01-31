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
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"istio.io/istio/cni/pkg/iptables"
)

const (
	tableNamePod  = "istio-nri-pod"
	tableNameHost = "istio-nri-host"
	podV4IPsSet   = "podips-v4"
	podV6IPsSet   = "podips-v6"
	probesTOS     = 42
)

// Mark packets originated on the node that targets ambient Pods
func SyncHostRules(podIPs []string) error {
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("portmap failure, can not start nftables:%v", err)
	}

	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableNameHost,
	})

	// This ensures the sets and table are flushed
	nft.AddTable(table)
	nft.DelTable(table)
	nft.AddTable(table)

	// add set with Local Pod IPs on the mesh
	v4Set := &nftables.Set{
		Table:   table,
		Name:    podV4IPsSet,
		KeyType: nftables.TypeIPAddr,
	}
	v6Set := &nftables.Set{
		Table:   table,
		Name:    podV6IPsSet,
		KeyType: nftables.TypeIP6Addr,
	}

	var elementsV4, elementsV6 []nftables.SetElement
	for _, ip := range podIPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if addr.Is4() {
			elementsV4 = append(elementsV4, nftables.SetElement{
				Key: addr.AsSlice(),
			})
		} else if addr.Is6() {
			elementsV6 = append(elementsV6, nftables.SetElement{
				Key: addr.AsSlice(),
			})
		}
	}

	if err := nft.AddSet(v4Set, elementsV4); err != nil {
		return fmt.Errorf("failed to add Set %s : %v", v4Set.Name, err)
	}
	if err := nft.AddSet(v6Set, elementsV6); err != nil {
		return fmt.Errorf("failed to add Set %s : %v", v6Set.Name, err)
	}

	chain := nft.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	//  meta skuid 0 ip dscp set 42
	// [ meta load skuid => reg 1 ]
	// [ cmp eq reg 1 0x00000000 ]
	// [ meta load nfproto => reg 1 ]
	// [ cmp eq reg 1 0x00000002 ]
	// [ payload load 2b @ network header + 0 => reg 1 ]
	// [ bitwise reg 1 = ( reg 1 & 0x000003ff ) ^ 0x0000a800 ]
	// [ payload write reg 1 => 2b @ network header + 0 csum_type 1 csum_off 10 csum_flags 0x0 ]
	// [ counter pkts 0 bytes 0 ]
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeySKUID, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{0x0, 0x0, 0x0, 0x0}},
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: v4Set.Name},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 2},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 4, Mask: []byte{0x0, 0x0, 0x03, 0xff}, Xor: []byte{0x0, 0x0, 0xa8, 0x00}},
			&expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, CsumType: expr.CsumTypeInet, CsumOffset: 10, CsumFlags: unix.NFT_PAYLOAD_CSUM_NONE},
			&expr.Counter{},
		},
	})

	// TODO IPv6

	err = nft.Flush()
	if err != nil {
		return fmt.Errorf("failed to create %s table: %v", tableNameHost, err)
	}
	return nil
}

// https://github.com/istio/istio/blob/c3ab6023f2867716455dfc1e1bde7e34845b0f44/tools/istio-iptables/pkg/capture/run_linux.go#L29C1-L87C2
func SyncRouteRules(containerNs int) error {
	// get the socket inside the namespace to avoid problem with golang and goroutines and net namespaces
	nhNs, err := netlink.NewHandleAt(netns.NsHandle(containerNs))
	if err != nil {
		return err
	}

	link, err := nhNs.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to find 'lo' link: %v", err)
	}

	r := netlink.NewRule()
	r.Family = unix.AF_INET // TODO IPv6
	r.Table = iptables.RouteTableInbound
	r.Mark = iptables.InpodTProxyMark
	// If the interface is loopback, the rule only matches packets originating from this host.
	// https://man7.org/linux/man-pages/man8/ip-rule.8.html
	r.IifName = "lo"
	if err := nhNs.RuleAdd(r); err != nil {
		return fmt.Errorf("failed to configure netlink rule: %v", err)
	}

	// Send all routes that need to be transparently proxied through the lo interface
	// so it picks the rule in the PREROUTING table to redirect to the proxy
	// Equivalent to `ip route add local default dev lo table <table>`
	cidrs := []string{"0.0.0.0/0"}
	for _, fullCIDR := range cidrs {
		_, dst, err := net.ParseCIDR(fullCIDR)
		if err != nil {
			return fmt.Errorf("parse CIDR: %v", err)
		}

		err = nhNs.RouteAdd(&netlink.Route{
			Dst:       dst,
			Scope:     netlink.SCOPE_HOST,
			Type:      unix.RTN_LOCAL,
			Table:     iptables.RouteTableInbound,
			LinkIndex: link.Attrs().Index,
		})
		if err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "file exists") {
				return fmt.Errorf("failed to add route: %v", err)
			}

		}
	}
	return nil
}

// SyncRules syncs ip masquerade rules
func SyncRules(netNsFd int) error {
	nft, err := nftables.New(nftables.WithNetNSFd(netNsFd))
	if err != nil {
		return fmt.Errorf("indpod failure, can not start nftables: %v", err)
	}

	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableNamePod,
	})
	nft.FlushTable(table)

	chainPre := nft.AddChain(&nftables.Chain{
		Name:     iptables.ChainInpodPrerouting,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	/*
			All the TCP incoming traffic from external interfaces that does not have the DSCP set to 42 redirect to the tunnel

			 nft --debug=netlink add rule inet kindnet-dnscache preroutingnat meta iifname != lo meta l4proto tcp ip dscp != 42 redirect to 10053
		inet kindnet-dnscache preroutingnat
		  [ meta load iifname => reg 1 ]
		  [ cmp neq reg 1 0x00006f6c 0x00000000 0x00000000 0x00000000 ]
		  [ meta load l4proto => reg 1 ]
		  [ cmp eq reg 1 0x00000006 ]
		  [ meta load nfproto => reg 1 ]
		  [ cmp eq reg 1 0x00000002 ]
		  [ payload load 1b @ network header + 1 => reg 1 ]
		  [ bitwise reg 1 = ( reg 1 & 0x000000fc ) ^ 0x00000000 ]
		  [ cmp neq reg 1 0x000000a8 ]
		  [ immediate reg 1 0x00004527 ]
		  [ redir proto_min reg 1 flags 0x2 ]
	*/
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainPre,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: []uint8{0x6c, 0x6f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_TCP}},
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 0x1, Len: 0x1},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 0x1, Mask: []uint8{0xfc}, Xor: []uint8{0x0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: []byte{probesTOS}},
			&expr.Immediate{Register: 0x1, Data: binaryutil.BigEndian.PutUint16(iptables.ZtunnelInboundPlaintextPort)},
			&expr.Redir{RegisterProtoMin: 0x1, RegisterProtoMax: 0x1, Flags: 0x2},
		},
	})

	/*
		nft --debug=netlink add rule inet kindnet-dnscache preroutingnat meta mark 123 meta l4proto tcp redirect to 10053
		inet kindnet-dnscache preroutingnat
		  [ meta load mark => reg 1 ]
		  [ cmp eq reg 1 0x0000007b ]
		  [ meta load l4proto => reg 1 ]
		  [ cmp eq reg 1 0x00000006 ]
		  [ immediate reg 1 0x00004527 ]
		  [ redir proto_min reg 1 flags 0x2 ]
	*/
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainPre,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: binaryutil.PutInt32(iptables.InpodTProxyMark)},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_TCP}},
			&expr.Immediate{Register: 0x1, Data: binaryutil.BigEndian.PutUint16(iptables.ZtunnelOutboundPort)},
			&expr.Redir{RegisterProtoMin: 0x1, RegisterProtoMax: 0x1, Flags: 0x2},
		},
	})

	// OUTPUT needs to send to PREROUTING the packet that we want to redirect to the tunnel
	chainOut := nft.AddChain(&nftables.Chain{
		Name:     iptables.ChainInpodOutput,
		Table:    table,
		Type:     nftables.ChainTypeRoute,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	/*
		nft --debug=netlink add rule inet kindnet-ipmasq postrouting  meta oifname != lo meta l4proto tcp mark set 123
		inet kindnet-ipmasq postrouting
		  [ meta load oifname => reg 1 ]
		  [ cmp neq reg 1 0x00006f6c 0x00000000 0x00000000 0x00000000 ]
		  [ meta load l4proto => reg 1 ]
		  [ cmp eq reg 1 0x00000006 ]
		  [ immediate reg 1 0x0000007b ]
		  [ meta set mark with reg 1 ]
	*/
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainOut,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: []uint8{0x6c, 0x6f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_TCP}},
			&expr.Immediate{Register: 0x1, Data: binaryutil.PutInt32(iptables.InpodTProxyMark)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
		},
	})

	err = nft.Flush()
	if err != nil {
		return fmt.Errorf("failed to create %s table: %v", tableNamePod, err)
	}
	return nil
}

func CleanRules(netNsFd int) {
	nft, err := nftables.New(nftables.WithNetNSFd(netNsFd))
	if err != nil {
		return
	}
	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableNamePod,
	})
	nft.DelTable(table)

	err = nft.Flush()
	if err != nil {
		// TODO: log?
	}
}

// netlink is 4 bytes aligned
func encodeWithAlignment(data any) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, data)
	if err != nil {
		panic(err)
	}

	// Calculate padding
	padding := (4 - buf.Len()%4) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	return buf.Bytes()
}
