// Package tcx enforces MultiNetworkPolicy with eBPF programs attached to the
// TCX ingress and egress hooks of a pod's interfaces.
//
// It serves pods whose traffic bypasses the netfilter hooks the nftables
// backend uses, such as Kata Containers pods: with the "tcfilter" networking
// model a TC mirred redirect moves packets between the CNI interface and the
// VM, with "macvtap" a macvtap device on top of the CNI interface does. The
// programs attach to the TCX hooks of the CNI interface, which run before the
// runtime's own legacy tc filters, or of the macvtap device, so the runtime's
// configuration is left untouched.
//
// Compile turns the policies that select a pod into per-interface tables
// (platform independent). Datapath loads bpf/policy.c with those tables,
// attaches it and pins the links in bpffs so enforcement survives a restart
// of the daemon.
package tcx

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -go-package tcx -tags linux -target bpfel -output-stem policy policy ../../bpf/policy.c -- -I../../bpf/include -O2 -g -Wall -Werror
