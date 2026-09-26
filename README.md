# multi-networkpolicy-nftables

[![build](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/build.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/build.yml)
[![test](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/test.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/test.yml)
[![lint](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/golangci-lint.yml)
[![e2e](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/kind-e2e.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/kind-e2e.yml)
[![CodeQL](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/codeql.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/telekom/multi-networkpolicy-nftables)](https://goreportcard.com/report/github.com/telekom/multi-networkpolicy-nftables)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

[multi-networkpolicy](https://github.com/telekom/multi-networkpolicy) implementation with nftables

## Current Status of the Repository

It is now being actively developed and is not stable yet. Bug reports and feature requests are welcome.

## Description

Kubernetes provides [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) for network security. Currently net-attach-def does not support Network Policies because net-attach-def is a CRD (user-defined resource) outside of Kubernetes.
multi-networkpolicy implements Network Policy functionality for net-attach-def, by nftables and provides network security for net-attach-def networks.
Pods of sandboxed runtimes such as Kata Containers, whose traffic bypasses netfilter, are policed by an eBPF program on the TCX hooks of their interfaces instead (see [Kata Containers and other sandboxed runtimes](#kata-containers-and-other-sandboxed-runtimes)).

## Architecture

multi-networkpolicy-nftables runs as a DaemonSet on each Kubernetes node. It watches for MultiNetworkPolicy custom resources and translates them into nftables rules applied directly in pod network namespaces.

### Components

- **Controllers** (`pkg/controllers/`): Watch Kubernetes resources (Pods, Namespaces, MultiNetworkPolicies, NetworkAttachmentDefinitions) using client-go informers.
- **Server** (`pkg/server/`): Core orchestration and sync loop that coordinates controllers and triggers rule generation.
- **Rule Generator** (`pkg/server/netfilterrules.go`): Translates MultiNetworkPolicy specs into nftables rule sets using the google/nftables library.
- **TCX Datapath** (`pkg/tcx/`, `bpf/policy.c`): For pods of the RuntimeClasses in `--tcx-runtime-classes`, compiles the policies into BPF tables and attaches `bpf/policy.c` to the TCX ingress/egress hooks of the pod's interfaces.

### How It Works

1. The daemon watches for changes to MultiNetworkPolicy resources and related objects (Pods, Namespaces, NetworkAttachmentDefinitions).
2. On each sync cycle, it determines which pods are affected by which policies.
3. For each affected pod, it enters the pod's network namespace and applies nftables rules that enforce the specified ingress/egress policies. Pods of a sandboxed runtime listed in `--tcx-runtime-classes` get TCX programs instead.
4. When policies are removed, the corresponding nftables rules are cleaned up automatically.

![Multi NetworkPolicy Overview](docs/images/multi-networkpolicy-overview.png)

## Quickstart

Install MultiNetworkPolicy CRD into Kubernetes.

```
$ git clone https://github.com/k8snetworkplumbingwg/multi-networkpolicy
$ cd multi-networkpolicy
$ kubectl create -f scheme.yml
customresourcedefinition.apiextensions.k8s.io/multi-networkpolicies.k8s.cni.cncf.io created
```

Deploy multi-networkpolicy-nftables into Kubernetes.

```
$ git clone https://github.com/telekom/multi-networkpolicy-nftables
$ cd multi-networkpolicy-nftables
$ kubectl create -f deploy.yml
serviceaccount/multi-networkpolicy created
clusterrole.rbac.authorization.k8s.io/multi-networkpolicy created
clusterrolebinding.rbac.authorization.k8s.io/multi-networkpolicy created
daemonset.apps/multi-networkpolicy-ds-amd64 created
```

## Kata Containers and other sandboxed runtimes

Kata Containers connects the VM to the pod's CNI interfaces with a TC redirect
(`internetworking_model = "tcfilter"`, the default) or a macvtap device
(`"macvtap"`). Both bypass the netfilter hooks the nftables rules live in, so
those rules have no effect on Kata pods. For pods of the RuntimeClasses listed
in `--tcx-runtime-classes`, the daemon attaches an eBPF program to the TCX
ingress and egress hooks of the device the VM's traffic passes instead:

```text
tcfilter:  peer ──► net1 [TCX ingress: policy] ──TCX_NEXT──► Kata tc redirect ──► VM
           peer ◄── net1 [TCX egress:  policy] ◄──────────── Kata tc redirect ◄── VM
macvtap:   peer ◄─► tapN_kata [TCX ingress/egress: policy] ◄─► VM
```

* Kata itself is not modified: with `tcfilter` the programs run before
  Kata's tc filters and hand accepted packets on to them; with `macvtap` they
  sit on the macvtap device Kata created for the interface.
* Policies compile to LPM tries of peer addresses and ports mapped to rule
  bitmaps, so the number of TC objects does not grow with the policy.
* Policy updates are atomic (`bpf_link_update`), established connections
  are tracked in a flow table and survive policy changes, and the pinned
  programs keep enforcing while the daemon restarts after a crash.
* Runc pods on the same node keep using nftables; a policy can select pods of
  both kinds.

Deploy with the Kata overlay, which mounts bpffs and enables the flag for the
kata-deploy RuntimeClasses (adjust them and the CRI socket to your cluster):

```
$ kubectl create -f deploy-kata.yml
```

Requirements: Linux 6.6 or later and bpffs mounted at `/sys/fs/bpf`. See
[Kata Containers and other sandboxed runtimes](docs/kata.md) for the design,
flags, semantics, limits and troubleshooting.

## Requirements

This project leverages `nftables` hence the netfilter module needs to be loaded on the container host:

```
# modprobe nf_ct
# modprobe nf_tables
```

## Configurations

See [Configurations](docs/configurations.md).

### Generated Manifests

`deploy.yml`, `deploy-kata.yml`, `e2e/multi-network-policy-nftables-e2e.yml`
and `e2e/multi-network-policy-nftables-e2e-kata.yml` are generated from the
shared kustomize base under `config/manager`. Edit the base or an overlay,
then run:

```bash
make manifests
make verify-manifests
```

The e2e overlay only changes test-specific settings such as the local image,
containerd socket, sync period, network plugin list, verbosity, and privileged
mode. RBAC and shared mounts stay aligned with the normal deploy manifest.

## Development

### Prerequisites

- Go 1.24+ (see go.mod for exact version requirements)
- Linux with nftables support (for tests)
- Linux 6.6+ for the TCX datapath tests, clang to regenerate the BPF object
- Docker (for container image builds)
- [kind](https://kind.sigs.k8s.io/) (for e2e tests)
- [Bats](https://bats-core.readthedocs.io/) (for e2e tests; install via `brew install bats-core` or your package manager)

### Build

```bash
go build ./cmd/multi-networkpolicy-nftables/
```

### Test

Controller tests require envtest assets. CI installs them with
`setup-envtest`; locally, install the helper and export the asset path before
running tests:

```bash
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.24.1
export KUBEBUILDER_ASSETS="$(setup-envtest use 1.35.0 --bin-dir testbin/k8s -p path)"
```

Run unprivileged unit tests (controller/utils packages) with:

```bash
make test-unprivileged
```

Run the full nftables-backed test target (Linux + root/passwordless sudo required) with:

```bash
sudo modprobe nft_ct
make test
```

To run only the privileged suite directly:

```bash
make test-nftables
```

The privileged suite includes the TCX datapath tests in `pkg/tcx`: they load
`bpf/policy.c` and run packets through it with `BPF_PROG_TEST_RUN`, and they
build network namespaces that reproduce Kata's `tcfilter` redirect to test
real connections. They need `ip`, `tc` and bpffs at `/sys/fs/bpf`, and skip
themselves when not run as root.

### BPF program

`bpf/policy.c` is compiled into `pkg/tcx/policy_bpfel.o`, with Go bindings in
`pkg/tcx/policy_bpfel.go` (both committed, so building the daemon needs no
clang). After changing the C source, regenerate them with the clang of
Ubuntu 24.04 (18.1.3), which CI uses to check that they are up to date:

```bash
make bpf
make verify-bpf
```

### Lint

```bash
golangci-lint run
```

### E2E Tests

End-to-end tests use kind to create a cluster with Calico, Multus, and bond-cni:

```bash
cd e2e
./get_tools.sh
./setup_cluster.sh
./run_all_tests.sh
```

The Kata Containers suite in `e2e/kata` creates a separate kind cluster
(`kata`) with Kata Containers installed by kata-deploy, and tests policies on
pods of the Go and Rust runtimes with `tcfilter` networking and of the Go
runtime with `macvtap` networking. It needs `/dev/kvm` on the host:

```bash
cd e2e
./get_tools.sh
KATA_E2E_HOST_DEVTMPFS=1 ./kata/setup_cluster.sh
./kata/run_tests.sh
```

See [e2e/kata](e2e/kata/README.md) for what the setup changes on the kind
nodes (the macvtap suite needs `KATA_E2E_HOST_DEVTMPFS=1`).

## Roadmap

- Improved e2e test coverage and reliability
- Enhanced CI/CD pipeline with caching and security scanning
- Performance benchmarks for rule generation

## Contact Us

For any questions about Multus CNI, feel free to ask a question in #general in the [NPWG Slack](https://npwg-team.slack.com/), or open up a GitHub issue. Request an invite to NPWG slack [here](https://intel-corp.herokuapp.com/).
