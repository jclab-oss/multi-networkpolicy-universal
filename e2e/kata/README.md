# Kata Containers e2e suite

Tests the TCX datapath with real Kata Containers VMs on a kind cluster:

| Suite | RuntimeClass | Kata runtime | `internetworking_model` |
|---|---|---|---|
| `tcfilter-ingress` | `kata-qemu` | Go | `tcfilter` (IPv4 and IPv6, mixed with a runc pod, daemon stop and kill) |
| `runtime-rs-egress` | `kata-qemu-runtime-rs` | Rust | `tcfilter` (egress with ports) |
| `macvtap-ingress` | `kata-qemu-macvtap` | Go | `macvtap` (IPv4) |
| `default-network` | `kata-qemu` | Go | `tcfilter`, net-attach-def as the primary network (`eth0`) |
| `default-network-macvtap` | `kata-qemu-macvtap` | Go | `macvtap`, net-attach-def as the primary network (`eth0`) |

```bash
cd e2e
./get_tools.sh
KATA_E2E_HOST_DEVTMPFS=1 ./kata/setup_cluster.sh   # cluster "kata"
./kata/run_tests.sh
./bin/kind delete cluster --name kata
```

The cluster's kubeconfig is written to `e2e/kata/kubeconfig`; your own
kubeconfig is not touched. Requirements: `/dev/kvm`, Linux 6.6+, Docker,
helm and bats.

`setup_cluster.sh` adapts the kind nodes, which are containers, to what Kata
expects from a host:

* `/dev/shm` is enlarged: Kata backs the VM memory with a file in it, and the
  container runtime limits it to 64 MiB.
* dbus is installed: runtime-rs creates the sandbox cgroup through systemd's
  D-Bus API.
* bpffs is mounted at `/sys/fs/bpf` for the daemon's pinned programs.
* With `KATA_E2E_HOST_DEVTMPFS=1`, the kernel's devtmpfs is mounted over the
  nodes' `/dev`, so the `/dev/tap<ifindex>` devices of new macvtap interfaces
  appear, which Kata's macvtap networking opens. devtmpfs is one instance
  shared with the host: CI enables it on its throwaway runner; without it the
  macvtap suite is skipped.

In this cluster, IPv6 neighbor discovery towards a macvtap-attached VM fails
with or without the daemon, so the macvtap suite tests IPv4 only.
