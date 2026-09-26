# Kata Containers and other sandboxed runtimes

Pods of a sandboxed runtime such as [Kata Containers](https://katacontainers.io/)
run inside a VM. The nftables rules this daemon installs in the pod network
namespace never see their traffic:

| Kata `internetworking_model` | How packets reach the VM | nftables `input`/`output` |
|---|---|---|
| `tcfilter` (default) | TC `mirred` redirect between the CNI interface and the VM's tap device | bypassed: the redirect takes the packet before netfilter |
| `macvtap` | macvtap device on top of the CNI interface | bypassed: the macvtap `rx_handler` takes the packet before the IP stack |

For such pods the daemon enforces MultiNetworkPolicy with an eBPF program on
the TCX hooks (Linux 6.6+) of the device the VM's traffic passes instead. All other pods keep using nftables; one daemon handles
both, and a policy may select pods of both kinds.

## How it works

```text
tcfilter:  peer ──► net1 [TCX ingress] ──TCX_NEXT──► Kata tc redirect ──► tap ──► VM
           peer ◄── net1 [TCX egress]  ◄──────────── Kata tc redirect ◄── tap ◄── VM

macvtap:   peer ──► (lower device) ──► tapN_kata [TCX ingress] ──► VM
           peer ◄── (lower device) ◄── tapN_kata [TCX egress]  ◄── VM
```

* **Nothing of the runtime is modified.** With `tcfilter`, the programs sit
  on the CNI interface and run before the legacy tc filters Kata installs; a
  packet the policy accepts continues with `TCX_NEXT` to Kata's own redirect,
  a denied packet is dropped. Traffic from the VM is redirected out of the
  CNI interface, where the egress program sees it.
* **macvtap.** With `macvtap`, the programs sit on the macvtap device Kata
  created for the interface. For a macvlan net-attach-def the CNI interface
  never sees the VM's traffic: the kernel stacks a macvtap created on a
  macvlan device directly on the macvlan's lower device. The daemon finds the
  macvtap device by its link: it is linked to the CNI interface (veth and
  similar), or shares the CNI interface's lower device (macvlan). If several
  interfaces of a pod share a lower device, their macvtap devices are matched
  in creation order.
* **Policy tables.** For each interface the daemon compiles the policies into
  LPM tries: one maps a peer address, one a protocol and destination port, to
  the set of policy rules it satisfies (a bitmap). A packet is accepted when
  one rule is satisfied by both. The number of TC objects is constant per
  interface, however many peers, CIDRs and ports the policies have.
* **Atomic updates.** A policy change loads a new program with fully
  populated tables and swaps it in with `bpf_link_update`; every packet is
  evaluated against either the old or the new policy.
* **Connection tracking.** Packets on these paths do not reach
  `nf_conntrack`, so accepted flows are recorded in a shared LRU table.
  Later packets of the flow in either direction, ICMP errors about it
  (`RELATED`: the error must quote the flow and go back to the quoted
  packet's sender) and non-first fragments of an accepted packet are
  accepted without evaluating the policy, as with the nftables backend's
  `ct state established,related accept`. Interfaces no policy isolates
  record no flows, so they cannot fill the shared table. Established connections therefore
  survive a policy change. Idle timeouts follow the `nf_conntrack` defaults
  (TCP established 5 days, closing or unanswered TCP 2 minutes, UDP and other
  protocols 2 minutes once answered and 30 seconds before).

### Failure behavior

| Event | Effect |
|---|---|
| Policy changes | New policy applied atomically; established connections continue |
| Daemon crashes or is killed | Programs are pinned in bpffs and **keep enforcing** the last policy |
| Daemon stops gracefully (rolling update, uninstall) | Programs removed, like the nftables rules |
| A policy cannot be compiled (named port, too many rules) | **Fails closed**: the directions it isolates accept no new connections until it is fixed; the error is logged and retried |
| Applying a pod's policy fails (kernel error) | The previously applied policy stays in place; the error is logged and retried |
| Pod sandbox recreated (new network namespace) | Stale pins are detected and the programs attached to the new interfaces |
| Pod deleted | Its programs are removed on the next reconcile |

## Enabling it

1. List the RuntimeClasses whose pods bypass netfilter:

   ```
   --tcx-runtime-classes=kata,kata-qemu,kata-clh
   ```

   Pods with `spec.runtimeClassName` in the list use the TCX datapath, all
   other pods nftables. Without the flag the TCX datapath is off.

2. Give the daemon bpffs. [`deploy-kata.yml`](../deploy-kata.yml) (overlay
   [`config/manager/overlays/kata`](../config/manager/overlays/kata)) mounts
   the host's `/sys/fs/bpf` and sets the containerd socket; adjust the runtime
   classes and the CRI endpoint to your cluster:

   ```
   kubectl create -f deploy-kata.yml
   ```

| Flag | Default | Description |
|---|---|---|
| `--tcx-runtime-classes` | *(empty)* | RuntimeClass names policed through TCX |
| `--bpf-pin-path` | `/sys/fs/bpf/multi-networkpolicy` | bpffs directory for the pinned programs and flow tables |
| `--tcx-flow-table-size` | `65536` | Connections tracked across all TCX-policed pods of the node |

### Requirements

* Linux 6.6 or later (TCX links).
* Ethernet interfaces (the program parses Ethernet frames; the daemon refuses
  other link types).
* bpffs mounted at `/sys/fs/bpf` on the host (systemd does this by default).
* The daemon's `SYS_ADMIN` and `NET_ADMIN` capabilities (already in
  `deploy.yml`) to load and attach the programs, and `SYS_PTRACE` with the
  `Unconfined` AppArmor profile to open the network namespace of a sandboxed
  pod.

## Supported policy features

Everything the nftables backend supports: `podSelector`, `namespaceSelector`,
`ipBlock` with `except`, TCP/UDP/SCTP ports and `endPort`, protocol-only ports,
IPv4 and IPv6, `--accept-icmp`, `--accept-icmpv6` (IPv6 neighbor discovery is
always accepted), `--allow-src-prefix` and `--allow-dst-prefix`. Named ports
are rejected, as by the nftables backend. Pods whose primary network is a
net-attach-def (Multus `v1.multus-cni.io/default-network` annotation) are
policed on `eth0`, see [Configurations](configurations.md).

The TCX datapath follows the MultiNetworkPolicy specification in these
points:

* An interface is isolated for a direction only by policies whose
  `policy-for` networks include the interface's network.
* Rules and policies are additive: an `ipBlock.except` only removes addresses
  from its own `ipBlock`, another rule can still allow them.
* A `podSelector` without `namespaceSelector` selects pods in the policy's
  namespace.
* A port entry without `protocol` means TCP.

In addition, VLAN-tagged frames are dropped on an isolated direction: the VM
controls the raw frames it sends, and the tag would hide the IP header from the
policy.

### Limits

* 512 policy rules per interface and direction (the sum of the ingress, or
  egress, rules of all policies that select the interface).
* Connections beyond `--tcx-flow-table-size` evict the least recently used
  entries; an evicted connection is evaluated against the policy again.
* The flow table tracks connections by address, protocol and ports with idle
  timeouts; it does not validate TCP sequence numbers like `nf_conntrack`.

## Troubleshooting

The daemon logs `tcx: applied policy <digest> to pod <uid> interface <name>`
(verbosity 2) whenever it loads a program. On the node, every policed
interface has two pinned links:

```
# ls /sys/fs/bpf/multi-networkpolicy/endpoints/<pod-uid>/<interface>/
egress  ingress
```

In the pod's network namespace, a recent `bpftool net show` lists the
attached `mnp_ingress` and `mnp_egress` programs (on the CNI interface for
`tcfilter`, on `tapN_kata` for `macvtap`). With `-v=4` the daemon logs which
device it polices an interface on.

A Kata pod whose RuntimeClass is missing from `--tcx-runtime-classes` gets
nftables rules that have no effect.

## Tested with

The [Kata e2e suite](../e2e/kata) runs in CI on kind with Kata Containers
4.2.0 (kata-deploy) on the GitHub-hosted Ubuntu 24.04 runner, and was run on
Linux 6.8 during development:

| RuntimeClass | Runtime | `internetworking_model` |
|---|---|---|
| `kata-qemu` | Go (`containerd-shim-kata-v2`) | `tcfilter`, IPv4 and IPv6 |
| `kata-qemu-runtime-rs` | Rust (runtime-rs) | `tcfilter` |
| `kata-qemu-macvtap` | Go | `macvtap` on a macvlan net-attach-def, IPv4 |

Each model is tested with the policed net-attach-def as a secondary network
(`net1`) and as the primary network (`eth0`, Multus default-network).

The datapath itself is also tested without Kata, against a network namespace
setup that reproduces Kata's tc redirect filters (`pkg/tcx`, privileged tests).
