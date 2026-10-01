# Kata Containers and other sandboxed runtimes

Pods of a sandboxed runtime such as [Kata Containers](https://katacontainers.io/),
and pods that run a VM such as [Virtink](https://github.com/smartxworks/virtink)
and [KubeVirt](https://kubevirt.io/), run their workload inside a VM. The
nftables rules this daemon installs in the pod network namespace never see
their traffic:

| Runtime | How packets reach the VM | nftables `input`/`output` |
|---|---|---|
| Kata `tcfilter` (default) | TC `mirred` redirect between the CNI interface and the VM's tap device | bypassed: the redirect takes the packet before netfilter |
| Kata `macvtap` | macvtap device on top of the CNI interface | bypassed: the macvtap `rx_handler` takes the packet before the IP stack |
| Virtink `bridge`, KubeVirt bridge binding | a bridge in the pod namespace joins the CNI interface and the VM's tap device | bypassed: the frame is bridged and never reaches the namespace's IP stack |

For such pods the daemon enforces MultiNetworkPolicy with an eBPF program on
the TCX hooks (Linux 6.6+) of the device the VM's traffic passes instead. All other pods keep using nftables; one daemon handles
both, and a policy may select pods of both kinds.

## How it works

```text
tcfilter:  peer ──► net1 [TCX ingress] ──TCX_NEXT──► Kata tc redirect ──► tap ──► VM
           peer ◄── net1 [TCX egress]  ◄──────────── Kata tc redirect ◄── tap ◄── VM

macvtap:   peer ──► (lower device) ──► tapN_kata [TCX ingress] ──► VM
           peer ◄── (lower device) ◄── tapN_kata [TCX egress]  ◄── VM

bridge:    peer ──► eth0-nic [TCX ingress] ──► br-eth0 ──► tap-eth0 ──► VM
           peer ◄── eth0-nic [TCX egress]  ◄── br-eth0 ◄── tap-eth0 ◄── VM
           (eth0 is a dummy device holding the pod address: no traffic)
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
| Backend annotation changed | The previous backend's programs or nftables rules are removed and the new one applied |
| Pod annotated `tcx`, TCX datapath unavailable | The pod is not policed; the error is logged and retried |

## Enabling it

1. Choose the pods the TCX datapath polices, by RuntimeClass, by
   annotation, or both:

   ```
   --tcx-runtime-classes=kata,kata-qemu,kata-clh
   ```

   ```yaml
   metadata:
     annotations:
       multinetworkpolicy.io/backend: tcx   # or nftables
   ```

   A pod's backend is, in this order:

   1. the one its backend annotation names (`tcx` or `nftables`, case
      insensitive); the key is set with `--backend-annotation`;
   2. `tcx` if its `spec.runtimeClassName` is listed in
      `--tcx-runtime-classes`;
   3. `nftables`.

   A pod that runs a VM without a RuntimeClass of its own, such as a Virtink
   or KubeVirt VM pod, is selected by the annotation. Virtink copies the
   annotations of a `VirtualMachine` to its pod, so annotating the
   `VirtualMachine` with `multinetworkpolicy.io/backend: tcx` is enough.

   The annotation works in both directions: `nftables` keeps a pod of a
   listed RuntimeClass on nftables (for example a runtime class whose pods
   do reach netfilter), `tcx` moves any pod to the TCX datapath, a runc pod
   included, since the TCX hooks see its traffic as well. It can be changed on
   a running pod; the daemon then removes the pod's programs or nftables rules
   of the previous backend. A value other than `tcx` or `nftables` is logged
   and ignored.

2. Give the daemon bpffs. [`deploy-kata.yml`](../deploy-kata.yml) (overlay
   [`config/manager/overlays/kata`](../config/manager/overlays/kata)) mounts
   the host's `/sys/fs/bpf` and sets the containerd socket; adjust the runtime
   classes and the CRI endpoint to your cluster:

   ```
   kubectl create -f deploy-kata.yml
   ```

   With `--tcx-runtime-classes` set, the daemon does not start without a
   working TCX datapath. With only the annotation (the default
   `--backend-annotation`), a daemon without bpffs, such as the one from
   `deploy.yml`, starts without the datapath and reports every pod annotated
   `tcx` as not policed; it does not fall back to nftables, which cannot
   police a Kata pod.

| Flag | Default | Description |
|---|---|---|
| `--tcx-runtime-classes` | *(empty)* | RuntimeClass names policed through TCX |
| `--backend-annotation` | `multinetworkpolicy.io/backend` | Pod annotation that selects the backend, overriding `--tcx-runtime-classes`; empty disables it |
| `--bpf-pin-path` | `/sys/fs/bpf/multi-networkpolicy` | bpffs directory for the pinned programs and flow tables |
| `--tcx-flow-table-size` | `65536` | Connections tracked across all TCX-policed pods of the node |
| `--tcx-interface-rules` | `^(.+)$=${1}-nic` | Rules naming the device policed for a pod interface, see below |

### Which device is policed

The programs are attached to the device that actually carries the traffic of a
pod interface, which is not always the interface the pod's network status
names:

* Kata's `macvtap` model stacks a macvtap device on the interface. It is found
  from the link topology, nothing to configure.
* A runtime that bridges a VM to the pod interface **renames** it and leaves a
  dummy device behind under the original name. Virtink's bridge mode turns
  `eth0` into `eth0-nic`, enslaves it to `br-eth0` together with the VM's
  `tap-eth0`, and creates a dummy `eth0` that keeps the pod address so the
  address stays visible in the namespace; KubeVirt's bridge binding does the
  same. Only the renamed device carries traffic.

`--tcx-interface-rules` maps the name of a pod interface to the name of the
device to police, as `<regex>=<replacement>` split at the first `=`, with
`${1}`, `${2}` … expanding the submatches of the regular expression. The
default covers the rename above:

```
--tcx-interface-rules='^(.+)$=${1}-nic'
```

The first rule that both matches the interface and names a device the pod has
is used, otherwise the interface itself, so the default changes nothing for a
pod without a renamed device. Repeat the flag for more rules; they are tried
in order:

```
--tcx-interface-rules='^(.+)$=${1}-nic' --tcx-interface-rules='^net(\d+)$=vmtap${1}'
```

Pass it empty to disable the rules and always police the interface itself.

Because a dummy device carries no traffic, policing it would enforce nothing
at all. The daemon refuses to and reports the pod instead:

```
interface eth0: inspect interface: eth0 is a dummy device and carries no
traffic; name the device that does with --tcx-interface-rules
```

A `bridge` mode VM reaches the policy through the CNI interface only. Traffic
between the VM and the pod namespace itself, such as the DHCP server Virtink
runs on the bridge to hand the pod address to the VM, does not pass that
device and is not policed.

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

The datapath itself is also tested without Kata, against network namespace
setups that reproduce Kata's tc redirect filters and Virtink's bridge mode
(`pkg/tcx`, privileged tests).

Virtink has not been run in CI: its bridge mode is covered by the reproduced
topology only — a renamed interface enslaved to a bridge with the VM behind a
tap device, and a dummy device under the original name — which was read off
Virtink's `setupBridgeNetwork`.
