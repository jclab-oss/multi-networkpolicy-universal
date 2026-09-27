package tcx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
)

// RuleWords is the number of 64-bit words in a rule bitmap. It must match
// MNP_RULE_WORDS in bpf/policy.c.
const RuleWords = 8

// MaxRules is the number of policy rules one direction of an interface can
// hold: every ingress (or egress) rule of every policy that applies to the
// interface takes one bit.
const MaxRules = RuleWords * 64

// Direction indexes match DIR_INGRESS and DIR_EGRESS in bpf/policy.c.
type Direction int

const (
	// Ingress is traffic towards the pod; the peer is the source address.
	Ingress Direction = 0
	// Egress is traffic from the pod; the peer is the destination address.
	Egress Direction = 1
)

func (d Direction) String() string {
	if d == Ingress {
		return "ingress"
	}
	return "egress"
}

// RuleSet is a bitmap of policy rules, one bit per rule.
type RuleSet [RuleWords]uint64

// Set marks rule i as satisfied.
func (r *RuleSet) Set(i int) { r[i/64] |= 1 << (i % 64) }

// Has reports whether rule i is satisfied.
func (r RuleSet) Has(i int) bool { return r[i/64]&(1<<(i%64)) != 0 }

// Intersects reports whether both sets satisfy a common rule.
func (r RuleSet) Intersects(o RuleSet) bool {
	for i := range r {
		if r[i]&o[i] != 0 {
			return true
		}
	}
	return false
}

func (r RuleSet) or(o RuleSet) RuleSet {
	for i := range r {
		r[i] |= o[i]
	}
	return r
}

// PeerEntry is one element of a peer LPM trie. For an address, the longest
// matching entry carries every rule whose peers include the address, so no
// entry may be dropped even when its rule set is empty: it shadows the
// shorter prefixes an ipBlock.except carves out of.
type PeerEntry struct {
	Prefix netip.Prefix
	Rules  RuleSet
	// AllowCommon marks addresses covered by --allow-src-prefix (ingress)
	// or --allow-dst-prefix (egress), which are accepted unconditionally.
	AllowCommon bool
}

// PortPrefix is a protocol plus the Bits most significant bits of a port.
type PortPrefix struct {
	Proto uint8
	Port  uint16
	Bits  uint8
}

func (p PortPrefix) contains(o PortPrefix) bool {
	if p.Proto != o.Proto || p.Bits > o.Bits {
		return false
	}
	shift := 16 - uint(p.Bits)
	return uint32(p.Port)>>shift == uint32(o.Port)>>shift
}

// PortEntry is one element of the port LPM trie.
type PortEntry struct {
	PortPrefix
	Rules RuleSet
}

// DirectionPolicy is the compiled policy for one direction of one interface.
type DirectionPolicy struct {
	// Isolated is set when at least one policy selects the interface for
	// this direction. Traffic of a direction that is not isolated is
	// accepted.
	Isolated bool
	// WildPeer holds the rules without from/to peers (any peer matches).
	WildPeer RuleSet
	// WildPort holds the rules without ports (any protocol and port matches).
	WildPort RuleSet
	Peers    []PeerEntry
	Ports    []PortEntry
	// Rules names the policy rule behind each bit.
	Rules []string
}

// Allows evaluates the compiled policy for a new connection the way the BPF
// program does, minus connection tracking. The unit tests use it to check the
// compiler against the policy semantics.
func (d *DirectionPolicy) Allows(peer netip.Addr, proto uint8, port uint16, hasPorts bool) bool {
	if !d.Isolated {
		return true
	}
	peerRules, allowCommon := d.lookupPeer(peer)
	if allowCommon {
		return true
	}
	portRules := d.WildPort
	if hasPorts {
		portRules = portRules.or(d.lookupPort(proto, port))
	}
	return peerRules.or(d.WildPeer).Intersects(portRules)
}

func (d *DirectionPolicy) lookupPeer(addr netip.Addr) (RuleSet, bool) {
	best := -1
	for i, e := range d.Peers {
		if e.Prefix.Addr().Is4() == addr.Is4() && e.Prefix.Contains(addr) && (best < 0 || e.Prefix.Bits() > d.Peers[best].Prefix.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return RuleSet{}, false
	}
	return d.Peers[best].Rules, d.Peers[best].AllowCommon
}

func (d *DirectionPolicy) lookupPort(proto uint8, port uint16) RuleSet {
	target := PortPrefix{Proto: proto, Port: port, Bits: 16}
	best := -1
	for i, e := range d.Ports {
		if e.contains(target) && (best < 0 || e.Bits > d.Ports[best].Bits) {
			best = i
		}
	}
	if best < 0 {
		return RuleSet{}
	}
	return d.Ports[best].Rules
}

// EndpointPolicy is the compiled policy of one pod interface.
type EndpointPolicy struct {
	Interface     string
	NetattachName string
	AcceptICMP    bool
	AcceptICMPv6  bool
	Directions    [2]DirectionPolicy
}

// Digest identifies the compiled policy; the datapath skips reloading an
// interface whose digest did not change.
func (e *EndpointPolicy) Digest() string {
	b, err := json.Marshal(e)
	if err != nil {
		// Every field is plain data; Marshal cannot fail.
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Compile turns the policies that select a pod into one EndpointPolicy per
// policed interface of the pod.
//
// The semantics follow the MultiNetworkPolicy (and Kubernetes NetworkPolicy)
// specification:
//   - an interface is isolated for a direction only by policies whose
//     policy-for networks include the interface's network;
//   - rules and policies are additive, an ipBlock.except only removes
//     addresses from its own ipBlock;
//   - a podSelector without namespaceSelector selects pods in the policy's
//     namespace.
func Compile(ctx context.Context, deps controllers.PolicyDeps, cfg controllers.CommonRuleConfig, policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo) ([]EndpointPolicy, error) {
	ingress, egress := controllers.SelectPolicies(policyMap, pod, podInfo)
	resolver := &peerResolver{ctx: ctx, deps: deps, nsLabels: map[string]labels.Set{}, pods: map[types.UID]*controllers.PodInfo{}}

	allowSrc, err := parsePrefixes(cfg.AllowSrcPrefix)
	if err != nil {
		return nil, fmt.Errorf("allow-src-prefix: %w", err)
	}
	allowDst, err := parsePrefixes(cfg.AllowDstPrefix)
	if err != nil {
		return nil, fmt.Errorf("allow-dst-prefix: %w", err)
	}

	endpoints := make([]EndpointPolicy, 0, len(podInfo.Interfaces))
	for _, intf := range podInfo.Interfaces {
		ep := EndpointPolicy{
			Interface:     intf.InterfaceName,
			NetattachName: intf.NetattachName,
			AcceptICMP:    cfg.AcceptICMP,
			AcceptICMPv6:  cfg.AcceptICMPv6,
		}
		if ep.Directions[Ingress], err = compileDirection(Ingress, intf, ingress, allowSrc, resolver); err != nil {
			return nil, fmt.Errorf("interface %s: %w", intf.InterfaceName, err)
		}
		if ep.Directions[Egress], err = compileDirection(Egress, intf, egress, allowDst, resolver); err != nil {
			return nil, fmt.Errorf("interface %s: %w", intf.InterfaceName, err)
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

// Isolation returns, for each policed interface of the pod, a policy that
// accepts no new connection in the directions the pod's policies isolate and
// everything in the others. The reconciler applies it when Compile fails, so
// a policy that cannot be compiled fails closed instead of leaving the pod
// open. Established connections and the common rules (ICMP, allowed
// prefixes) still apply.
func Isolation(cfg controllers.CommonRuleConfig, policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo) []EndpointPolicy {
	ingress, egress := controllers.SelectPolicies(policyMap, pod, podInfo)
	// The prefixes were validated when the flags were parsed.
	allowSrc, _ := parsePrefixes(cfg.AllowSrcPrefix)
	allowDst, _ := parsePrefixes(cfg.AllowDstPrefix)
	isolated := func(intf controllers.InterfaceInfo, policies []controllers.SelectedPolicy, allow []netip.Prefix) DirectionPolicy {
		for _, sp := range policies {
			if intf.CheckPolicyNetwork(sp.Networks) {
				dp := DirectionPolicy{Isolated: true}
				var groups []prefixGroup
				for _, p := range allow {
					groups = append(groups, prefixGroup{cidr: p, bit: commonBit})
				}
				dp.Peers = buildPeerEntries(groups)
				return dp
			}
		}
		return DirectionPolicy{}
	}
	endpoints := make([]EndpointPolicy, 0, len(podInfo.Interfaces))
	for _, intf := range podInfo.Interfaces {
		endpoints = append(endpoints, EndpointPolicy{
			Interface:     intf.InterfaceName,
			NetattachName: intf.NetattachName,
			AcceptICMP:    cfg.AcceptICMP,
			AcceptICMPv6:  cfg.AcceptICMPv6,
			Directions:    [2]DirectionPolicy{isolated(intf, ingress, allowSrc), isolated(intf, egress, allowDst)},
		})
	}
	return endpoints
}

func compileDirection(dir Direction, intf controllers.InterfaceInfo, policies []controllers.SelectedPolicy, allowCommon []netip.Prefix, resolver *peerResolver) (DirectionPolicy, error) {
	var dp DirectionPolicy
	var peerGroups []prefixGroup
	var portGroups []portGroup

	for _, sp := range policies {
		if !intf.CheckPolicyNetwork(sp.Networks) {
			continue
		}
		dp.Isolated = true
		policyName := sp.Policy.Namespace + "/" + sp.Policy.Name

		for i, rule := range policyRules(sp.Policy, dir) {
			bit := len(dp.Rules)
			if bit >= MaxRules {
				return dp, fmt.Errorf("%s: more than %d rules apply to the interface", dir, MaxRules)
			}
			dp.Rules = append(dp.Rules, fmt.Sprintf("%s %s[%d]", policyName, dir, i))

			if len(rule.ports) == 0 {
				dp.WildPort.Set(bit)
			}
			for _, port := range rule.ports {
				prefixes, err := portPrefixes(port)
				if err != nil {
					return dp, fmt.Errorf("policy %s %s[%d]: %w", policyName, dir, i, err)
				}
				for _, p := range prefixes {
					portGroups = append(portGroups, portGroup{prefix: p, bit: bit})
				}
			}

			if len(rule.peers) == 0 {
				dp.WildPeer.Set(bit)
			}
			for j, peer := range rule.peers {
				groups, err := resolver.peerGroups(sp, peer, bit)
				if err != nil {
					return dp, fmt.Errorf("policy %s %s[%d] peer %d: %w", policyName, dir, i, j, err)
				}
				peerGroups = append(peerGroups, groups...)
			}
		}
	}
	if !dp.Isolated {
		return dp, nil
	}
	for _, p := range allowCommon {
		peerGroups = append(peerGroups, prefixGroup{cidr: p, bit: commonBit})
	}
	dp.Peers = buildPeerEntries(peerGroups)
	dp.Ports = buildPortEntries(portGroups)
	return dp, nil
}

type genericRule struct {
	peers []multiv1beta1.MultiNetworkPolicyPeer
	ports []multiv1beta1.MultiNetworkPolicyPort
}

func policyRules(policy *multiv1beta1.MultiNetworkPolicy, dir Direction) []genericRule {
	var rules []genericRule
	if dir == Ingress {
		for _, r := range policy.Spec.Ingress {
			rules = append(rules, genericRule{peers: r.From, ports: r.Ports})
		}
		return rules
	}
	for _, r := range policy.Spec.Egress {
		rules = append(rules, genericRule{peers: r.To, ports: r.Ports})
	}
	return rules
}

// commonBit marks a prefix group that sets AllowCommon instead of a rule bit.
const commonBit = -1

// prefixGroup is the address set of one peer: cidr minus excepts.
type prefixGroup struct {
	cidr    netip.Prefix
	excepts []netip.Prefix
	bit     int
}

func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Addr().Is4() == inner.Addr().Is4() && outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// buildPeerEntries computes the LPM trie contents for a set of peers.
//
// Every cidr and every except becomes an entry. For an address, the longest
// matching entry P is nested inside every inserted prefix that contains the
// address, so the address is in a peer's cidr (or except) exactly when P is.
// P's rule set is therefore the union of the peers with P inside their cidr
// and outside all of their excepts, which is the address's rule set.
func buildPeerEntries(groups []prefixGroup) []PeerEntry {
	candidates := map[netip.Prefix]struct{}{}
	// Single-address peers (the pods a selector resolves to) can only
	// contain the entry for that very address, so they are looked up by
	// key instead of being compared against every entry.
	exact := map[netip.Prefix][]int{}
	var blocks []int
	for i, g := range groups {
		candidates[g.cidr] = struct{}{}
		for _, e := range g.excepts {
			candidates[e] = struct{}{}
		}
		if g.cidr.IsSingleIP() && len(g.excepts) == 0 {
			exact[g.cidr] = append(exact[g.cidr], i)
		} else {
			blocks = append(blocks, i)
		}
	}

	entries := make([]PeerEntry, 0, len(candidates))
	for p := range candidates {
		entry := PeerEntry{Prefix: p}
		apply := func(g prefixGroup) {
			if g.bit == commonBit {
				entry.AllowCommon = true
			} else {
				entry.Rules.Set(g.bit)
			}
		}
		for _, i := range exact[p] {
			apply(groups[i])
		}
		for _, i := range blocks {
			g := groups[i]
			if !prefixContains(g.cidr, p) {
				continue
			}
			excluded := false
			for _, e := range g.excepts {
				if prefixContains(e, p) {
					excluded = true
					break
				}
			}
			if !excluded {
				apply(g)
			}
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b PeerEntry) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		return a.Prefix.Bits() - b.Prefix.Bits()
	})
	return entries
}

type portGroup struct {
	prefix PortPrefix
	bit    int
}

// buildPortEntries computes the port LPM trie contents; the argument is the
// same as for buildPeerEntries, without excepts.
func buildPortEntries(groups []portGroup) []PortEntry {
	candidates := map[PortPrefix]struct{}{}
	for _, g := range groups {
		candidates[g.prefix] = struct{}{}
	}
	entries := make([]PortEntry, 0, len(candidates))
	for p := range candidates {
		entry := PortEntry{PortPrefix: p}
		for _, g := range groups {
			if g.prefix.contains(p) {
				entry.Rules.Set(g.bit)
			}
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b PortEntry) int {
		if a.Proto != b.Proto {
			return int(a.Proto) - int(b.Proto)
		}
		if a.Port != b.Port {
			return int(a.Port) - int(b.Port)
		}
		return int(a.Bits) - int(b.Bits)
	})
	return entries
}

// IP protocol numbers of the protocols a policy port can name.
const (
	protoTCP  = 6
	protoUDP  = 17
	protoSCTP = 132
)

func portPrefixes(port multiv1beta1.MultiNetworkPolicyPort) ([]PortPrefix, error) {
	proto := uint8(protoTCP)
	if port.Protocol != nil {
		switch *port.Protocol {
		case corev1.ProtocolTCP:
		case corev1.ProtocolUDP:
			proto = protoUDP
		case corev1.ProtocolSCTP:
			proto = protoSCTP
		default:
			return nil, fmt.Errorf("unsupported protocol %q", *port.Protocol)
		}
	}
	if port.Port == nil {
		return []PortPrefix{{Proto: proto}}, nil
	}

	start := port.Port.IntValue()
	if port.Port.Type == intstr.String {
		n, err := strconv.Atoi(port.Port.StrVal)
		if err != nil {
			return nil, fmt.Errorf("named port %q is not supported; numeric ports are required", port.Port.StrVal)
		}
		start = n
	}
	if start < 1 || start > math.MaxUint16 {
		return nil, fmt.Errorf("port %d out of range, must be between 1 and %d", start, math.MaxUint16)
	}
	end := start
	if port.EndPort != nil && int(*port.EndPort) > start {
		end = int(*port.EndPort)
		if end > math.MaxUint16 {
			return nil, fmt.Errorf("endPort %d out of range, must be between 1 and %d", end, math.MaxUint16)
		}
	}

	var prefixes []PortPrefix
	for p := uint32(start); p <= uint32(end); {
		// the largest aligned block starting at p that ends within the range
		size := uint32(1) << 16
		if p != 0 {
			size = uint32(1) << bits.TrailingZeros32(p)
		}
		for p+size-1 > uint32(end) {
			size >>= 1
		}
		prefixes = append(prefixes, PortPrefix{Proto: proto, Port: uint16(p), Bits: uint8(16 - bits.TrailingZeros32(size))}) //nolint:gosec // p <= 65535 and size <= 1<<16
		p += size
	}
	return prefixes, nil
}

func parsePrefixes(texts []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(texts))
	for _, t := range texts {
		p, err := netip.ParsePrefix(strings.TrimSpace(t))
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, canonicalPrefix(p))
	}
	return prefixes, nil
}

func canonicalPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked()
}

// parseAddr accepts the plain addresses of a network-status entry, and
// tolerates the address/prefix form some plugins report.
func parseAddr(s string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Addr().Unmap(), nil
}

type peerResolver struct {
	ctx      context.Context
	deps     controllers.PolicyDeps
	nsLabels map[string]labels.Set
	pods     map[types.UID]*controllers.PodInfo
}

func (r *peerResolver) peerGroups(sp controllers.SelectedPolicy, peer multiv1beta1.MultiNetworkPolicyPeer, bit int) ([]prefixGroup, error) {
	if peer.IPBlock != nil {
		cidr, err := netip.ParsePrefix(peer.IPBlock.CIDR)
		if err != nil {
			return nil, fmt.Errorf("ipBlock cidr: %w", err)
		}
		g := prefixGroup{cidr: canonicalPrefix(cidr), bit: bit}
		for _, e := range peer.IPBlock.Except {
			ep, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("ipBlock except: %w", err)
			}
			g.excepts = append(g.excepts, canonicalPrefix(ep))
		}
		return []prefixGroup{g}, nil
	}
	if peer.PodSelector == nil && peer.NamespaceSelector == nil {
		return nil, fmt.Errorf("peer has neither ipBlock nor selectors")
	}

	addrs, err := r.selectorAddrs(sp, peer)
	if err != nil {
		return nil, err
	}
	groups := make([]prefixGroup, 0, len(addrs))
	for _, a := range addrs {
		groups = append(groups, prefixGroup{cidr: netip.PrefixFrom(a, a.BitLen()), bit: bit})
	}
	return groups, nil
}

// selectorAddrs returns the addresses the selected pods have on the policy's
// networks.
func (r *peerResolver) selectorAddrs(sp controllers.SelectedPolicy, peer multiv1beta1.MultiNetworkPolicyPeer) ([]netip.Addr, error) {
	podSelector := labels.Everything()
	if peer.PodSelector != nil {
		s, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("pod selector: %w", err)
		}
		podSelector = s
	}
	var nsSelector labels.Selector
	if peer.NamespaceSelector != nil {
		s, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			return nil, fmt.Errorf("namespace selector: %w", err)
		}
		nsSelector = s
	}

	pods, err := r.deps.ListPods(r.ctx, podSelector)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var addrs []netip.Addr
	for _, p := range pods {
		if nsSelector == nil {
			if p.Namespace != sp.Policy.Namespace {
				continue
			}
		} else {
			nsLabels, err := r.namespaceLabels(p.Namespace)
			if err != nil {
				klog.Errorf("cannot get namespace %s: %v", p.Namespace, err)
				continue
			}
			if !nsSelector.Matches(nsLabels) {
				continue
			}
		}
		info, err := r.podInfo(p)
		if err != nil {
			klog.Errorf("cannot get %s/%s pod info: %v", p.Namespace, p.Name, err)
			continue
		}
		for _, intf := range info.Interfaces {
			if !intf.CheckPolicyNetwork(sp.Networks) {
				continue
			}
			for _, ip := range intf.IPs {
				a, err := parseAddr(ip)
				if err != nil {
					klog.Errorf("pod %s/%s interface %s: invalid address %q", p.Namespace, p.Name, intf.InterfaceName, ip)
					continue
				}
				addrs = append(addrs, a)
			}
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addrs), nil
}

func (r *peerResolver) namespaceLabels(name string) (labels.Set, error) {
	if l, ok := r.nsLabels[name]; ok {
		return l, nil
	}
	info, err := r.deps.GetNamespaceInfo(r.ctx, name)
	if err != nil {
		return nil, err
	}
	r.nsLabels[name] = labels.Set(info.Labels)
	return r.nsLabels[name], nil
}

func (r *peerResolver) podInfo(p *corev1.Pod) (*controllers.PodInfo, error) {
	if p.UID != "" {
		if info, ok := r.pods[p.UID]; ok {
			return info, nil
		}
	}
	info, err := r.deps.GetPodInfo(r.ctx, p)
	if err != nil {
		return nil, err
	}
	if p.UID != "" {
		r.pods[p.UID] = info
	}
	return info, nil
}
