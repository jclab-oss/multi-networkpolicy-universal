package tcx

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// fakeCluster implements controllers.PolicyDeps over a fixed set of pods.
type fakeCluster struct {
	pods       []*corev1.Pod
	namespaces map[string]map[string]string
	infos      map[types.UID]*controllers.PodInfo
}

func (f *fakeCluster) ListPods(_ context.Context, selector labels.Selector) ([]*corev1.Pod, error) {
	var out []*corev1.Pod
	for _, p := range f.pods {
		if selector.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeCluster) GetNamespaceInfo(_ context.Context, namespace string) (*controllers.NamespaceInfo, error) {
	return &controllers.NamespaceInfo{Name: namespace, Labels: f.namespaces[namespace]}, nil
}

func (f *fakeCluster) GetPodInfo(_ context.Context, pod *corev1.Pod) (*controllers.PodInfo, error) {
	if info, ok := f.infos[pod.UID]; ok {
		return info, nil
	}
	return &controllers.PodInfo{Name: pod.Name, Namespace: pod.Namespace}, nil
}

// addPod registers a pod with one interface per "network=ip" pair.
func (f *fakeCluster) addPod(namespace, name string, podLabels map[string]string, ifaces ...string) (*corev1.Pod, *controllers.PodInfo) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace, Name: name, UID: types.UID(namespace + "-" + name), Labels: podLabels,
	}}
	info := &controllers.PodInfo{Name: name, Namespace: namespace}
	for i, spec := range ifaces {
		network, ip, _ := strings.Cut(spec, "=")
		info.Interfaces = append(info.Interfaces, controllers.InterfaceInfo{
			NetattachName: network,
			InterfaceName: fmt.Sprintf("net%d", i+1),
			InterfaceType: "macvlan",
			IPs:           []string{ip},
		})
	}
	f.pods = append(f.pods, pod)
	if f.infos == nil {
		f.infos = map[types.UID]*controllers.PodInfo{}
	}
	f.infos[pod.UID] = info
	return pod, info
}

// policy returns a policy in namespace ns1, where the test pods live.
func policy(name, networks string, spec multiv1beta1.MultiNetworkPolicySpec) *multiv1beta1.MultiNetworkPolicy {
	return &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "ns1",
			Name:        name,
			Annotations: map[string]string{controllers.PolicyNetworkAnnotation: networks},
		},
		Spec: spec,
	}
}

func policyMap(policies ...*multiv1beta1.MultiNetworkPolicy) controllers.PolicyMap {
	m := controllers.PolicyMap{}
	for _, p := range policies {
		m[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] = p
	}
	return m
}

func tcpPort(p int) multiv1beta1.MultiNetworkPolicyPort {
	proto := corev1.ProtocolTCP
	port := intstr.FromInt(p)
	return multiv1beta1.MultiNetworkPolicyPort{Protocol: &proto, Port: &port}
}

func selectPods(l map[string]string) multiv1beta1.MultiNetworkPolicyPeer {
	return multiv1beta1.MultiNetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: l}}
}

func mustCompile(t *testing.T, f *fakeCluster, cfg controllers.CommonRuleConfig, pm controllers.PolicyMap, pod *corev1.Pod, info *controllers.PodInfo) []EndpointPolicy {
	t.Helper()
	eps, err := Compile(context.Background(), f, cfg, pm, pod, info)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return eps
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestCompileSimpleIngress(t *testing.T) {
	f := &fakeCluster{}
	server, serverInfo := f.addPod("ns1", "server", map[string]string{"name": "server"}, "default/net-a=10.0.0.1")
	f.addPod("ns1", "client-a", map[string]string{"name": "client-a"}, "default/net-a=10.0.0.2")
	f.addPod("ns1", "client-b", map[string]string{"name": "client-b"}, "default/net-a=10.0.0.3")
	// Same labels in another namespace: a podSelector without namespaceSelector must not select it.
	f.addPod("ns2", "client-a", map[string]string{"name": "client-a"}, "default/net-a=10.0.0.4")

	pm := policyMap(policy("allow-a", "default/net-a", multiv1beta1.MultiNetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"name": "server"}},
		Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
			From: []multiv1beta1.MultiNetworkPolicyPeer{selectPods(map[string]string{"name": "client-a"})},
		}},
	}))
	eps := mustCompile(t, f, controllers.CommonRuleConfig{}, pm, server, serverInfo)
	if len(eps) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(eps))
	}
	in, eg := &eps[0].Directions[Ingress], &eps[0].Directions[Egress]
	if !in.Isolated || eg.Isolated {
		t.Fatalf("isolation ingress=%v egress=%v, want true/false", in.Isolated, eg.Isolated)
	}
	for _, tc := range []struct {
		peer string
		want bool
	}{
		{"10.0.0.2", true},
		{"10.0.0.3", false},
		{"10.0.0.4", false},
		{"192.0.2.1", false},
	} {
		if got := in.Allows(addr(tc.peer), protoTCP, 5555, true); got != tc.want {
			t.Errorf("ingress from %s = %v, want %v", tc.peer, got, tc.want)
		}
	}
	if !eg.Allows(addr("192.0.2.1"), protoUDP, 53, true) {
		t.Errorf("egress must not be isolated")
	}
}

func TestCompileNamespaceSelector(t *testing.T) {
	f := &fakeCluster{namespaces: map[string]map[string]string{"ns2": {"team": "blue"}, "ns3": {"team": "red"}}}
	server, serverInfo := f.addPod("ns1", "server", nil, "default/net-a=10.0.0.1")
	f.addPod("ns2", "blue", map[string]string{"role": "client"}, "default/net-a=10.0.0.2")
	f.addPod("ns3", "red", map[string]string{"role": "client"}, "default/net-a=10.0.0.3")
	f.addPod("ns2", "blue-other", map[string]string{"role": "db"}, "default/net-a=10.0.0.5")

	pm := policyMap(policy("p", "default/net-a", multiv1beta1.MultiNetworkPolicySpec{
		Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "blue"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"role": "client"}},
			}}},
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "red"}},
			}}},
		},
	}))
	in := mustCompile(t, f, controllers.CommonRuleConfig{}, pm, server, serverInfo)[0].Directions[Ingress]
	for peer, want := range map[string]bool{"10.0.0.2": true, "10.0.0.3": true, "10.0.0.5": false} {
		if got := in.Allows(addr(peer), protoTCP, 80, true); got != want {
			t.Errorf("ingress from %s = %v, want %v", peer, got, want)
		}
	}
}

func TestCompileIsolatesOnlyPolicyNetworks(t *testing.T) {
	f := &fakeCluster{}
	pod, info := f.addPod("ns1", "pod", nil, "ns1/net-a=10.0.0.1", "ns1/net-b=10.1.0.1")
	// "net-a" without a namespace names the policy's namespace.
	pm := policyMap(policy("deny-a", "net-a", multiv1beta1.MultiNetworkPolicySpec{
		PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
	}))

	eps := mustCompile(t, f, controllers.CommonRuleConfig{}, pm, pod, info)
	byName := map[string]EndpointPolicy{}
	for _, ep := range eps {
		byName[ep.Interface] = ep
	}
	a, b := byName["net1"], byName["net2"]
	if !a.Directions[Ingress].Isolated || !a.Directions[Egress].Isolated {
		t.Errorf("net1 must be isolated in both directions")
	}
	if a.Directions[Ingress].Allows(addr("10.0.0.2"), protoTCP, 80, true) || a.Directions[Egress].Allows(addr("10.0.0.2"), protoTCP, 80, true) {
		t.Errorf("deny-all policy must deny")
	}
	if b.Directions[Ingress].Isolated || b.Directions[Egress].Isolated {
		t.Errorf("net2 is not on the policy's network and must not be isolated")
	}
}

func TestCompileIPBlockExceptIsAdditive(t *testing.T) {
	f := &fakeCluster{}
	pod, info := f.addPod("ns1", "pod", nil, "default/net=10.0.0.1")
	pm := policyMap(
		policy("a", "default/net", multiv1beta1.MultiNetworkPolicySpec{
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
				From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}}}},
			}},
		}),
		// A second policy allows part of what the first one excepts.
		policy("b", "default/net", multiv1beta1.MultiNetworkPolicySpec{
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
				From:  []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.1.2.0/24"}}},
				Ports: []multiv1beta1.MultiNetworkPolicyPort{tcpPort(443)},
			}},
		}),
	)
	in := mustCompile(t, f, controllers.CommonRuleConfig{}, pm, pod, info)[0].Directions[Ingress]
	for _, tc := range []struct {
		peer string
		port uint16
		want bool
	}{
		{"10.2.3.4", 80, true},
		{"10.1.3.4", 80, false},
		{"10.1.2.3", 80, false},
		{"10.1.2.3", 443, true},
		{"11.0.0.1", 443, false},
	} {
		if got := in.Allows(addr(tc.peer), protoTCP, tc.port, true); got != tc.want {
			t.Errorf("ingress from %s:%d = %v, want %v", tc.peer, tc.port, got, tc.want)
		}
	}
}

func TestCompilePorts(t *testing.T) {
	udp, sctp := corev1.ProtocolUDP, corev1.ProtocolSCTP
	end := int32(2000)
	p1000 := intstr.FromInt(1000)
	f := &fakeCluster{}
	pod, info := f.addPod("ns1", "pod", nil, "default/net=10.0.0.1")
	pm := policyMap(policy("p", "default/net", multiv1beta1.MultiNetworkPolicySpec{
		Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
			{Ports: []multiv1beta1.MultiNetworkPolicyPort{tcpPort(5555), {Protocol: &udp, Port: &p1000, EndPort: &end}}},
			{Ports: []multiv1beta1.MultiNetworkPolicyPort{{Protocol: &sctp}}},
		},
	}))
	eg := mustCompile(t, f, controllers.CommonRuleConfig{}, pm, pod, info)[0].Directions[Egress]
	peer := addr("198.51.100.7")
	for _, tc := range []struct {
		proto uint8
		port  uint16
		want  bool
	}{
		{protoTCP, 5555, true},
		{protoTCP, 5556, false},
		{protoUDP, 999, false},
		{protoUDP, 1000, true},
		{protoUDP, 1500, true},
		{protoUDP, 2000, true},
		{protoUDP, 2001, false},
		{protoTCP, 1500, false},
		{protoSCTP, 1, true},
		{protoSCTP, 65535, true},
	} {
		if got := eg.Allows(peer, tc.proto, tc.port, true); got != tc.want {
			t.Errorf("egress proto %d port %d = %v, want %v", tc.proto, tc.port, got, tc.want)
		}
	}
	// ICMP has no ports: a rule that lists ports cannot match it.
	if eg.Allows(peer, 1, 0, false) {
		t.Errorf("ICMP must not match port rules")
	}
}

func TestCompileNamedPortFails(t *testing.T) {
	named := intstr.FromString("http")
	f := &fakeCluster{}
	pod, info := f.addPod("ns1", "pod", nil, "default/net=10.0.0.1")
	pm := policyMap(policy("p", "default/net", multiv1beta1.MultiNetworkPolicySpec{
		Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &named}}}},
	}))
	if _, err := Compile(context.Background(), f, controllers.CommonRuleConfig{}, pm, pod, info); err == nil || !strings.Contains(err.Error(), "named port") {
		t.Fatalf("Compile error = %v, want named port error", err)
	}
}

func TestCompileCommonConfig(t *testing.T) {
	f := &fakeCluster{}
	pod, info := f.addPod("ns1", "pod", nil, "default/net=10.0.0.1")
	pm := policyMap(policy("deny", "default/net", multiv1beta1.MultiNetworkPolicySpec{
		PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
	}))
	cfg := controllers.CommonRuleConfig{AcceptICMP: true, AllowSrcPrefix: []string{"fe80::/10"}, AllowDstPrefix: []string{"192.0.2.0/24"}}
	ep := mustCompile(t, f, cfg, pm, pod, info)[0]
	if !ep.AcceptICMP || ep.AcceptICMPv6 {
		t.Errorf("ICMP flags = %v/%v", ep.AcceptICMP, ep.AcceptICMPv6)
	}
	in, eg := ep.Directions[Ingress], ep.Directions[Egress]
	if !in.Allows(addr("fe80::1"), protoTCP, 1, true) || in.Allows(addr("192.0.2.1"), protoTCP, 1, true) {
		t.Errorf("allow-src-prefix applies to ingress only")
	}
	if !eg.Allows(addr("192.0.2.1"), protoTCP, 1, true) || eg.Allows(addr("fe80::1"), protoTCP, 1, true) {
		t.Errorf("allow-dst-prefix applies to egress only")
	}
}

func TestCompileRuleLimit(t *testing.T) {
	f := &fakeCluster{}
	pod, info := f.addPod("ns1", "pod", nil, "default/net=10.0.0.1")
	rules := make([]multiv1beta1.MultiNetworkPolicyIngressRule, MaxRules+1)
	pm := policyMap(policy("p", "default/net", multiv1beta1.MultiNetworkPolicySpec{Ingress: rules}))
	if _, err := Compile(context.Background(), f, controllers.CommonRuleConfig{}, pm, pod, info); err == nil {
		t.Fatalf("Compile must reject more than %d rules", MaxRules)
	}
	pm = policyMap(policy("p", "default/net", multiv1beta1.MultiNetworkPolicySpec{Ingress: rules[:MaxRules]}))
	in := mustCompile(t, f, controllers.CommonRuleConfig{}, pm, pod, info)[0].Directions[Ingress]
	if !in.WildPeer.Has(MaxRules-1) || !in.WildPort.Has(MaxRules-1) {
		t.Errorf("last rule bit not set")
	}
}

func TestDigestChangesWithPolicy(t *testing.T) {
	f := &fakeCluster{}
	pod, info := f.addPod("ns1", "pod", nil, "default/net=10.0.0.1")
	mk := func(port int) string {
		pm := policyMap(policy("p", "default/net", multiv1beta1.MultiNetworkPolicySpec{
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{Ports: []multiv1beta1.MultiNetworkPolicyPort{tcpPort(port)}}},
		}))
		eps := mustCompile(t, f, controllers.CommonRuleConfig{}, pm, pod, info)
		return eps[0].Digest()
	}
	if a, b := mk(80), mk(80); a != b {
		t.Errorf("digest is not deterministic")
	}
	if mk(80) == mk(81) {
		t.Errorf("digest must change with the policy")
	}
}

// naivePeer evaluates prefix groups directly: the reference for buildPeerEntries.
func naivePeer(groups []prefixGroup, a netip.Addr) (RuleSet, bool) {
	var rs RuleSet
	common := false
	for _, g := range groups {
		if g.cidr.Addr().Is4() != a.Is4() || !g.cidr.Contains(a) {
			continue
		}
		excluded := false
		for _, e := range g.excepts {
			if e.Addr().Is4() == a.Is4() && e.Contains(a) {
				excluded = true
			}
		}
		if excluded {
			continue
		}
		if g.bit == commonBit {
			common = true
		} else {
			rs.Set(g.bit)
		}
	}
	return rs, common
}

func randomPrefix(r *rand.Rand, v6 bool) netip.Prefix {
	// A small address space makes nesting and overlaps likely.
	if v6 {
		b := [16]byte{0x20, 0x01, 0x0d, 0xb8}
		b[14], b[15] = byte(r.Intn(4)), byte(r.Intn(256))
		return netip.PrefixFrom(netip.AddrFrom16(b), 112+r.Intn(17)).Masked()
	}
	b := [4]byte{10, 0, byte(r.Intn(4)), byte(r.Intn(256))}
	return netip.PrefixFrom(netip.AddrFrom4(b), 16+r.Intn(17)).Masked()
}

func TestBuildPeerEntriesMatchesNaive(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for iter := 0; iter < 300; iter++ {
		v6 := iter%2 == 1
		var groups []prefixGroup
		for i := 0; i < 1+r.Intn(8); i++ {
			g := prefixGroup{cidr: randomPrefix(r, v6), bit: r.Intn(6) - 1}
			for j := 0; j < r.Intn(3); j++ {
				e := randomPrefix(r, v6)
				if g.cidr.Bits() <= e.Bits() && g.cidr.Contains(e.Addr()) {
					g.excepts = append(g.excepts, e)
				}
			}
			groups = append(groups, g)
		}
		dp := DirectionPolicy{Isolated: true, Peers: buildPeerEntries(groups)}
		for probe := 0; probe < 400; probe++ {
			a := randomPrefix(r, v6).Addr()
			if probe%2 == 0 {
				// the last address of a prefix sits on a boundary
				p := randomPrefix(r, v6)
				a = p.Addr()
				for i := 0; i < r.Intn(3); i++ {
					a = a.Next()
				}
			}
			wantRules, wantCommon := naivePeer(groups, a)
			gotRules, gotCommon := dp.lookupPeer(a)
			if gotRules != wantRules || gotCommon != wantCommon {
				t.Fatalf("iter %d addr %s: got %v/%v want %v/%v (groups %+v)", iter, a, gotRules, gotCommon, wantRules, wantCommon, groups)
			}
		}
	}
}

func TestPortPrefixesCoverRangeExactly(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	ranges := [][2]int{{1, 65535}, {1, 1}, {65535, 65535}, {1000, 2000}, {1024, 2047}, {80, 80}}
	for i := 0; i < 40; i++ {
		s := 1 + r.Intn(65535)
		e := s + r.Intn(65536-s)
		ranges = append(ranges, [2]int{s, e})
	}
	for _, rg := range ranges {
		port := intstr.FromInt(rg[0])
		end := int32(rg[1]) //nolint:gosec // test data within port range
		prefixes, err := portPrefixes(multiv1beta1.MultiNetworkPolicyPort{Port: &port, EndPort: &end})
		if err != nil {
			t.Fatal(err)
		}
		for p := 0; p <= 65535; p++ {
			covered := 0
			for _, pp := range prefixes {
				if pp.contains(PortPrefix{Proto: protoTCP, Port: uint16(p), Bits: 16}) { //nolint:gosec // p <= 65535
					covered++
				}
			}
			want := 0
			if p >= rg[0] && p <= rg[1] {
				want = 1
			}
			if covered != want {
				t.Fatalf("range %v port %d covered %d times, want %d", rg, p, covered, want)
			}
		}
	}
}

func TestBuildPortEntriesMatchesNaive(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for iter := 0; iter < 50; iter++ {
		type rng struct {
			proto      uint8
			start, end int
			bit        int
		}
		var rngs []rng
		var groups []portGroup
		for i := 0; i < 1+r.Intn(6); i++ {
			s := 1 + r.Intn(3000)
			rg := rng{proto: []uint8{protoTCP, protoUDP}[r.Intn(2)], start: s, end: s + r.Intn(500), bit: r.Intn(5)}
			rngs = append(rngs, rg)
			port := intstr.FromInt(rg.start)
			end := int32(rg.end) //nolint:gosec // test data within port range
			proto := corev1.ProtocolTCP
			if rg.proto == protoUDP {
				proto = corev1.ProtocolUDP
			}
			prefixes, err := portPrefixes(multiv1beta1.MultiNetworkPolicyPort{Protocol: &proto, Port: &port, EndPort: &end})
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range prefixes {
				groups = append(groups, portGroup{prefix: p, bit: rg.bit})
			}
		}
		dp := DirectionPolicy{Ports: buildPortEntries(groups)}
		for p := 0; p <= 4000; p++ {
			for _, proto := range []uint8{protoTCP, protoUDP} {
				var want RuleSet
				for _, rg := range rngs {
					if rg.proto == proto && p >= rg.start && p <= rg.end {
						want.Set(rg.bit)
					}
				}
				if got := dp.lookupPort(proto, uint16(p)); got != want { //nolint:gosec // p <= 4000
					t.Fatalf("iter %d proto %d port %d: got %v want %v", iter, proto, p, got, want)
				}
			}
		}
	}
}

func TestIsolationDeniesIsolatedDirections(t *testing.T) {
	named := intstr.FromString("http")
	f := &fakeCluster{}
	pod, info := f.addPod("ns1", "pod", nil, "default/net-a=10.0.0.1", "default/net-b=10.1.0.1")
	pm := policyMap(policy("p", "default/net-a", multiv1beta1.MultiNetworkPolicySpec{
		Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &named}}}},
	}))
	if _, err := Compile(context.Background(), f, controllers.CommonRuleConfig{}, pm, pod, info); err == nil {
		t.Fatalf("Compile must fail on the named port")
	}
	eps := Isolation(controllers.CommonRuleConfig{AllowSrcPrefix: []string{"192.0.2.0/24"}}, pm, pod, info)
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(eps))
	}
	a, b := eps[0], eps[1]
	if a.Interface != "net1" || !a.Directions[Ingress].Isolated || a.Directions[Egress].Isolated {
		t.Errorf("net1 = %+v, want ingress isolated only", a.Directions)
	}
	if a.Directions[Ingress].Allows(addr("10.0.0.2"), protoTCP, 80, true) {
		t.Errorf("isolated direction must deny new connections")
	}
	if !a.Directions[Ingress].Allows(addr("192.0.2.1"), protoTCP, 80, true) {
		t.Errorf("allow-src-prefix still applies")
	}
	if b.Directions[Ingress].Isolated || b.Directions[Egress].Isolated {
		t.Errorf("net2 is not on the policy's network")
	}
}
