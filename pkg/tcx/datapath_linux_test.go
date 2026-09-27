//go:build linux

package tcx

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// kataTopology reproduces the network of a Kata Containers pod with
// internetworking_model = "tcfilter":
//
//	client netns          pod netns                                  guest netns ("VM")
//	c0 10.9.0.1 <-veth-> eth0 ==tc mirred== tap0_kata <-veth-> g0 10.9.0.2 (MAC of eth0)
//
// The two ingress qdiscs and u32 redirect filters are exactly what Kata's
// addQdiscIngress/addRedirectTCFilter install, so traffic between the client
// and the guest never reaches the pod namespace's IP stack or netfilter.
type kataTopology struct {
	t                  *testing.T
	client, pod, guest string // netns names below /run/netns
}

func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("requires %s", tool)
		}
	}
}

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func newKataTopology(t *testing.T, suffix string) *kataTopology {
	t.Helper()
	requireTools(t, "ip", "tc")
	id := fmt.Sprintf("%d%s", os.Getpid()%100000, suffix)
	k := &kataTopology{t: t, client: "mnpc" + id, pod: "mnpp" + id, guest: "mnpg" + id}
	for _, n := range []string{k.client, k.pod, k.guest} {
		sh(t, "ip", "netns", "add", n)
	}
	t.Cleanup(k.destroy)

	sh(t, "ip", "link", "add", "c0", "netns", k.client, "type", "veth", "peer", "name", "eth0", "netns", k.pod)
	sh(t, "ip", "link", "add", "tap0_kata", "netns", k.pod, "type", "veth", "peer", "name", "g0", "netns", k.guest)
	mac := sh(t, "ip", "netns", "exec", k.pod, "cat", "/sys/class/net/eth0/address")
	sh(t, "ip", "-n", k.guest, "link", "set", "g0", "address", mac)
	sh(t, "ip", "-n", k.client, "addr", "add", "10.9.0.1/24", "dev", "c0")
	sh(t, "ip", "-n", k.guest, "addr", "add", "10.9.0.2/24", "dev", "g0")
	for _, l := range [][2]string{{k.client, "c0"}, {k.client, "lo"}, {k.pod, "eth0"}, {k.pod, "tap0_kata"}, {k.guest, "g0"}, {k.guest, "lo"}} {
		sh(t, "ip", "-n", l[0], "link", "set", l[1], "up")
	}
	for _, pair := range [][2]string{{"eth0", "tap0_kata"}, {"tap0_kata", "eth0"}} {
		sh(t, "ip", "netns", "exec", k.pod, "tc", "qdisc", "add", "dev", pair[0], "ingress")
		sh(t, "ip", "netns", "exec", k.pod, "tc", "filter", "add", "dev", pair[0], "parent", "ffff:", "protocol", "all",
			"u32", "match", "u8", "0", "0", "action", "mirred", "egress", "redirect", "dev", pair[1])
	}
	return k
}

func (k *kataTopology) destroy() {
	for _, n := range []string{k.client, k.pod, k.guest} {
		_ = exec.Command("ip", "netns", "del", n).Run()
	}
}

func (k *kataTopology) podNetns() string { return "/run/netns/" + k.pod }

func inNetns(t *testing.T, name string, fn func() error) error {
	t.Helper()
	netns, err := ns.GetNS("/run/netns/" + name)
	if err != nil {
		t.Fatalf("open netns %s: %v", name, err)
	}
	defer netns.Close()
	return netns.Do(func(ns.NetNS) error { return fn() })
}

// serve starts an echo server in the netns. The listening socket stays in the
// namespace it was created in.
func serve(t *testing.T, netnsName, addr string) {
	t.Helper()
	var l net.Listener
	if err := inNetns(t, netnsName, func() (err error) {
		l, err = net.Listen("tcp", addr)
		return err
	}); err != nil {
		t.Fatalf("listen %s in %s: %v", addr, netnsName, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}

func dial(t *testing.T, netnsName, addr string) (net.Conn, error) {
	t.Helper()
	var c net.Conn
	err := inNetns(t, netnsName, func() (err error) {
		c, err = net.DialTimeout("tcp", addr, 1500*time.Millisecond)
		return err
	})
	return c, err
}

// echo sends a line over the connection and waits for it to come back.
func echo(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintln(c, msg); err != nil {
		return err
	}
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(got) != msg {
		return fmt.Errorf("echo %q, got %q", msg, got)
	}
	return nil
}

func expectConnect(t *testing.T, from, addr, what string) {
	t.Helper()
	c, err := dial(t, from, addr)
	if err != nil {
		t.Errorf("%s: connect %s: %v", what, addr, err)
		return
	}
	defer c.Close()
	if err := echo(c, "ping"); err != nil {
		t.Errorf("%s: %v", what, err)
	}
}

func expectBlocked(t *testing.T, from, addr, what string) {
	t.Helper()
	c, err := dial(t, from, addr)
	if err == nil {
		c.Close()
		t.Errorf("%s: connect %s succeeded, want blocked", what, addr)
	}
}

// kataPolicies compiles the policy of the pod running in the guest:
// ingress only from the client on TCP 5555, egress denied.
func kataPolicies(t *testing.T, allowIngress bool) []EndpointPolicy {
	t.Helper()
	f := &fakeCluster{}
	server, info := f.addPod("ns1", "server", map[string]string{"name": "server"}, "default/net=10.9.0.2")
	info.Interfaces[0].InterfaceName = "eth0"
	f.addPod("ns1", "client", map[string]string{"name": "client"}, "default/net=10.9.0.1")

	spec := multiv1beta1.MultiNetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"name": "server"}},
		PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
	}
	if allowIngress {
		tcp := corev1.ProtocolTCP
		spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{{
			From:  []multiv1beta1.MultiNetworkPolicyPeer{selectPods(map[string]string{"name": "client"})},
			Ports: []multiv1beta1.MultiNetworkPolicyPort{{Protocol: &tcp, Port: ptrIntOrString(5555)}},
		}}
	}
	eps, err := Compile(context.Background(), f, controllers.CommonRuleConfig{}, policyMap(policy("p", "default/net", spec)), server, info)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return eps
}

func TestDatapathKataTCFilter(t *testing.T) {
	d := newTestDatapath(t)
	k := newKataTopology(t, "a")
	const podUID = "kata-pod-uid"

	serve(t, k.guest, "10.9.0.2:5555")
	serve(t, k.guest, "10.9.0.2:5556")
	serve(t, k.client, "10.9.0.1:7777")

	expectConnect(t, k.client, "10.9.0.2:5555", "baseline ingress")
	expectConnect(t, k.guest, "10.9.0.1:7777", "baseline egress")

	if err := d.Apply(k.podNetns(), podUID, kataPolicies(t, true)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	expectConnect(t, k.client, "10.9.0.2:5555", "allowed port")
	expectBlocked(t, k.client, "10.9.0.2:5556", "port not in policy")
	expectBlocked(t, k.guest, "10.9.0.1:7777", "egress denied")
	if out := sh(t, "ip", "netns", "exec", k.pod, "tc", "filter", "show", "dev", "eth0", "ingress"); !strings.Contains(out, "mirred") {
		t.Errorf("Kata's redirect filter must be left in place, got:\n%s", out)
	}

	// An established connection survives a policy change, like conntrack.
	established, err := dial(t, k.client, "10.9.0.2:5555")
	if err != nil {
		t.Fatalf("connect before the policy change: %v", err)
	}
	defer established.Close()
	if err := d.Apply(k.podNetns(), podUID, kataPolicies(t, false)); err != nil {
		t.Fatalf("Apply deny-all: %v", err)
	}
	if err := echo(established, "still-there"); err != nil {
		t.Errorf("established connection after the policy change: %v", err)
	}
	expectBlocked(t, k.client, "10.9.0.2:5555", "new connection after deny-all")

	// The daemon goes away without cleaning up: the pinned links keep
	// enforcing, and a new daemon updates them in place.
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	expectBlocked(t, k.client, "10.9.0.2:5555", "after the daemon stopped")
	d2, err := NewDatapath(d.cfg)
	if err != nil {
		t.Fatalf("NewDatapath after restart: %v", err)
	}
	d = d2
	t.Cleanup(func() { _ = d2.RemoveAll(); _ = d2.Close() })
	if err := d.Apply(k.podNetns(), podUID, kataPolicies(t, true)); err != nil {
		t.Fatalf("Apply after restart: %v", err)
	}
	expectConnect(t, k.client, "10.9.0.2:5555", "allowed port after restart")
	expectBlocked(t, k.client, "10.9.0.2:5556", "port not in policy after restart")
	if n := countTCX(t, k.pod, "eth0"); n != 2 {
		t.Errorf("TCX programs on eth0 = %d, want 2 (updated in place, not stacked)", n)
	}

	// Pruning the pod detaches the programs.
	if err := d.Prune(func(Endpoint) bool { return false }); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	expectConnect(t, k.client, "10.9.0.2:5556", "after prune")
	expectConnect(t, k.guest, "10.9.0.1:7777", "egress after prune")
	if n := countTCX(t, k.pod, "eth0"); n != 0 {
		t.Errorf("TCX programs on eth0 after prune = %d, want 0", n)
	}
}

func TestDatapathSandboxRecreated(t *testing.T) {
	d := newTestDatapath(t)
	const podUID = "kata-pod-recreated"

	k := newKataTopology(t, "b")
	if err := d.Apply(k.podNetns(), podUID, kataPolicies(t, true)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The sandbox is recreated with a new network namespace; the pins of
	// the old one point at links that are no longer attached anywhere.
	k.destroy()
	k = newKataTopology(t, "c")
	serve(t, k.guest, "10.9.0.2:5555")
	serve(t, k.guest, "10.9.0.2:5556")
	if err := d.Apply(k.podNetns(), podUID, kataPolicies(t, true)); err != nil {
		t.Fatalf("Apply to the new sandbox: %v", err)
	}
	expectConnect(t, k.client, "10.9.0.2:5555", "allowed port in the new sandbox")
	expectBlocked(t, k.client, "10.9.0.2:5556", "port not in policy in the new sandbox")

	// A daemon started with the datapath disabled removes what an earlier
	// run pinned.
	if err := RemovePinned(d.cfg.PinPath); err != nil {
		t.Fatalf("RemovePinned: %v", err)
	}
	expectConnect(t, k.client, "10.9.0.2:5556", "after RemovePinned")
	if n := countTCX(t, k.pod, "eth0"); n != 0 {
		t.Errorf("TCX programs on eth0 after RemovePinned = %d, want 0", n)
	}
}

// countTCX counts the TCX programs attached to the interface in both directions.
func countTCX(t *testing.T, netnsName, ifname string) int {
	t.Helper()
	n := 0
	if err := inNetns(t, netnsName, func() error {
		ifc, err := net.InterfaceByName(ifname)
		if err != nil {
			return err
		}
		for _, at := range attachTypes {
			res, err := queryTCX(ifc.Index, at)
			if err != nil {
				return err
			}
			n += res
		}
		return nil
	}); err != nil {
		t.Fatalf("query TCX programs: %v", err)
	}
	return n
}

func queryTCX(ifindex int, at ebpf.AttachType) (int, error) {
	res, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: at})
	if err != nil {
		return 0, err
	}
	return len(res.Programs), nil
}

func ptrIntOrString(p int) *intstr.IntOrString {
	v := intstr.FromInt(p)
	return &v
}

// TestDatapathPlainPod polices a pod whose traffic terminates in its own
// network namespace, like a runc pod whose backend annotation selects TCX:
//
//	client netns c0 10.9.0.1 <-veth-> pod netns eth0 10.9.0.2
func TestDatapathPlainPod(t *testing.T) {
	d := newTestDatapath(t)
	requireTools(t, "ip")
	id := fmt.Sprintf("%d", os.Getpid()%100000)
	client, pod := "mnpc"+id+"r", "mnpp"+id+"r"
	for _, n := range []string{client, pod} {
		sh(t, "ip", "netns", "add", n)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", n).Run() })
	}
	sh(t, "ip", "link", "add", "c0", "netns", client, "type", "veth", "peer", "name", "eth0", "netns", pod)
	sh(t, "ip", "-n", client, "addr", "add", "10.9.0.1/24", "dev", "c0")
	sh(t, "ip", "-n", pod, "addr", "add", "10.9.0.2/24", "dev", "eth0")
	for _, l := range [][2]string{{client, "c0"}, {client, "lo"}, {pod, "eth0"}, {pod, "lo"}} {
		sh(t, "ip", "-n", l[0], "link", "set", l[1], "up")
	}
	serve(t, pod, "10.9.0.2:5555")
	serve(t, pod, "10.9.0.2:5556")
	serve(t, client, "10.9.0.1:7777")

	if err := d.Apply("/run/netns/"+pod, "runc-pod-uid", kataPolicies(t, true)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	expectConnect(t, client, "10.9.0.2:5555", "allowed port")
	expectBlocked(t, client, "10.9.0.2:5556", "port not in policy")
	expectBlocked(t, pod, "10.9.0.1:7777", "egress denied")
}
