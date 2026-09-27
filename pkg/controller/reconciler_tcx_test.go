package controller

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/tcx"
	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// fakeSandbox records what the reconciler asks of the TCX datapath. Pinned
// holds the endpoints the datapath has; Prune removes the rejected ones.
type fakeSandbox struct {
	applied   map[types.UID][]tcx.EndpointPolicy
	netns     map[types.UID]string
	pinned    []tcx.Endpoint
	applyErr  error
	removeAll int
}

func (f *fakeSandbox) Apply(netnsPath string, podUID types.UID, endpoints []tcx.EndpointPolicy) error {
	if f.applied == nil {
		f.applied = map[types.UID][]tcx.EndpointPolicy{}
		f.netns = map[types.UID]string{}
	}
	f.applied[podUID] = endpoints
	f.netns[podUID] = netnsPath
	if f.applyErr != nil {
		return f.applyErr
	}
	for _, ep := range endpoints {
		e := tcx.Endpoint{PodUID: podUID, Interface: ep.Interface}
		if !slices.Contains(f.pinned, e) {
			f.pinned = append(f.pinned, e)
		}
	}
	return nil
}

func (f *fakeSandbox) Prune(keep func(tcx.Endpoint) bool) error {
	f.pinned = slices.DeleteFunc(f.pinned, func(e tcx.Endpoint) bool { return !keep(e) })
	return nil
}

func (f *fakeSandbox) RemoveAll() error {
	f.removeAll++
	f.pinned = nil
	return nil
}

// ensureRuntimeClass creates the RuntimeClass so the API server admits pods
// that reference it.
func ensureRuntimeClass(t *testing.T, name string) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := nodev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	c, err := client.New(testEnv.Config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	rc := &nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: name}, Handler: name}
	if err := c.Create(context.Background(), rc); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create RuntimeClass %s: %v", name, err)
	}
}

// newKataPod returns a pod named "kata" of the RuntimeClass "kata".
func newKataPod(t *testing.T, namespace, nodeName string) *corev1.Pod {
	t.Helper()
	ensureRuntimeClass(t, "kata")
	pod := newPod(namespace, "kata", nodeName, map[string]string{"app": "kata"})
	rc := "kata"
	pod.Spec.RuntimeClassName = &rc
	return pod
}

func podInfoWith(pod *corev1.Pod, ifaces ...string) *controllers.PodInfo {
	info := &controllers.PodInfo{Name: pod.Name, Namespace: pod.Namespace, NodeName: pod.Spec.NodeName, NetNSPath: "/proc/42/ns/net"}
	for _, i := range ifaces {
		info.Interfaces = append(info.Interfaces, controllers.InterfaceInfo{NetattachName: "default/" + i, InterfaceName: i, IPs: []string{"10.0.0.1"}})
	}
	return info
}

func reconcileNode(t *testing.T, r *NodeReconciler) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: r.NodeName}})
	return err
}

func TestReconcile_TCXRuntimeClassSelectsBackend(t *testing.T) {
	namespace, nodeName := testScope(t)
	kata := newKataPod(t, namespace, nodeName)
	runc := newPod(namespace, "runc", nodeName, map[string]string{"app": "runc"})
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), kata, runc)
	setPodRunning(t, kata)
	setPodRunning(t, runc)

	sandbox := &fakeSandbox{}
	var nftPods []string
	r := &NodeReconciler{
		NodeName:          nodeName,
		Client:            testClient,
		HostPrefix:        "/host",
		TCX:               sandbox,
		TCXRuntimeClasses: []string{"kata-qemu", "kata"},
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(p *corev1.Pod) (*controllers.PodInfo, error) { return podInfoWith(p, "net1"), nil },
		},
		ApplyRulesForPodFunc: func(_ context.Context, _ controllers.PolicyDeps, _ controllers.CommonRuleConfig, _ controllers.PolicyMap, p *corev1.Pod, _ *controllers.PodInfo, _ string) error {
			nftPods = append(nftPods, p.Name)
			return nil
		},
	}
	if err := reconcileNode(t, r); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !slices.Equal(nftPods, []string{"runc"}) {
		t.Errorf("nftables backend applied to %v, want [runc]", nftPods)
	}
	eps, ok := sandbox.applied[kata.UID]
	if !ok || len(sandbox.applied) != 1 {
		t.Fatalf("TCX backend applied to %v, want only the kata pod", sandbox.applied)
	}
	if len(eps) != 1 || eps[0].Interface != "net1" {
		t.Errorf("TCX endpoints = %+v, want net1", eps)
	}
	if got := sandbox.netns[kata.UID]; got != "/host/proc/42/ns/net" {
		t.Errorf("netns path = %q, want the host-prefixed CRI path", got)
	}
}

func TestReconcile_TCXDisabledUsesNftables(t *testing.T) {
	namespace, nodeName := testScope(t)
	kata := newKataPod(t, namespace, nodeName)
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), kata)
	setPodRunning(t, kata)

	nftCalled := false
	r := &NodeReconciler{
		NodeName:          nodeName,
		Client:            testClient,
		TCXRuntimeClasses: []string{"kata"}, // no datapath: the feature is off
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(p *corev1.Pod) (*controllers.PodInfo, error) { return podInfoWith(p, "net1"), nil },
		},
		ApplyRulesForPodFunc: func(context.Context, controllers.PolicyDeps, controllers.CommonRuleConfig, controllers.PolicyMap, *corev1.Pod, *controllers.PodInfo, string) error {
			nftCalled = true
			return nil
		},
	}
	if err := reconcileNode(t, r); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !nftCalled {
		t.Errorf("without a TCX datapath every pod must use nftables")
	}
}

func TestReconcile_TCXPrunesStaleEndpoints(t *testing.T) {
	namespace, nodeName := testScope(t)
	kata := newKataPod(t, namespace, nodeName)
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), kata)
	setPodRunning(t, kata)

	sandbox := &fakeSandbox{pinned: []tcx.Endpoint{
		{PodUID: "deleted-pod", Interface: "net1"},
		{PodUID: kata.UID, Interface: "net9"}, // interface removed from the pod
	}}
	r := &NodeReconciler{
		NodeName:          nodeName,
		Client:            testClient,
		TCX:               sandbox,
		TCXRuntimeClasses: []string{"kata"},
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(p *corev1.Pod) (*controllers.PodInfo, error) { return podInfoWith(p, "net1", "net2"), nil },
		},
	}
	if err := reconcileNode(t, r); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := []tcx.Endpoint{{PodUID: kata.UID, Interface: "net1"}, {PodUID: kata.UID, Interface: "net2"}}
	if !slices.Equal(sandbox.pinned, want) {
		t.Errorf("pinned after reconcile = %v, want %v", sandbox.pinned, want)
	}
}

func TestReconcile_TCXKeepsPolicyWhenPodInfoFails(t *testing.T) {
	namespace, nodeName := testScope(t)
	kata := newKataPod(t, namespace, nodeName)
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), kata)
	setPodRunning(t, kata)

	existing := []tcx.Endpoint{{PodUID: kata.UID, Interface: "net1"}, {PodUID: kata.UID, Interface: "net2"}}
	sandbox := &fakeSandbox{pinned: slices.Clone(existing)}
	r := &NodeReconciler{
		NodeName:          nodeName,
		Client:            testClient,
		TCX:               sandbox,
		TCXRuntimeClasses: []string{"kata"},
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(*corev1.Pod) (*controllers.PodInfo, error) { return nil, errors.New("CRI unavailable") },
		},
	}
	if err := reconcileNode(t, r); err == nil {
		t.Fatalf("Reconcile must report the failure")
	}
	if !slices.Equal(sandbox.pinned, existing) {
		t.Errorf("pinned = %v, want the last applied policy kept: %v", sandbox.pinned, existing)
	}
}

func TestReconcile_TCXKeepsPolicyWhenApplyFails(t *testing.T) {
	namespace, nodeName := testScope(t)
	kata := newKataPod(t, namespace, nodeName)
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), kata)
	setPodRunning(t, kata)

	existing := []tcx.Endpoint{{PodUID: kata.UID, Interface: "net1"}}
	sandbox := &fakeSandbox{pinned: slices.Clone(existing), applyErr: errors.New("attach failed")}
	r := &NodeReconciler{
		NodeName:          nodeName,
		Client:            testClient,
		TCX:               sandbox,
		TCXRuntimeClasses: []string{"kata"},
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(p *corev1.Pod) (*controllers.PodInfo, error) { return podInfoWith(p, "net1"), nil },
		},
	}
	err := reconcileNode(t, r)
	if err == nil || !strings.Contains(err.Error(), "attach failed") {
		t.Fatalf("Reconcile error = %v, want the apply failure", err)
	}
	if !slices.Equal(sandbox.pinned, existing) {
		t.Errorf("pinned = %v, want %v", sandbox.pinned, existing)
	}
}

func TestReconcile_TCXFailsClosedWhenPolicyDoesNotCompile(t *testing.T) {
	namespace, nodeName := testScope(t)
	kata := newKataPod(t, namespace, nodeName)
	policy := newPolicy(namespace, "named-port", map[string]string{"app": "kata"}, nil)
	policy.Annotations = map[string]string{controllers.PolicyNetworkAnnotation: "default/net1"}
	named := intstr.FromString("http")
	policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{{Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &named}}}}
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), kata, policy)
	// The reconciler lists policies of all namespaces; other tests expect none.
	t.Cleanup(func() { _ = testClient.Delete(context.Background(), policy) })
	setPodRunning(t, kata)

	sandbox := &fakeSandbox{}
	r := &NodeReconciler{
		NodeName:          nodeName,
		Client:            testClient,
		TCX:               sandbox,
		TCXRuntimeClasses: []string{"kata"},
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(p *corev1.Pod) (*controllers.PodInfo, error) { return podInfoWith(p, "net1"), nil },
		},
	}
	err := reconcileNode(t, r)
	if err == nil || !strings.Contains(err.Error(), "named port") {
		t.Fatalf("Reconcile error = %v, want the compile failure", err)
	}
	eps := sandbox.applied[kata.UID]
	if len(eps) != 1 || !eps[0].Directions[tcx.Ingress].Isolated || eps[0].Directions[tcx.Egress].Isolated {
		t.Fatalf("applied %+v, want net1 with ingress isolated", eps)
	}
	if eps[0].Directions[tcx.Ingress].Allows(netip.MustParseAddr("10.0.0.9"), 6, 80, true) {
		t.Errorf("ingress must deny new connections while the policy does not compile")
	}
}

func TestCleanupOnShutdown_RemovesTCXPrograms(t *testing.T) {
	_, nodeName := testScope(t)
	sandbox := &fakeSandbox{pinned: []tcx.Endpoint{{PodUID: "p", Interface: "net1"}}}
	r := &NodeReconciler{NodeName: nodeName, Client: testClient, TCX: sandbox}
	if err := CleanupOnShutdown(context.Background(), r, testClient); err != nil {
		t.Fatalf("CleanupOnShutdown: %v", err)
	}
	if sandbox.removeAll != 1 || len(sandbox.pinned) != 0 {
		t.Errorf("RemoveAll calls = %d, pinned = %v", sandbox.removeAll, sandbox.pinned)
	}
}
