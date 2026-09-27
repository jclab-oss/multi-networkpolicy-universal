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

// annotatedPod returns a runc pod ("runc") or a pod of the RuntimeClass
// "kata" ("kata") carrying the backend annotation key=value.
func annotatedPod(t *testing.T, namespace, nodeName, kind, key, value string) *corev1.Pod {
	t.Helper()
	pod := newPod(namespace, kind, nodeName, map[string]string{"app": kind})
	if kind == "kata" {
		pod = newKataPod(t, namespace, nodeName)
	}
	pod.Annotations = map[string]string{key: value}
	return pod
}

type backendRecorder struct {
	nft     []string
	flushed []string
}

func (b *backendRecorder) reconciler(t *testing.T, nodeName string, sandbox SandboxDatapath) *NodeReconciler {
	t.Helper()
	return &NodeReconciler{
		NodeName:          nodeName,
		Client:            testClient,
		TCX:               sandbox,
		TCXRuntimeClasses: []string{"kata"},
		BackendAnnotation: controllers.DefaultBackendAnnotation,
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(p *corev1.Pod) (*controllers.PodInfo, error) { return podInfoWith(p, "net1"), nil },
		},
		ApplyRulesForPodFunc: func(_ context.Context, _ controllers.PolicyDeps, _ controllers.CommonRuleConfig, _ controllers.PolicyMap, p *corev1.Pod, _ *controllers.PodInfo, _ string) error {
			b.nft = append(b.nft, p.Name)
			return nil
		},
		FlushRulesForPodFunc: func(_, podName, _, _ string) error {
			b.flushed = append(b.flushed, podName)
			return nil
		},
	}
}

func TestReconcile_BackendAnnotationSelectsTCXForRuncPod(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := annotatedPod(t, namespace, nodeName, "runc", controllers.DefaultBackendAnnotation, "tcx")
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), pod)
	setPodRunning(t, pod)

	sandbox := &fakeSandbox{}
	rec := &backendRecorder{}
	r := rec.reconciler(t, nodeName, sandbox)
	for i := 0; i < 2; i++ {
		if err := reconcileNode(t, r); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	if _, ok := sandbox.applied[pod.UID]; !ok || len(rec.nft) != 0 {
		t.Fatalf("TCX applied = %v, nftables applied to %v; want TCX only", sandbox.applied, rec.nft)
	}
	// The pod's nftables rules, e.g. from before the annotation was set, are
	// removed once.
	if !slices.Equal(rec.flushed, []string{"runc"}) {
		t.Errorf("nftables rules flushed for %v, want once for runc", rec.flushed)
	}
}

func TestReconcile_BackendAnnotationSelectsNftablesForKataPod(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := annotatedPod(t, namespace, nodeName, "kata", controllers.DefaultBackendAnnotation, " NFTables ")
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), pod)
	setPodRunning(t, pod)

	sandbox := &fakeSandbox{pinned: []tcx.Endpoint{{PodUID: pod.UID, Interface: "net1"}}}
	rec := &backendRecorder{}
	if err := reconcileNode(t, rec.reconciler(t, nodeName, sandbox)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !slices.Equal(rec.nft, []string{"kata"}) || len(sandbox.applied) != 0 {
		t.Fatalf("nftables applied to %v, TCX applied = %v; want nftables only", rec.nft, sandbox.applied)
	}
	if len(sandbox.pinned) != 0 {
		t.Errorf("TCX programs of a pod that moved to nftables must be removed, pinned = %v", sandbox.pinned)
	}
}

func TestReconcile_InvalidBackendAnnotationFallsBack(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := annotatedPod(t, namespace, nodeName, "kata", controllers.DefaultBackendAnnotation, "ebpf")
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), pod)
	setPodRunning(t, pod)

	sandbox := &fakeSandbox{}
	rec := &backendRecorder{}
	if err := reconcileNode(t, rec.reconciler(t, nodeName, sandbox)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := sandbox.applied[pod.UID]; !ok || len(rec.nft) != 0 {
		t.Fatalf("an invalid value must fall back to the RuntimeClass (TCX for kata); TCX = %v, nftables = %v", sandbox.applied, rec.nft)
	}
}

func TestReconcile_CustomBackendAnnotationKey(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := annotatedPod(t, namespace, nodeName, "runc", "example.com/dataplane", "tcx")
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), pod)
	setPodRunning(t, pod)

	sandbox := &fakeSandbox{}
	rec := &backendRecorder{}
	r := rec.reconciler(t, nodeName, sandbox)
	r.BackendAnnotation = "example.com/dataplane"
	if err := reconcileNode(t, r); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := sandbox.applied[pod.UID]; !ok {
		t.Fatalf("the configured annotation key must select TCX")
	}

	// With the default key configured, the custom annotation means nothing.
	rec = &backendRecorder{}
	sandbox = &fakeSandbox{}
	if err := reconcileNode(t, rec.reconciler(t, nodeName, sandbox)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(sandbox.applied) != 0 || !slices.Equal(rec.nft, []string{"runc"}) {
		t.Errorf("TCX = %v, nftables = %v; want nftables for an unrecognized annotation key", sandbox.applied, rec.nft)
	}
}

func TestReconcile_BackendAnnotationTCXWithoutDatapath(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := annotatedPod(t, namespace, nodeName, "runc", controllers.DefaultBackendAnnotation, "tcx")
	seedObjects(t, newNamespace(namespace, nil), newNode(nodeName), pod)
	setPodRunning(t, pod)

	rec := &backendRecorder{}
	r := rec.reconciler(t, nodeName, nil)
	r.TCXUnavailable = errors.New("pin path /sys/fs/bpf/multi-networkpolicy is not on a bpf filesystem")
	err := reconcileNode(t, r)
	if err == nil || !strings.Contains(err.Error(), "TCX datapath is unavailable") || !strings.Contains(err.Error(), "bpf filesystem") {
		t.Fatalf("Reconcile error = %v, want the unavailable datapath and its reason", err)
	}
	// Not silently enforced by nftables, which cannot police Kata pods.
	if len(rec.nft) != 0 {
		t.Errorf("nftables applied to %v", rec.nft)
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
