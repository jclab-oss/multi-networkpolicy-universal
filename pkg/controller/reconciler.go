package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/tcx"
	multiutils "github.com/telekom/multi-networkpolicy-nftables/pkg/utils"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	klog "k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

var _ controllers.PolicyDeps = (*NodeReconciler)(nil)

// SandboxDatapath enforces the policies of pods whose traffic bypasses the
// netfilter hooks of their network namespace (see package tcx).
type SandboxDatapath interface {
	Apply(netnsPath string, podUID types.UID, endpoints []tcx.EndpointPolicy) error
	Prune(keep func(tcx.Endpoint) bool) error
	RemoveAll() error
}

var _ SandboxDatapath = (*tcx.Datapath)(nil)

// NodeReconciler reconciles the local node's pods into nftables rules, or into
// TCX programs for pods of the runtime classes in TCXRuntimeClasses.
type NodeReconciler struct {
	NodeName       string
	Client         client.Client
	PolicyDeps     controllers.PolicyDeps
	HostPrefix     string
	NetworkPlugins []string
	CommonCfg      controllers.CommonRuleConfig
	CriClient      pb.RuntimeServiceClient
	CriConn        *grpc.ClientConn

	ContainerRuntimeEndpoint string
	criMu                    sync.Mutex

	// TCX enforces the pods whose spec.runtimeClassName is listed in
	// TCXRuntimeClasses, such as Kata Containers pods. Nil disables it.
	TCX               SandboxDatapath
	TCXRuntimeClasses []string

	ApplyRulesForPodFunc func(context.Context, controllers.PolicyDeps, controllers.CommonRuleConfig, controllers.PolicyMap, *corev1.Pod, *controllers.PodInfo, string) error
}

// CleanupOnShutdown removes policy rules for pods on the local node.
func CleanupOnShutdown(ctx context.Context, r *NodeReconciler, cl client.Client) error {
	var tcxErr error
	if r.TCX != nil {
		// The pinned programs do not depend on the pods' state; remove them
		// first so no failure below can leave them behind.
		klog.Info("cleanup: removing TCX programs")
		if tcxErr = r.TCX.RemoveAll(); tcxErr != nil {
			tcxErr = fmt.Errorf("remove TCX programs: %w", tcxErr)
		}
	}
	return errors.Join(tcxErr, cleanupAllPods(ctx, r, cl))
}

// SetupWithManager wires node, pod, policy, namespace, and NAD watches.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(NodePredicate(r.NodeName))).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(mapPodToNode(r.NodeName)),
			builder.WithPredicates(PodPredicate())).
		Watches(&multiv1beta1.MultiNetworkPolicy{},
			handler.EnqueueRequestsFromMapFunc(mapPolicyToNode(r.NodeName)),
			builder.WithPredicates(PolicyPredicate())).
		Watches(&netdefv1.NetworkAttachmentDefinition{},
			handler.EnqueueRequestsFromMapFunc(mapNetDefToNode(r.NodeName))).
		Watches(&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(mapNamespaceToNode(r.NodeName))).
		Complete(r)
}

// Reconcile applies current policy state to all relevant pods on the local node.
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name != r.NodeName {
		return ctrl.Result{}, nil
	}

	var policyList multiv1beta1.MultiNetworkPolicyList
	if err := r.Client.List(ctx, &policyList); err != nil {
		return ctrl.Result{}, fmt.Errorf("list policies: %w", err)
	}
	policyMap := buildPolicyMap(policyList.Items)

	var podList corev1.PodList
	if err := r.Client.List(ctx, &podList, client.MatchingFields{PodHostnameIndex: r.NodeName}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list pods for node %s: %w", r.NodeName, err)
	}
	deps := r.policyDeps()
	retryNeeded := false
	var retryErrs []error
	// TCX endpoints to keep: pod UID -> interfaces, nil keeps all of the
	// pod's interfaces. Anything else pinned by this node is pruned.
	tcxKeep := map[types.UID]map[string]bool{}
	for i := range podList.Items {
		pod := &podList.Items[i]
		if !controllers.IsMultiNetworkpolicyTarget(pod) {
			continue
		}
		useTCX := r.usesTCX(pod)

		podInfo, err := deps.GetPodInfo(ctx, pod)
		if err != nil {
			klog.Errorf("failed to get pod info for %s/%s: %v", pod.Namespace, pod.Name, err)
			retryNeeded = true
			retryErrs = append(retryErrs, fmt.Errorf("get pod info for %s/%s: %w", pod.Namespace, pod.Name, err))
			if useTCX {
				// Keep enforcing the last applied policy until the pod
				// can be inspected again.
				tcxKeep[pod.UID] = nil
			}
			continue
		}
		if podInfo == nil || len(podInfo.Interfaces) == 0 {
			klog.V(4).Infof("pod %s/%s has no relevant interfaces, skipping", pod.Namespace, pod.Name)
			continue
		}

		if useTCX {
			keep, err := r.applyTCX(ctx, deps, policyMap, pod, podInfo)
			tcxKeep[pod.UID] = keep
			if err != nil {
				klog.Errorf("failed to apply TCX policy for %s/%s: %v", pod.Namespace, pod.Name, err)
				retryErrs = append(retryErrs, fmt.Errorf("apply TCX policy for %s/%s: %w", pod.Namespace, pod.Name, err))
			}
			continue
		}

		if err := r.applyRulesForPod(ctx, deps, r.CommonCfg, policyMap, pod, podInfo, r.HostPrefix); err != nil {
			klog.Errorf("failed to apply rules for %s/%s: %v", pod.Namespace, pod.Name, err)
			retryNeeded = true
			retryErrs = append(retryErrs, fmt.Errorf("apply rules for %s/%s: %w", pod.Namespace, pod.Name, err))
		}
	}

	if r.TCX != nil {
		if err := r.TCX.Prune(func(ep tcx.Endpoint) bool {
			ifaces, ok := tcxKeep[ep.PodUID]
			return ok && (ifaces == nil || ifaces[ep.Interface])
		}); err != nil {
			klog.Errorf("failed to prune TCX policies: %v", err)
			retryErrs = append(retryErrs, fmt.Errorf("prune TCX policies: %w", err))
		}
	}

	if len(retryErrs) > 0 {
		return ctrl.Result{}, errors.Join(retryErrs...)
	}
	if retryNeeded {
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

func (r *NodeReconciler) policyDeps() controllers.PolicyDeps {
	if r.PolicyDeps != nil {
		return r.PolicyDeps
	}
	return r
}

func (r *NodeReconciler) applyRulesForPod(ctx context.Context, deps controllers.PolicyDeps, cfg controllers.CommonRuleConfig, policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo, hostPrefix string) error {
	if r.ApplyRulesForPodFunc != nil {
		return r.ApplyRulesForPodFunc(ctx, deps, cfg, policyMap, pod, podInfo, hostPrefix)
	}
	return applyRulesForPod(ctx, deps, cfg, policyMap, pod, podInfo, hostPrefix)
}

func (r *NodeReconciler) usesTCX(pod *corev1.Pod) bool {
	if r.TCX == nil || pod.Spec.RuntimeClassName == nil {
		return false
	}
	return slices.Contains(r.TCXRuntimeClasses, *pod.Spec.RuntimeClassName)
}

// applyTCX compiles and applies the policies of a pod enforced by the TCX
// datapath. It returns the interfaces whose programs must be kept, nil for
// all of them.
//
// A policy that cannot be compiled (a named port, too many rules) fails
// closed: the directions it isolates accept no new connections until it is
// fixed. When applying fails, the policy applied last stays in place.
func (r *NodeReconciler) applyTCX(ctx context.Context, deps controllers.PolicyDeps, policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo) (map[string]bool, error) {
	endpoints, compileErr := tcx.Compile(ctx, deps, r.CommonCfg, policyMap, pod, podInfo)
	if compileErr != nil {
		compileErr = fmt.Errorf("compile (denying new connections in the isolated directions): %w", compileErr)
		endpoints = tcx.Isolation(r.CommonCfg, policyMap, pod, podInfo)
	}
	if err := r.TCX.Apply(filepath.Join(r.HostPrefix, podInfo.NetNSPath), pod.UID, endpoints); err != nil {
		return nil, errors.Join(compileErr, err)
	}
	keep := make(map[string]bool, len(endpoints))
	for _, ep := range endpoints {
		keep[ep.Interface] = true
	}
	return keep, compileErr
}

// ListPods returns pods matching the provided label selector.
func (r *NodeReconciler) ListPods(ctx context.Context, selector labels.Selector) ([]*corev1.Pod, error) {
	var podList corev1.PodList
	if err := r.Client.List(ctx, &podList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}
	result := make([]*corev1.Pod, len(podList.Items))
	for i := range podList.Items {
		result[i] = &podList.Items[i]
	}
	return result, nil
}

// GetNamespaceInfo returns the labels needed for namespace selector evaluation.
func (r *NodeReconciler) GetNamespaceInfo(ctx context.Context, namespace string) (*controllers.NamespaceInfo, error) {
	var ns corev1.Namespace
	if err := r.Client.Get(ctx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		return nil, err
	}
	return &controllers.NamespaceInfo{Name: ns.Name, Labels: ns.Labels}, nil
}

// GetPodInfo extracts pod interface metadata and resolves its network namespace when needed.
func (r *NodeReconciler) GetPodInfo(ctx context.Context, pod *corev1.Pod) (*controllers.PodInfo, error) {
	podInfo, err := controllers.NewPodInfoFromPod(ctx, pod, nil, r.NodeName, r.NetworkPlugins, r)
	if err != nil {
		return nil, fmt.Errorf("build pod info for %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if podInfo == nil || len(podInfo.Interfaces) == 0 || !multiutils.CheckNodeNameIdentical(r.NodeName, pod.Spec.NodeName) {
		return podInfo, nil
	}

	criClient, err := r.criRuntimeClient(ctx)
	if err != nil {
		return nil, err
	}
	netnsPath, err := controllers.GetPodNetNSPathWithContext(ctx, criClient, pod)
	if err != nil {
		return nil, fmt.Errorf("resolve pod network namespace for %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if netnsPath == "" {
		return nil, fmt.Errorf("resolve pod network namespace for %s/%s: empty netns path", pod.Namespace, pod.Name)
	}
	podInfo.NetNSPath = netnsPath
	return podInfo, nil
}

func (r *NodeReconciler) criRuntimeClient(ctx context.Context) (pb.RuntimeServiceClient, error) {
	r.criMu.Lock()
	defer r.criMu.Unlock()

	if r.CriClient != nil {
		return r.CriClient, nil
	}
	if r.ContainerRuntimeEndpoint == "" {
		return nil, fmt.Errorf("CRI runtime endpoint is empty")
	}

	criClient, criConn, err := controllers.GetCriRuntimeClientWithContext(ctx, r.ContainerRuntimeEndpoint, r.HostPrefix)
	if err != nil {
		return nil, fmt.Errorf("connect to CRI runtime %q: %w", r.ContainerRuntimeEndpoint, err)
	}
	r.CriClient = criClient
	r.CriConn = criConn
	return r.CriClient, nil
}

// CloseCRI closes any cached CRI connection.
func (r *NodeReconciler) CloseCRI() error {
	r.criMu.Lock()
	defer r.criMu.Unlock()

	var err error
	if r.CriConn != nil {
		err = r.CriConn.Close()
	}
	r.CriConn = nil
	r.CriClient = nil
	return err
}

// GetPluginType resolves the CNI plugin type for a NetworkAttachmentDefinition.
func (r *NodeReconciler) GetPluginType(ctx context.Context, namespacedName types.NamespacedName) (string, error) {
	return resolvePluginType(ctx, r.Client, namespacedName)
}

func resolvePluginType(ctx context.Context, cl client.Client, namespacedName types.NamespacedName) (string, error) {
	var nad netdefv1.NetworkAttachmentDefinition
	if err := cl.Get(ctx, namespacedName, &nad); err != nil {
		return "", fmt.Errorf("get network attachment definition: %w", err)
	}

	confBytes, err := netdefutils.GetCNIConfig(&nad, "/etc/cni/multus/net.d")
	if err != nil {
		return "", fmt.Errorf("get CNI config: %w", err)
	}

	netconfList := &cnitypes.NetConfList{}
	listErr := json.Unmarshal(confBytes, netconfList)
	if listErr == nil && len(netconfList.Plugins) > 0 {
		return netconfList.Plugins[0].Type, nil
	}

	netconf := &cnitypes.NetConf{}
	confErr := json.Unmarshal(confBytes, netconf)
	if confErr == nil && netconf.Type != "" {
		return netconf.Type, nil
	}
	if listErr != nil || confErr != nil {
		return "", fmt.Errorf("parse CNI config for network attachment %s: %w", namespacedName, errors.Join(listErr, confErr))
	}

	return "", fmt.Errorf("parse CNI config for network attachment %s: plugin type is empty", namespacedName)
}

func buildPolicyMap(policies []multiv1beta1.MultiNetworkPolicy) controllers.PolicyMap {
	pm := make(controllers.PolicyMap, len(policies))
	for i := range policies {
		p := &policies[i]
		pm[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] = p
	}
	return pm
}
