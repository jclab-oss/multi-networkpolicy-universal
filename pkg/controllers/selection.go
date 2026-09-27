package controllers

import (
	"fmt"
	"slices"
	"strings"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
)

// PolicyNetworkAnnotation declares which secondary networks a policy targets.
const PolicyNetworkAnnotation = "k8s.v1.cni.cncf.io/policy-for"

// SelectedPolicy is a policy that selects a pod, together with the networks
// (namespace/name of the net-attach-defs) it applies to.
type SelectedPolicy struct {
	Policy   *multiv1beta1.MultiNetworkPolicy
	Networks []string
}

// SelectPolicies returns the policies that select the pod on at least one of
// its interfaces, split by the direction they enable and sorted by
// namespace/name. Every enforcement backend starts from this selection.
func SelectPolicies(policyMap PolicyMap, pod *corev1.Pod, podInfo *PodInfo) (ingress, egress []SelectedPolicy) {
	for _, policy := range policyMap {
		if policy.GetNamespace() != pod.Namespace {
			continue
		}
		if policy.Spec.PodSelector.Size() != 0 {
			policyPodSelector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
			if err != nil {
				klog.Errorf("bad label selector for policy [%s/%s]: %v", policy.Namespace, policy.Name, err)
				continue
			}
			if !policyPodSelector.Matches(labels.Set(pod.Labels)) {
				continue
			}
		}

		ingressEnable, egressEnable := EnabledPolicyTypes(policy)
		klog.V(8).Infof("ingress/egress = %v/%v\n", ingressEnable, egressEnable)

		policyNetworksAnnot, ok := policy.GetAnnotations()[PolicyNetworkAnnotation]
		if !ok {
			continue
		}
		policyNetworksAnnot = strings.ReplaceAll(policyNetworksAnnot, " ", "")
		policyNetworks := strings.Split(policyNetworksAnnot, ",")
		for pidx, networkName := range policyNetworks {
			if !strings.ContainsAny(networkName, "/") {
				policyNetworks[pidx] = fmt.Sprintf("%s/%s", policy.GetNamespace(), networkName)
			}
		}
		slices.Sort(policyNetworks)

		if podInfo.CheckPolicyNetwork(policyNetworks) {
			if ingressEnable {
				ingress = append(ingress, SelectedPolicy{Policy: policy, Networks: policyNetworks})
			}
			if egressEnable {
				egress = append(egress, SelectedPolicy{Policy: policy, Networks: policyNetworks})
			}
		}
	}

	slices.SortStableFunc(ingress, compareSelectedPolicy)
	slices.SortStableFunc(egress, compareSelectedPolicy)
	return ingress, egress
}

func compareSelectedPolicy(a, b SelectedPolicy) int {
	return strings.Compare(a.Policy.GetNamespace()+"/"+a.Policy.GetName(), b.Policy.GetNamespace()+"/"+b.Policy.GetName())
}

// EnabledPolicyTypes reports whether the policy restricts ingress and egress.
func EnabledPolicyTypes(policy *multiv1beta1.MultiNetworkPolicy) (bool, bool) {
	var ingressEnable, egressEnable bool
	if len(policy.Spec.PolicyTypes) > 0 {
		for _, v := range policy.Spec.PolicyTypes {
			if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeIngress)) {
				ingressEnable = true
			} else if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeEgress)) {
				egressEnable = true
			}
		}
		return ingressEnable, egressEnable
	}

	return policy.Spec.Ingress != nil, policy.Spec.Egress != nil
}
