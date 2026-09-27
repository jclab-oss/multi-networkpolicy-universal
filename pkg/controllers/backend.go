package controllers

// Values of the backend annotation.
const (
	BackendNftables = "nftables"
	BackendTCX      = "tcx"
)

// DefaultBackendAnnotation is the pod annotation that selects the enforcement
// backend of a pod, overriding the choice made from its RuntimeClass.
const DefaultBackendAnnotation = "multinetworkpolicy.io/backend"
