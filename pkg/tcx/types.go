package tcx

import "k8s.io/apimachinery/pkg/types"

// Config configures the datapath.
type Config struct {
	// PinPath is the bpffs directory the daemon owns. The shared flow tables
	// and the links of every policed interface are pinned below it.
	PinPath string
	// FlowTableSize is the number of flows tracked across all interfaces.
	FlowTableSize uint32
	// InterfaceRules map a pod interface to the device whose TCX hooks are
	// policed for it, for runtimes that move its traffic to another device.
	InterfaceRules []InterfaceRule
}

// Endpoint names a policed pod interface.
type Endpoint struct {
	PodUID    types.UID
	Interface string
}
