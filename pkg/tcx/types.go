package tcx

import "k8s.io/apimachinery/pkg/types"

// Config configures the datapath.
type Config struct {
	// PinPath is the bpffs directory the daemon owns. The shared flow tables
	// and the links of every policed interface are pinned below it.
	PinPath string
	// FlowTableSize is the number of flows tracked across all interfaces.
	FlowTableSize uint32
}

// Endpoint names a policed pod interface.
type Endpoint struct {
	PodUID    types.UID
	Interface string
}
