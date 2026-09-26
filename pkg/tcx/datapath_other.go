//go:build !linux

package tcx

import (
	"fmt"
	"runtime"

	"k8s.io/apimachinery/pkg/types"
)

// Datapath is only implemented on Linux.
type Datapath struct{}

// NewDatapath always fails outside Linux.
func NewDatapath(Config) (*Datapath, error) {
	return nil, fmt.Errorf("the TCX datapath is unsupported on %s", runtime.GOOS)
}

// Close is a no-op.
func (d *Datapath) Close() error { return nil }

// Apply always fails outside Linux.
func (d *Datapath) Apply(string, types.UID, []EndpointPolicy) error {
	return fmt.Errorf("the TCX datapath is unsupported on %s", runtime.GOOS)
}

// Prune is a no-op.
func (d *Datapath) Prune(func(Endpoint) bool) error { return nil }

// RemoveAll is a no-op.
func (d *Datapath) RemoveAll() error { return nil }

// RemovePinned is a no-op.
func RemovePinned(string) error { return nil }
