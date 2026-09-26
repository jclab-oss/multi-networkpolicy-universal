package tcx

import (
	"fmt"
	"slices"
)

// linkInfo is the part of a network interface the datapath needs to find
// where a pod interface's traffic can be policed.
type linkInfo struct {
	Index int
	Name  string
	Kind  string // IFLA_INFO_KIND, e.g. "veth", "macvlan", "macvtap"
	// Link is the index of the lower device (IFLA_LINK), 0 if none.
	Link int
	// LinkNetnsID is IFLA_LINK_NETNSID when the lower device lives in
	// another network namespace, -1 otherwise.
	LinkNetnsID int
}

// enforcementLink returns the device whose TCX hooks see the traffic of the
// pod interface name.
//
// That is the interface itself, unless the runtime attached the VM through a
// macvtap device on top of it (Kata's "macvtap" networking): traffic to and
// from the VM then passes the macvtap device, and for a macvlan interface
// never the interface itself, since the kernel stacks a macvtap created on a
// macvlan device directly on the macvlan's lower device. So the macvtap is
// either linked to the interface, or shares its lower device. When several
// pod interfaces share a lower device, their macvtap devices were created in
// the same order as the interfaces, so both are matched by index.
func enforcementLink(links []linkInfo, name string) (linkInfo, error) {
	i := slices.IndexFunc(links, func(l linkInfo) bool { return l.Name == name })
	if i < 0 {
		return linkInfo{}, fmt.Errorf("interface %s not found", name)
	}
	iface := links[i]

	var direct []linkInfo
	for _, l := range links {
		if l.Kind == "macvtap" && l.Link == iface.Index && l.LinkNetnsID < 0 {
			direct = append(direct, l)
		}
	}
	switch len(direct) {
	case 0:
	case 1:
		return direct[0], nil
	default:
		return linkInfo{}, fmt.Errorf("interface %s has %d macvtap devices", name, len(direct))
	}

	if iface.Link == 0 {
		return iface, nil
	}
	sameLower := func(l linkInfo) bool {
		return l.Link == iface.Link && l.LinkNetnsID == iface.LinkNetnsID
	}
	var siblings, macvtaps []linkInfo
	for _, l := range links {
		if !sameLower(l) {
			continue
		}
		switch l.Kind {
		case "macvtap":
			macvtaps = append(macvtaps, l)
		case iface.Kind:
			siblings = append(siblings, l)
		}
	}
	if len(macvtaps) == 0 {
		return iface, nil
	}
	if len(macvtaps) != len(siblings) {
		return linkInfo{}, fmt.Errorf("cannot tell which of %d macvtap devices on the lower device of %s belongs to it (%d interfaces share it)", len(macvtaps), name, len(siblings))
	}
	byIndex := func(a, b linkInfo) int { return a.Index - b.Index }
	slices.SortFunc(siblings, byIndex)
	slices.SortFunc(macvtaps, byIndex)
	return macvtaps[slices.IndexFunc(siblings, func(l linkInfo) bool { return l.Name == name })], nil
}
