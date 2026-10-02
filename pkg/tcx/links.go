package tcx

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// linkInfo is the part of a network interface the datapath needs to find
// where a pod interface's traffic can be policed.
type linkInfo struct {
	Index int
	Name  string
	Kind  string // IFLA_INFO_KIND, e.g. "veth", "macvlan", "macvtap", "dummy"
	// Link is the index of the lower device (IFLA_LINK), 0 if none.
	Link int
	// LinkNetnsID is IFLA_LINK_NETNSID when the lower device lives in
	// another network namespace, -1 otherwise.
	LinkNetnsID int
}

// dummyKind is the IFLA_INFO_KIND of a dummy device.
const dummyKind = "dummy"

// DefaultInterfaceRule is the default of --tcx-interface-rules. It covers the
// runtimes that move a pod interface out of the way and leave a dummy device
// carrying its name and address behind: Virtink's bridge mode renames eth0 to
// eth0-nic, enslaves it to a bridge that also holds the VM's tap device, and
// creates a dummy eth0 with the pod address; KubeVirt's bridge binding builds
// the same topology. Traffic of such a pod only passes the renamed device.
const DefaultInterfaceRule = `^(.+)$=${1}-nic`

// InterfaceRule maps the name of a pod interface to the name of the device
// whose TCX hooks see its traffic.
type InterfaceRule struct {
	Match       *regexp.Regexp
	Replacement string
}

// ParseInterfaceRules parses "<regex>=<replacement>" specifications, split at
// the first "=". The replacement expands the submatches of the regular
// expression as ${1}, ${2} and so on. Blank specifications are ignored.
func ParseInterfaceRules(specs []string) ([]InterfaceRule, error) {
	rules := make([]InterfaceRule, 0, len(specs))
	for _, spec := range specs {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		expr, replacement, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, fmt.Errorf("interface rule %q: want \"<regex>=<replacement>\"", spec)
		}
		if expr == "" {
			return nil, fmt.Errorf("interface rule %q: empty regular expression", spec)
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("interface rule %q: %w", spec, err)
		}
		rules = append(rules, InterfaceRule{Match: re, Replacement: replacement})
	}
	return rules, nil
}

// target returns the device name the rule maps name to, and whether the rule
// applies at all. A rule that maps a name to itself does not.
func (r InterfaceRule) target(name string) (string, bool) {
	match := r.Match.FindStringSubmatchIndex(name)
	if match == nil {
		return "", false
	}
	target := string(r.Match.ExpandString(nil, r.Replacement, name, match))
	if target == "" || target == name {
		return "", false
	}
	return target, true
}

// enforcementLink returns the device whose TCX hooks see the traffic of the
// pod interface name.
//
// That is the interface itself, unless the runtime moved its traffic to
// another device: the rules rename it (see DefaultInterfaceRule), and a
// macvtap device may sit on top of it (Kata's "macvtap" networking).
func enforcementLink(links []linkInfo, name string, rules []InterfaceRule) (linkInfo, error) {
	target, err := resolveLink(links, name, rules)
	if err != nil {
		return linkInfo{}, err
	}
	// A dummy device discards everything it is handed and receives nothing,
	// so a program on its hooks would silently police no traffic at all.
	if target.Kind == dummyKind {
		return linkInfo{}, fmt.Errorf("%s is a dummy device and carries no traffic; name the device that does with --tcx-interface-rules", target.Name)
	}
	return target, nil
}

func resolveLink(links []linkInfo, name string, rules []InterfaceRule) (linkInfo, error) {
	iface, err := baseLink(links, name, rules)
	if err != nil {
		return linkInfo{}, err
	}

	// Traffic to and from the VM passes a macvtap device on top of the
	// interface, and for a macvlan interface never the interface itself,
	// since the kernel stacks a macvtap created on a macvlan device directly
	// on the macvlan's lower device. So the macvtap is either linked to the
	// interface, or shares its lower device. When several pod interfaces
	// share a lower device, their macvtap devices were created in the same
	// order as the interfaces, so both are matched by index.
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
		return linkInfo{}, fmt.Errorf("interface %s has %d macvtap devices", iface.Name, len(direct))
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
		return linkInfo{}, fmt.Errorf("cannot tell which of %d macvtap devices on the lower device of %s belongs to it (%d interfaces share it)", len(macvtaps), iface.Name, len(siblings))
	}
	byIndex := func(a, b linkInfo) int { return a.Index - b.Index }
	slices.SortFunc(siblings, byIndex)
	slices.SortFunc(macvtaps, byIndex)
	return macvtaps[slices.IndexFunc(siblings, func(l linkInfo) bool { return l.Name == iface.Name })], nil
}

// baseLink returns the device the pod interface name is policed on before the
// macvtap resolution: the device named by the first rule that both matches the
// interface and names a device the namespace has, else the interface itself.
//
// The interface itself may be absent, for a runtime that renames it without
// leaving anything behind.
func baseLink(links []linkInfo, name string, rules []InterfaceRule) (linkInfo, error) {
	byName := func(n string) int {
		return slices.IndexFunc(links, func(l linkInfo) bool { return l.Name == n })
	}
	for _, rule := range rules {
		target, ok := rule.target(name)
		if !ok {
			continue
		}
		if i := byName(target); i >= 0 {
			return links[i], nil
		}
	}
	if i := byName(name); i >= 0 {
		return links[i], nil
	}
	return linkInfo{}, fmt.Errorf("interface %s not found", name)
}
