package tcx

import "testing"

func TestEnforcementLink(t *testing.T) {
	lo := linkInfo{Index: 1, Name: "lo", LinkNetnsID: -1}
	// Interfaces the rules do not name are policed as before, so every case
	// without its own rules runs with the default one.
	for _, tc := range []struct {
		name  string
		links []linkInfo
		iface string
		rules []string
		want  string
		err   bool
	}{{
		name: "tcfilter: no macvtap",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0", Kind: "veth", Link: 9, LinkNetnsID: 0},
			{Index: 5, Name: "tap0_kata", Kind: "tun", LinkNetnsID: -1}},
		iface: "eth0", want: "eth0",
	}, {
		name: "macvtap on a veth",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0", Kind: "veth", Link: 9, LinkNetnsID: 0},
			{Index: 7, Name: "tap0_kata", Kind: "macvtap", Link: 3, LinkNetnsID: -1}},
		iface: "eth0", want: "tap0_kata",
	}, {
		// Kata on a macvlan net-attach-def, as seen in the e2e cluster.
		name: "macvtap stacked on the macvlan's lower device",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0", Kind: "veth", Link: 1204, LinkNetnsID: 0},
			{Index: 4, Name: "net1", Kind: "macvlan", Link: 2, LinkNetnsID: 0},
			{Index: 56861, Name: "tap0_kata", Kind: "macvtap", Link: 3, LinkNetnsID: -1},
			{Index: 28394, Name: "tap1_kata", Kind: "macvtap", Link: 2, LinkNetnsID: 0}},
		iface: "net1", want: "tap1_kata",
	}, {
		name: "two macvlan interfaces on one lower device",
		links: []linkInfo{lo,
			{Index: 4, Name: "net1", Kind: "macvlan", Link: 2, LinkNetnsID: 0},
			{Index: 5, Name: "net2", Kind: "macvlan", Link: 2, LinkNetnsID: 0},
			{Index: 20, Name: "tap1_kata", Kind: "macvtap", Link: 2, LinkNetnsID: 0},
			{Index: 21, Name: "tap2_kata", Kind: "macvtap", Link: 2, LinkNetnsID: 0}},
		iface: "net2", want: "tap2_kata",
	}, {
		name: "macvlan without a VM",
		links: []linkInfo{lo,
			{Index: 4, Name: "net1", Kind: "macvlan", Link: 2, LinkNetnsID: 0}},
		iface: "net1", want: "net1",
	}, {
		name: "ambiguous macvtap devices",
		links: []linkInfo{lo,
			{Index: 4, Name: "net1", Kind: "macvlan", Link: 2, LinkNetnsID: 0},
			{Index: 20, Name: "tap1_kata", Kind: "macvtap", Link: 2, LinkNetnsID: 0},
			{Index: 21, Name: "tap2_kata", Kind: "macvtap", Link: 2, LinkNetnsID: 0}},
		iface: "net1", err: true,
	}, {
		name:  "missing interface",
		links: []linkInfo{lo},
		iface: "net1", err: true,
	}, {
		// Virtink's bridge mode (and KubeVirt's bridge binding): the pod
		// interface is renamed, enslaved to a bridge that also holds the
		// VM's tap device, and a dummy keeps its name and address.
		name: "bridged VM: renamed interface",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0-nic", Kind: "veth", Link: 9, LinkNetnsID: 0},
			{Index: 4, Name: "eth0", Kind: "dummy", LinkNetnsID: -1},
			{Index: 5, Name: "br-eth0", Kind: "bridge", LinkNetnsID: -1},
			{Index: 6, Name: "tap-eth0", Kind: "tun", LinkNetnsID: -1}},
		iface: "eth0", want: "eth0-nic",
	}, {
		name: "bridged VM: secondary interface",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0", Kind: "veth", Link: 9, LinkNetnsID: 0},
			{Index: 4, Name: "net1-nic", Kind: "macvlan", Link: 2, LinkNetnsID: 0},
			{Index: 5, Name: "net1", Kind: "dummy", LinkNetnsID: -1},
			{Index: 6, Name: "tap-net1", Kind: "tun", LinkNetnsID: -1}},
		iface: "net1", want: "net1-nic",
	}, {
		// Virtink only renames an interface that has an IPv4 address.
		name: "bridged VM: interface kept its name",
		links: []linkInfo{lo,
			{Index: 4, Name: "net1", Kind: "macvlan", Link: 2, LinkNetnsID: 0},
			{Index: 5, Name: "br-net1", Kind: "bridge", LinkNetnsID: -1},
			{Index: 6, Name: "tap-net1", Kind: "tun", LinkNetnsID: -1}},
		iface: "net1", want: "net1",
	}, {
		name: "dummy without a device to fall back to",
		links: []linkInfo{lo,
			{Index: 4, Name: "net1", Kind: "dummy", LinkNetnsID: -1}},
		iface: "net1", err: true,
	}, {
		name: "rules disabled",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0-nic", Kind: "veth", Link: 9, LinkNetnsID: 0},
			{Index: 4, Name: "eth0", Kind: "dummy", LinkNetnsID: -1}},
		iface: "eth0", rules: []string{}, err: true,
	}, {
		name: "custom rule for one interface",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0", Kind: "veth", Link: 9, LinkNetnsID: 0},
			{Index: 4, Name: "net1", Kind: "macvlan", Link: 2, LinkNetnsID: 0},
			{Index: 5, Name: "vm-net1", Kind: "veth", Link: 7, LinkNetnsID: -1}},
		iface: "net1", rules: []string{`^net(\d+)$=vm-net${1}`}, want: "vm-net1",
	}, {
		name: "first rule naming an existing device wins",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0", Kind: "veth", Link: 9, LinkNetnsID: 0},
			{Index: 4, Name: "eth0-nic", Kind: "veth", Link: 10, LinkNetnsID: 0}},
		iface: "eth0", rules: []string{`^(.+)$=${1}-vm`, DefaultInterfaceRule}, want: "eth0-nic",
	}, {
		// A macvtap on the renamed device is still resolved.
		name: "rule and macvtap",
		links: []linkInfo{lo,
			{Index: 3, Name: "eth0", Kind: "dummy", LinkNetnsID: -1},
			{Index: 4, Name: "eth0-nic", Kind: "veth", Link: 9, LinkNetnsID: 0},
			{Index: 5, Name: "tap0_kata", Kind: "macvtap", Link: 4, LinkNetnsID: -1}},
		iface: "eth0", want: "tap0_kata",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			specs := tc.rules
			if specs == nil {
				specs = []string{DefaultInterfaceRule}
			}
			rules, err := ParseInterfaceRules(specs)
			if err != nil {
				t.Fatalf("ParseInterfaceRules(%q): %v", specs, err)
			}
			got, err := enforcementLink(tc.links, tc.iface, rules)
			if tc.err {
				if err == nil {
					t.Fatalf("got %s, want an error", got.Name)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != tc.want {
				t.Errorf("got %s, want %s", got.Name, tc.want)
			}
		})
	}
}

func TestParseInterfaceRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		specs []string
		iface string
		want  string // the device the rules name, "" when none applies
		err   bool
	}{
		{name: "default rule", specs: []string{DefaultInterfaceRule}, iface: "eth0", want: "eth0-nic"},
		{name: "default rule on a secondary interface", specs: []string{DefaultInterfaceRule}, iface: "net1", want: "net1-nic"},
		{name: "no rules", specs: nil, iface: "eth0", want: ""},
		{name: "blank specifications are ignored", specs: []string{"", "  "}, iface: "eth0", want: ""},
		{name: "unanchored match", specs: []string{`^net\d+$=vmtap`}, iface: "net1", want: "vmtap"},
		{name: "non-matching rule", specs: []string{`^net\d+$=vmtap`}, iface: "eth0", want: ""},
		{name: "several submatches", specs: []string{`^(eth|net)(\d+)$=tap-${1}${2}`}, iface: "net12", want: "tap-net12"},
		{name: "a rule mapping a name to itself does not apply", specs: []string{`^(.+)$=${1}`}, iface: "eth0", want: ""},
		{name: "regular expression with a comma", specs: []string{`^net\d{1,3}$=vmtap`}, iface: "net12", want: "vmtap"},
		{name: "missing separator", specs: []string{"^eth0$"}, err: true},
		{name: "empty regular expression", specs: []string{"=eth0-nic"}, err: true},
		{name: "invalid regular expression", specs: []string{`^(eth0$=x`}, err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := ParseInterfaceRules(tc.specs)
			if tc.err {
				if err == nil {
					t.Fatalf("ParseInterfaceRules(%q) = %v, want an error", tc.specs, rules)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			for _, rule := range rules {
				if target, ok := rule.target(tc.iface); ok {
					got = target
					break
				}
			}
			if got != tc.want {
				t.Errorf("rules name %q for %s, want %q", got, tc.iface, tc.want)
			}
		})
	}
}
