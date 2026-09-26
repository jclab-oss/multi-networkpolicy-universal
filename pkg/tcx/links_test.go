package tcx

import "testing"

func TestEnforcementLink(t *testing.T) {
	lo := linkInfo{Index: 1, Name: "lo", LinkNetnsID: -1}
	for _, tc := range []struct {
		name  string
		links []linkInfo
		iface string
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
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := enforcementLink(tc.links, tc.iface)
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
