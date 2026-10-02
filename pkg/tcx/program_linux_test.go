//go:build linux

package tcx

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
)

// Verdicts of a TCX program as returned by BPF_PROG_TEST_RUN.
const (
	verdictNext = 0xffffffff // TCX_NEXT (-1)
	verdictDrop = 2          // TCX_DROP
)

// newTestDatapath creates a datapath pinned below a private bpffs directory,
// or skips the test when BPF programs cannot be loaded.
func newTestDatapath(t *testing.T, interfaceRules ...string) *Datapath {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &fs); err != nil || fs.Type != unix.BPF_FS_MAGIC {
		t.Skip("requires bpffs mounted at /sys/fs/bpf")
	}
	pin := filepath.Join("/sys/fs/bpf", fmt.Sprintf("mnp-test-%d-%s", os.Getpid(), sanitize(t.Name())))
	rules, err := ParseInterfaceRules(interfaceRules)
	if err != nil {
		t.Fatalf("ParseInterfaceRules(%q): %v", interfaceRules, err)
	}
	d, err := NewDatapath(Config{PinPath: pin, FlowTableSize: 1024, InterfaceRules: rules})
	if err != nil {
		t.Fatalf("NewDatapath: %v", err)
	}
	t.Cleanup(func() {
		_ = d.RemoveAll()
		_ = d.Close()
		_ = os.RemoveAll(pin)
	})
	return d
}

func sanitize(s string) string {
	b := []byte(s)
	for i, c := range b {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

// testProgram is a loaded policy object whose programs are run directly.
type testProgram struct {
	t    *testing.T
	coll *ebpf.Collection
}

func loadTestProgram(t *testing.T, d *Datapath, ep EndpointPolicy) *testProgram {
	t.Helper()
	ep.Interface = "eth0"
	coll, err := d.load(endpointKey{podUID: types.UID("test-" + sanitize(t.Name())), ifname: ep.Interface}, &ep)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { coll.Close() })
	return &testProgram{t: t, coll: coll}
}

func (p *testProgram) run(dir Direction, pkt []byte) uint32 {
	p.t.Helper()
	name := policyProgMnpIngress
	if dir == Egress {
		name = policyProgMnpEgress
	}
	ret, err := p.coll.Programs[name].Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		p.t.Fatalf("run %s: %v", name, err)
	}
	return ret
}

func (p *testProgram) expect(dir Direction, pkt []byte, want uint32, what string) {
	p.t.Helper()
	if got := p.run(dir, pkt); got != want {
		p.t.Errorf("%s: %s verdict = %#x, want %#x", what, dir, got, want)
	}
}

// Packet builders. Checksums are left zero: the program does not verify them.

func ether(ethertype uint16, payload []byte) []byte {
	b := make([]byte, 14, 14+len(payload))
	copy(b[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(b[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(b[12:], ethertype)
	return append(b, payload...)
}

type frag struct {
	id     uint32
	offset uint16 // in 8-byte units
	more   bool
}

func ipv4(src, dst string, proto uint8, l4 []byte, f *frag) []byte {
	b := make([]byte, 20, 20+len(l4))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(20+len(l4))) //nolint:gosec // test packets are small
	b[8] = 64
	b[9] = proto
	if f != nil {
		binary.BigEndian.PutUint16(b[4:], uint16(f.id)) //nolint:gosec // test data
		fo := f.offset
		if f.more {
			fo |= 0x2000
		}
		binary.BigEndian.PutUint16(b[6:], fo)
	}
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	return ether(0x0800, append(b, l4...))
}

// ipv6 builds an IPv6 packet; ext lists extension headers (next header values)
// inserted before the transport header, each 8 bytes long.
func ipv6(src, dst string, proto uint8, l4 []byte, ext []uint8, f *frag) []byte {
	var exts []byte
	next := proto
	if f != nil {
		h := make([]byte, 8)
		h[0] = next
		fo := f.offset << 3
		if f.more {
			fo |= 1
		}
		binary.BigEndian.PutUint16(h[2:], fo)
		binary.BigEndian.PutUint32(h[4:], f.id)
		exts = h
		next = 44
	}
	for i := len(ext) - 1; i >= 0; i-- {
		h := make([]byte, 8)
		h[0] = next
		exts = append(h, exts...)
		next = ext[i]
	}
	b := make([]byte, 40, 40+len(exts)+len(l4))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(exts)+len(l4))) //nolint:gosec // test packets are small
	b[6] = next
	b[7] = 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	return ether(0x86dd, append(append(b, exts...), l4...))
}

func tcp(sport, dport uint16, flags uint8) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	b[12] = 5 << 4
	b[13] = flags
	return b
}

func udp(sport, dport uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], 8)
	return b
}

func icmp(typ, code uint8, id uint16, quoted []byte) []byte {
	b := make([]byte, 8)
	b[0], b[1] = typ, code
	binary.BigEndian.PutUint16(b[4:], id)
	return append(b, quoted...)
}

const (
	tcpSYN = 0x02
	tcpACK = 0x10
	tcpFIN = 0x01
)

// allowFrom returns a direction policy with one rule: peer on TCP port.
func allowFrom(peer string, port uint16) DirectionPolicy {
	var rs RuleSet
	rs.Set(0)
	pfx := netip.MustParsePrefix(peer)
	return DirectionPolicy{
		Isolated: true,
		Peers:    []PeerEntry{{Prefix: pfx, Rules: rs}},
		Ports:    []PortEntry{{PortPrefix: PortPrefix{Proto: protoTCP, Port: port, Bits: 16}, Rules: rs}},
		Rules:    []string{"test"},
	}
}

func denyAll() DirectionPolicy { return DirectionPolicy{Isolated: true} }

func TestProgramPeerAndPort(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("10.0.0.2/32", 5555), denyAll()}})

	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(40000, 5555, tcpSYN), nil), verdictNext, "allowed peer and port")
	p.expect(Ingress, ipv4("10.0.0.3", "10.0.0.1", protoTCP, tcp(40000, 5555, tcpSYN), nil), verdictDrop, "other peer")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(40001, 5556, tcpSYN), nil), verdictDrop, "other port")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoUDP, udp(40002, 5555), nil), verdictDrop, "other protocol")
	p.expect(Egress, ipv4("10.0.0.1", "10.0.0.9", protoTCP, tcp(40003, 80, tcpSYN), nil), verdictDrop, "egress deny-all")
}

func TestProgramEstablishedFlow(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("10.0.0.2/32", 5555), denyAll()}})

	// Egress is deny-all, yet the reply of an accepted ingress connection passes.
	p.expect(Egress, ipv4("10.0.0.1", "10.0.0.2", protoTCP, tcp(5555, 41000, tcpSYN|tcpACK), nil), verdictDrop, "reply before the connection exists")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(41000, 5555, tcpSYN), nil), verdictNext, "SYN")
	p.expect(Egress, ipv4("10.0.0.1", "10.0.0.2", protoTCP, tcp(5555, 41000, tcpSYN|tcpACK), nil), verdictNext, "SYN-ACK")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(41000, 5555, tcpACK), nil), verdictNext, "ACK")
	p.expect(Egress, ipv4("10.0.0.1", "10.0.0.2", protoTCP, tcp(5555, 41001, tcpSYN|tcpACK), nil), verdictDrop, "reply to another port")

	// The flow is shared across reloads of the same interface's program.
	p2 := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{denyAll(), denyAll()}})
	p2.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(41000, 5555, tcpACK), nil), verdictNext, "established flow after a policy change")
	p2.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(41002, 5555, tcpSYN), nil), verdictDrop, "new connection after a policy change")
}

func TestProgramUnisolatedDirectionRecordsFlows(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{{}, denyAll()}})

	p.expect(Ingress, ipv4("192.0.2.5", "10.0.0.1", protoUDP, udp(5353, 53), nil), verdictNext, "ingress not isolated")
	p.expect(Egress, ipv4("10.0.0.1", "192.0.2.5", protoUDP, udp(53, 5353), nil), verdictNext, "reply through isolated egress")
	p.expect(Egress, ipv4("10.0.0.1", "192.0.2.5", protoUDP, udp(53, 5354), nil), verdictDrop, "unrelated egress")
}

func TestProgramNonIPAndVLAN(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{denyAll(), {}}})

	arp := ether(0x0806, make([]byte, 28))
	p.expect(Ingress, arp, verdictNext, "ARP")
	vlan := ether(0x8100, append([]byte{0, 1, 0x08, 0x00}, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(1, 2, tcpSYN), nil)[14:]...))
	p.expect(Ingress, vlan, verdictDrop, "VLAN-tagged frame, isolated")
	p.expect(Egress, vlan, verdictNext, "VLAN-tagged frame, not isolated")
	p.expect(Ingress, ether(0x0800, []byte{0x45, 0}), verdictDrop, "truncated IPv4 header")
}

func TestProgramICMP(t *testing.T) {
	d := newTestDatapath(t)
	deny := EndpointPolicy{Directions: [2]DirectionPolicy{denyAll(), denyAll()}}
	p := loadTestProgram(t, d, deny)

	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", 1, icmp(8, 0, 7, nil), nil), verdictDrop, "echo request, ICMP not accepted")
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", 58, icmp(135, 0, 0, nil), nil, nil), verdictNext, "neighbor solicitation")
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", 58, icmp(128, 0, 7, nil), nil, nil), verdictDrop, "ICMPv6 echo, not accepted")

	deny.AcceptICMP, deny.AcceptICMPv6 = true, true
	p = loadTestProgram(t, d, deny)
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", 1, icmp(8, 0, 8, nil), nil), verdictNext, "echo request, --accept-icmp")
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", 58, icmp(128, 0, 8, nil), nil, nil), verdictNext, "ICMPv6 echo, --accept-icmpv6")
}

func TestProgramEchoReplyFollowsRequest(t *testing.T) {
	d := newTestDatapath(t)
	var rs RuleSet
	rs.Set(0)
	allowAny := DirectionPolicy{Isolated: true, WildPeer: rs, WildPort: rs, Rules: []string{"any"}}
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{denyAll(), allowAny}})

	p.expect(Egress, ipv4("10.0.0.1", "10.0.0.2", 1, icmp(8, 0, 99, nil), nil), verdictNext, "echo request out")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", 1, icmp(0, 0, 99, nil), nil), verdictNext, "echo reply in")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", 1, icmp(0, 0, 100, nil), nil), verdictDrop, "echo reply with another id")
}

func TestProgramIPv6ExtensionHeaders(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("fd00::2/128", 443), denyAll()}})

	p.expect(Ingress, ipv6("fd00::2", "fd00::1", protoTCP, tcp(40000, 443, tcpSYN), nil, nil), verdictNext, "plain")
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", protoTCP, tcp(40001, 443, tcpSYN), []uint8{0, 60}, nil), verdictNext, "hop-by-hop and destination options")
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", protoTCP, tcp(40002, 444, tcpSYN), []uint8{0}, nil), verdictDrop, "hop-by-hop, other port")
	p.expect(Ingress, ipv6("fd00::3", "fd00::1", protoTCP, tcp(40003, 443, tcpSYN), []uint8{60}, nil), verdictDrop, "destination options, other peer")
	p.expect(Egress, ipv6("fd00::1", "fd00::9", protoTCP, tcp(443, 40005, tcpSYN), []uint8{0}, nil), verdictDrop, "egress deny-all with hop-by-hop")
	long := []uint8{0, 60, 60, 60, 60, 60, 60}
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", protoTCP, tcp(40004, 443, tcpSYN), long, nil), verdictDrop, "extension header chain too long")
}

func TestProgramFragments(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("10.0.0.2/32", 5555), denyAll()}})

	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(40000, 5555, tcpSYN), &frag{id: 11, more: true}), verdictNext, "first fragment")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, make([]byte, 16), &frag{id: 11, offset: 3}), verdictNext, "later fragment of accepted packet")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, make([]byte, 16), &frag{id: 12, offset: 3}), verdictDrop, "later fragment without first")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(40001, 6000, tcpSYN), &frag{id: 13, more: true}), verdictDrop, "first fragment, denied")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, make([]byte, 16), &frag{id: 13, offset: 3}), verdictDrop, "later fragment of denied packet")

	p.expect(Ingress, ipv6("fd00::2", "fd00::1", protoTCP, tcp(40002, 5555, tcpSYN), nil, &frag{id: 21, more: true}), verdictDrop, "IPv6 first fragment, peer not allowed")
	p6 := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("fd00::2/128", 5555), denyAll()}})
	p6.expect(Ingress, ipv6("fd00::2", "fd00::1", protoTCP, tcp(40003, 5555, tcpSYN), nil, &frag{id: 22, more: true}), verdictNext, "IPv6 first fragment")
	p6.expect(Ingress, ipv6("fd00::2", "fd00::1", protoTCP, make([]byte, 16), nil, &frag{id: 22, offset: 4}), verdictNext, "IPv6 later fragment")
	p6.expect(Ingress, ipv6("fd00::2", "fd00::1", protoTCP, make([]byte, 16), nil, &frag{id: 23, offset: 4}), verdictDrop, "IPv6 later fragment without first")
}

func TestProgramICMPErrorRelated(t *testing.T) {
	d := newTestDatapath(t)
	var rs RuleSet
	rs.Set(0)
	allowAny := DirectionPolicy{Isolated: true, WildPeer: rs, WildPort: rs, Rules: []string{"any"}}
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{denyAll(), allowAny}})

	sent := ipv4("10.0.0.1", "198.51.100.1", protoUDP, udp(33000, 9999), nil)[14:]
	unreachable := ipv4("198.51.100.1", "10.0.0.1", 1, icmp(3, 3, 0, sent), nil)
	p.expect(Ingress, unreachable, verdictDrop, "ICMP error before the flow exists")
	p.expect(Egress, ipv4("10.0.0.1", "198.51.100.1", protoUDP, udp(33000, 9999), nil), verdictNext, "UDP out")
	p.expect(Ingress, unreachable, verdictNext, "ICMP error quoting the flow")

	other := ipv4("10.0.0.1", "198.51.100.1", protoUDP, udp(33001, 9999), nil)[14:]
	p.expect(Ingress, ipv4("198.51.100.1", "10.0.0.1", 1, icmp(3, 3, 0, other), nil), verdictDrop, "ICMP error quoting another flow")
}

func TestProgramAllowCommonPrefix(t *testing.T) {
	d := newTestDatapath(t)
	in := denyAll()
	in.Peers = []PeerEntry{{Prefix: netip.MustParsePrefix("fe80::/10"), AllowCommon: true}}
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{in, denyAll()}})

	p.expect(Ingress, ipv6("fe80::2", "fd00::1", protoUDP, udp(546, 547), nil, nil), verdictNext, "allowed source prefix")
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", protoUDP, udp(546, 547), nil, nil), verdictDrop, "other source")
}

func TestProgramExceptShadowsCIDR(t *testing.T) {
	d := newTestDatapath(t)
	var rs RuleSet
	rs.Set(0)
	in := DirectionPolicy{
		Isolated: true,
		WildPort: rs,
		Peers:    buildPeerEntries([]prefixGroup{{cidr: netip.MustParsePrefix("10.0.0.0/8"), excepts: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}, bit: 0}}),
		Rules:    []string{"ipblock"},
	}
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{in, denyAll()}})

	p.expect(Ingress, ipv4("10.2.0.1", "10.0.0.1", protoTCP, tcp(1, 80, tcpSYN), nil), verdictNext, "inside cidr")
	p.expect(Ingress, ipv4("10.1.0.1", "10.0.0.1", protoTCP, tcp(2, 80, tcpSYN), nil), verdictDrop, "inside except")
	p.expect(Ingress, ipv4("11.0.0.1", "10.0.0.1", protoTCP, tcp(3, 80, tcpSYN), nil), verdictDrop, "outside cidr")
}

func TestProgramTCPCloseShortensFlow(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("10.0.0.2/32", 5555), denyAll()}})

	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(42000, 5555, tcpSYN), nil), verdictNext, "SYN")
	p.expect(Egress, ipv4("10.0.0.1", "10.0.0.2", protoTCP, tcp(5555, 42000, tcpSYN|tcpACK), nil), verdictNext, "SYN-ACK")
	p.expect(Egress, ipv4("10.0.0.1", "10.0.0.2", protoTCP, tcp(5555, 42000, tcpFIN|tcpACK), nil), verdictNext, "FIN")

	var v policyFlowVal
	k := policyFlowKey{EpId: EndpointID(types.UID("test-"+sanitize(t.Name())), "eth0"), Sport: htons(42000), Dport: htons(5555), Proto: protoTCP, Family: 4}
	s, dst := netip.MustParseAddr("10.0.0.2").As4(), netip.MustParseAddr("10.0.0.1").As4()
	copy(k.Saddr[:], s[:])
	copy(k.Daddr[:], dst[:])
	if err := d.flows.Lookup(k, &v); err != nil {
		t.Fatalf("flow lookup: %v", err)
	}
	if v.Flags != 3 { // FLOW_F_REPLIED | FLOW_F_CLOSING
		t.Errorf("flow flags = %#x, want replied|closing", v.Flags)
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func TestProgramICMPErrorMustReturnToSender(t *testing.T) {
	d := newTestDatapath(t)
	var rs RuleSet
	rs.Set(0)
	// Egress allows only 198.51.100.1:53/udp.
	eg := DirectionPolicy{
		Isolated: true,
		Peers:    []PeerEntry{{Prefix: netip.MustParsePrefix("198.51.100.1/32"), Rules: rs}},
		Ports:    []PortEntry{{PortPrefix: PortPrefix{Proto: protoUDP, Port: 53, Bits: 16}, Rules: rs}},
		Rules:    []string{"dns"},
	}
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{denyAll(), eg}})

	p.expect(Egress, ipv4("10.0.0.1", "198.51.100.1", protoUDP, udp(33000, 53), nil), verdictNext, "DNS query")
	p.expect(Ingress, ipv4("198.51.100.1", "10.0.0.1", protoUDP, udp(53, 33000), nil), verdictNext, "DNS answer")

	// The guest answers the server with a port unreachable: it goes back to
	// the sender of the quoted packet.
	answer := ipv4("198.51.100.1", "10.0.0.1", protoUDP, udp(53, 33000), nil)[14:]
	p.expect(Egress, ipv4("10.0.0.1", "198.51.100.1", 1, icmp(3, 3, 0, answer), nil), verdictNext, "ICMP error to the quoted packet's sender")
	// The same quote carried to a denied peer is not related to the flow.
	p.expect(Egress, ipv4("10.0.0.1", "203.0.113.9", 1, icmp(3, 3, 0, answer), nil), verdictDrop, "ICMP error to another destination")
	query := ipv4("10.0.0.1", "198.51.100.1", protoUDP, udp(33000, 53), nil)[14:]
	p.expect(Egress, ipv4("10.0.0.1", "203.0.113.9", 1, icmp(3, 3, 0, query), nil), verdictDrop, "ICMP error quoting an outgoing packet")
}

func TestProgramEchoRequestDoesNotFollowOwnRequest(t *testing.T) {
	d := newTestDatapath(t)
	var rs RuleSet
	rs.Set(0)
	allowAny := DirectionPolicy{Isolated: true, WildPeer: rs, WildPort: rs, Rules: []string{"any"}}
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{denyAll(), allowAny}})

	p.expect(Egress, ipv4("10.0.0.1", "10.0.0.2", 1, icmp(8, 0, 42, nil), nil), verdictNext, "echo request out")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", 1, icmp(8, 0, 42, nil), nil), verdictDrop, "echo request in with the same id")
	p.expect(Ingress, ipv4("10.0.0.2", "10.0.0.1", 1, icmp(0, 0, 42, nil), nil), verdictNext, "echo reply in")
}

func TestProgramIPv6FragmentBeforeExtensionHeader(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("fd00::2/128", 5555), denyAll()}})

	// Fragment header followed by destination options, then TCP.
	fragHdr := func(offset uint16, more bool, next uint8) []byte {
		h := make([]byte, 8)
		h[0] = next
		fo := offset << 3
		if more {
			fo |= 1
		}
		binary.BigEndian.PutUint16(h[2:], fo)
		binary.BigEndian.PutUint32(h[4:], 31)
		return h
	}
	dstopts := make([]byte, 8)
	dstopts[0] = protoTCP
	first := append(append(fragHdr(0, true, 60), dstopts...), tcp(40000, 5555, tcpSYN)...)
	later := append(fragHdr(4, false, 60), make([]byte, 16)...)
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", 44, first, nil, nil), verdictNext, "first fragment")
	p.expect(Ingress, ipv6("fd00::2", "fd00::1", 44, later, nil, nil), verdictNext, "later fragment")
}

func TestProgramPortsPastIPPacketAreIgnored(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("10.0.0.2/32", 5555), denyAll()}})

	// A TCP header in the Ethernet padding, after an IP packet without payload.
	pkt := ipv4("10.0.0.2", "10.0.0.1", protoTCP, tcp(40000, 5555, tcpSYN), nil)
	binary.BigEndian.PutUint16(pkt[14+2:], 20)
	p.expect(Ingress, pkt, verdictDrop, "ports beyond the IPv4 total length")

	pkt6 := ipv6("fd00::2", "fd00::1", protoTCP, tcp(40000, 5555, tcpSYN), nil, nil)
	binary.BigEndian.PutUint16(pkt6[14+4:], 4)
	p6 := loadTestProgram(t, d, EndpointPolicy{Directions: [2]DirectionPolicy{allowFrom("fd00::2/128", 5555), denyAll()}})
	p6.expect(Ingress, pkt6, verdictDrop, "ports beyond the IPv6 payload length")
}

func TestProgramUnpolicedInterfaceRecordsNoFlows(t *testing.T) {
	d := newTestDatapath(t)
	p := loadTestProgram(t, d, EndpointPolicy{})

	p.expect(Ingress, ipv4("192.0.2.5", "10.0.0.1", protoUDP, udp(5353, 53), nil), verdictNext, "not isolated")
	var k policyFlowKey
	var v policyFlowVal
	if err := d.flows.NextKey(nil, &k); err == nil {
		_ = d.flows.Lookup(k, &v)
		t.Errorf("flow table has an entry %+v; an interface no policy isolates must not record flows", k)
	}
}
