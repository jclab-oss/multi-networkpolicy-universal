//go:build linux

package tcx

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

// Flags of ep_cfg in bpf/policy.c.
const (
	cfgAcceptICMP   = 1 << 0
	cfgAcceptICMPv6 = 1 << 1
	peerAllowCommon = 1 << 0
)

// Timeouts of the flow table, taken from the nf_conntrack defaults so flows
// live as long as they would with the nftables backend.
const (
	tcpEstablishedTimeout   = 5 * 24 * time.Hour // nf_conntrack_tcp_timeout_established
	tcpTransitoryTimeout    = 2 * time.Minute    // nf_conntrack_tcp_timeout_syn_sent, _fin_wait, _time_wait
	otherEstablishedTimeout = 2 * time.Minute    // nf_conntrack_udp_timeout_stream
	otherTransitoryTimeout  = 30 * time.Second   // nf_conntrack_udp_timeout, nf_conntrack_icmp_timeout
	fragTimeout             = 30 * time.Second   // net.ipv4.ipfrag_time
)

const (
	endpointsDir = "endpoints"
	ingressPin   = "ingress"
	egressPin    = "egress"
)

type endpointKey struct {
	podUID types.UID
	ifname string
}

// Datapath loads, attaches and replaces the policy program of pod interfaces.
type Datapath struct {
	cfg   Config
	spec  *ebpf.CollectionSpec
	flows *ebpf.Map
	frags *ebpf.Map

	mu sync.Mutex
	// applied caches the digest of the policy last loaded per interface, so
	// a reconcile that changes nothing does not reload the program.
	applied map[endpointKey]string
}

// NewDatapath opens (or creates) the pinned flow tables. Links pinned by an
// earlier run of the daemon keep enforcing their policy until Apply replaces
// them.
func NewDatapath(cfg Config) (*Datapath, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	if err := os.MkdirAll(cfg.PinPath, 0o700); err != nil {
		return nil, fmt.Errorf("create pin path %s: %w", cfg.PinPath, err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(cfg.PinPath, &fs); err != nil {
		return nil, fmt.Errorf("statfs %s: %w", cfg.PinPath, err)
	}
	if fs.Type != unix.BPF_FS_MAGIC {
		return nil, fmt.Errorf("pin path %s is not on a bpf filesystem", cfg.PinPath)
	}

	spec, err := loadPolicy()
	if err != nil {
		return nil, err
	}
	d := &Datapath{cfg: cfg, spec: spec, applied: map[endpointKey]string{}}

	flowSpec := spec.Maps[policyMapFlows].Copy()
	if cfg.FlowTableSize > 0 {
		flowSpec.MaxEntries = cfg.FlowTableSize
	}
	if d.flows, err = d.openPinnedMap(flowSpec); err != nil {
		return nil, err
	}
	// Every object loaded later receives this map as a replacement, which
	// must match the definition in the object.
	spec.Maps[policyMapFlows].MaxEntries = flowSpec.MaxEntries
	if d.frags, err = d.openPinnedMap(spec.Maps[policyMapFrags].Copy()); err != nil {
		_ = d.flows.Close()
		return nil, err
	}
	return d, nil
}

// openPinnedMap reuses the map pinned by an earlier run, so tracked flows
// survive a restart of the daemon, and recreates it when its definition
// changed (for example a different --tcx-flow-table-size).
func (d *Datapath) openPinnedMap(spec *ebpf.MapSpec) (*ebpf.Map, error) {
	spec.Pinning = ebpf.PinByName
	opts := ebpf.MapOptions{PinPath: d.cfg.PinPath}
	m, err := ebpf.NewMapWithOptions(spec, opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		klog.Infof("tcx: recreating pinned map %s: definition changed", spec.Name)
		if rerr := os.Remove(filepath.Join(d.cfg.PinPath, spec.Name)); rerr != nil {
			return nil, fmt.Errorf("remove incompatible pinned map %s: %w", spec.Name, rerr)
		}
		m, err = ebpf.NewMapWithOptions(spec, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("open pinned map %s: %w", spec.Name, err)
	}
	return m, nil
}

// Close releases the daemon's handles. Pinned links stay attached.
func (d *Datapath) Close() error {
	return errors.Join(d.flows.Close(), d.frags.Close())
}

// EndpointID identifies a pod interface in the shared flow tables.
func EndpointID(podUID types.UID, ifname string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(string(podUID) + "/" + ifname))
	return h.Sum64()
}

func (d *Datapath) endpointDir(key endpointKey) string {
	return filepath.Join(d.cfg.PinPath, endpointsDir, string(key.podUID), key.ifname)
}

// Apply enforces the compiled policies of a pod's interfaces. netnsPath is the
// pod network namespace the interfaces live in.
//
// The new program and its tables are fully populated before they replace the
// running program through bpf_link_update, so a packet is evaluated either
// entirely against the old or entirely against the new policy.
func (d *Datapath) Apply(netnsPath string, podUID types.UID, endpoints []EndpointPolicy) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	netns, err := ns.GetNS(netnsPath)
	if err != nil {
		return fmt.Errorf("open netns %s: %w", netnsPath, err)
	}
	defer func() { _ = netns.Close() }()

	var errs []error
	for i := range endpoints {
		if err := d.applyEndpoint(netns, podUID, &endpoints[i]); err != nil {
			errs = append(errs, fmt.Errorf("interface %s: %w", endpoints[i].Interface, err))
		}
	}
	return errors.Join(errs...)
}

var attachTypes = [2]ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress}

func pinName(dir Direction) string {
	if dir == Ingress {
		return ingressPin
	}
	return egressPin
}

func (d *Datapath) applyEndpoint(netns ns.NetNS, podUID types.UID, ep *EndpointPolicy) error {
	key := endpointKey{podUID: podUID, ifname: ep.Interface}
	dir := d.endpointDir(key)
	digest := ep.Digest()

	var links [2]link.Link
	defer func() {
		for _, l := range links {
			if l != nil {
				_ = l.Close()
			}
		}
	}()
	var ifindex int
	if err := netns.Do(func(ns.NetNS) error {
		all, err := listLinks()
		if err != nil {
			return err
		}
		target, err := enforcementLink(all, ep.Interface)
		if err != nil {
			return err
		}
		ifc, err := net.InterfaceByIndex(target.Index)
		if err != nil {
			return err
		}
		// The program parses Ethernet frames; on another link type it
		// would take every packet for non-IP traffic and accept it.
		if len(ifc.HardwareAddr) != 6 {
			return fmt.Errorf("%s is not an Ethernet interface", ifc.Name)
		}
		if target.Name != ep.Interface {
			klog.V(4).Infof("tcx: pod %s interface %s is policed on %s", podUID, ep.Interface, target.Name)
		}
		ifindex = ifc.Index
		for i, at := range attachTypes {
			links[i] = attachedPinnedLink(filepath.Join(dir, pinName(Direction(i))), ifindex, at)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("inspect interface: %w", err)
	}
	if links[0] != nil && links[1] != nil && d.applied[key] == digest {
		return nil
	}

	coll, err := d.load(key, ep)
	if err != nil {
		return err
	}
	defer coll.Close()
	progs := [2]*ebpf.Program{coll.Programs[policyProgMnpIngress], coll.Programs[policyProgMnpEgress]}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create pin directory: %w", err)
	}
	delete(d.applied, key)
	if err := netns.Do(func(ns.NetNS) error {
		for i, at := range attachTypes {
			pin := filepath.Join(dir, pinName(Direction(i)))
			if links[i] != nil {
				if err := links[i].Update(progs[i]); err != nil {
					return fmt.Errorf("update %s link: %w", pinName(Direction(i)), err)
				}
				continue
			}
			// A leftover pin belongs to an interface that no longer exists
			// (the pod sandbox was recreated); its link is already defunct.
			if err := os.Remove(pin); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove stale %s pin: %w", pinName(Direction(i)), err)
			}
			l, err := link.AttachTCX(link.TCXOptions{
				Interface: ifindex,
				Program:   progs[i],
				Attach:    at,
				// Run before any other TCX program so nothing can redirect
				// a packet around the policy.
				Anchor: link.Head(),
			})
			if err != nil {
				return fmt.Errorf("attach %s: %w (TCX requires Linux 6.6 or later)", pinName(Direction(i)), err)
			}
			links[i] = l
			if err := l.Pin(pin); err != nil {
				return fmt.Errorf("pin %s link: %w", pinName(Direction(i)), err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	d.applied[key] = digest
	klog.V(2).Infof("tcx: applied policy %s to pod %s interface %s", digest[:12], podUID, ep.Interface)
	return nil
}

// attachedPinnedLink returns the link pinned at path when it is still attached
// to ifindex in the current network namespace, and nil otherwise.
func attachedPinnedLink(path string, ifindex int, at ebpf.AttachType) link.Link {
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			klog.Warningf("tcx: cannot load pinned link %s: %v", path, err)
		}
		return nil
	}
	info, err := l.Info()
	if err != nil {
		_ = l.Close()
		return nil
	}
	// Interface indexes are per network namespace; only the query, which
	// runs in the pod's namespace, proves the link is attached there.
	res, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: at})
	if err != nil {
		_ = l.Close()
		return nil
	}
	for _, p := range res.Programs {
		if id, ok := p.LinkID(); ok && id == info.ID {
			return l
		}
	}
	_ = l.Close()
	return nil
}

// load creates the program and tables for one interface.
func (d *Datapath) load(key endpointKey, ep *EndpointPolicy) (*ebpf.Collection, error) {
	spec := d.spec.Copy()

	var peer4, peer6 [2][]PeerEntry
	for dir := range ep.Directions {
		for _, e := range ep.Directions[dir].Peers {
			if e.Prefix.Addr().Is4() {
				peer4[dir] = append(peer4[dir], e)
			} else {
				peer6[dir] = append(peer6[dir], e)
			}
		}
	}
	sizes := map[string]int{
		policyMapPeer4Ingress: len(peer4[Ingress]),
		policyMapPeer4Egress:  len(peer4[Egress]),
		policyMapPeer6Ingress: len(peer6[Ingress]),
		policyMapPeer6Egress:  len(peer6[Egress]),
		policyMapPortIngress:  len(ep.Directions[Ingress].Ports),
		policyMapPortEgress:   len(ep.Directions[Egress].Ports),
	}
	for name, n := range sizes {
		spec.Maps[name].MaxEntries = uint32(max(n, 1)) //nolint:gosec // bounded by the policy size
	}

	cfg := policyEpCfg{
		EpId:               EndpointID(key.podUID, key.ifname),
		TcpEstablishedNs:   uint64(tcpEstablishedTimeout),
		TcpTransitoryNs:    uint64(tcpTransitoryTimeout),
		OtherEstablishedNs: uint64(otherEstablishedTimeout),
		OtherTransitoryNs:  uint64(otherTransitoryTimeout),
		FragNs:             uint64(fragTimeout),
	}
	if ep.AcceptICMP {
		cfg.Flags |= cfgAcceptICMP
	}
	if ep.AcceptICMPv6 {
		cfg.Flags |= cfgAcceptICMPv6
	}
	for dir := range ep.Directions {
		dp := &ep.Directions[dir]
		if dp.Isolated {
			cfg.Dir[dir].Isolated = 1
		}
		cfg.Dir[dir].WildPeer.W = dp.WildPeer
		cfg.Dir[dir].WildPort.W = dp.WildPort
	}
	if err := spec.Variables[policyVarCfg].Set(cfg); err != nil {
		return nil, fmt.Errorf("set config: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			policyMapFlows: d.flows,
			policyMapFrags: d.frags,
		},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return nil, fmt.Errorf("load policy program: %+v", verr)
		}
		return nil, fmt.Errorf("load policy program: %w", err)
	}

	fill := func() error {
		peerMaps := [2][2]string{
			{policyMapPeer4Ingress, policyMapPeer6Ingress},
			{policyMapPeer4Egress, policyMapPeer6Egress},
		}
		portMaps := [2]string{policyMapPortIngress, policyMapPortEgress}
		for dir := range ep.Directions {
			if err := putPeers(coll.Maps[peerMaps[dir][0]], coll.Maps[peerMaps[dir][1]], peer4[dir], peer6[dir]); err != nil {
				return err
			}
			if err := putPorts(coll.Maps[portMaps[dir]], ep.Directions[dir].Ports); err != nil {
				return err
			}
		}
		return nil
	}
	if err := fill(); err != nil {
		coll.Close()
		return nil, fmt.Errorf("populate policy tables: %w", err)
	}
	return coll, nil
}

func peerValue(e PeerEntry) policyPeerVal {
	v := policyPeerVal{Rules: policyRuleBits{W: e.Rules}}
	if e.AllowCommon {
		v.Flags = peerAllowCommon
	}
	return v
}

func putPeers(m4, m6 *ebpf.Map, v4, v6 []PeerEntry) error {
	for _, e := range v4 {
		k := policyLpmV4Key{Prefixlen: uint32(e.Prefix.Bits()), Addr: e.Prefix.Addr().As4()} //nolint:gosec // 0..32
		if err := m4.Put(k, peerValue(e)); err != nil {
			return fmt.Errorf("peer %s: %w", e.Prefix, err)
		}
	}
	for _, e := range v6 {
		k := policyLpmV6Key{Prefixlen: uint32(e.Prefix.Bits()), Addr: e.Prefix.Addr().As16()} //nolint:gosec // 0..128
		if err := m6.Put(k, peerValue(e)); err != nil {
			return fmt.Errorf("peer %s: %w", e.Prefix, err)
		}
	}
	return nil
}

func putPorts(m *ebpf.Map, entries []PortEntry) error {
	for _, e := range entries {
		k := policyLpmPortKey{
			Prefixlen: 8 + uint32(e.Bits),
			Proto:     e.Proto,
			Port:      [2]uint8{uint8(e.Port >> 8), uint8(e.Port)}, //nolint:gosec // byte split
		}
		if err := m.Put(k, policyRuleBits{W: e.Rules}); err != nil {
			return fmt.Errorf("port %d/%d proto %d: %w", e.Port, e.Bits, e.Proto, err)
		}
	}
	return nil
}

// Endpoints lists the interfaces with pinned links.
func (d *Datapath) Endpoints() ([]Endpoint, error) {
	return pinnedEndpoints(d.cfg.PinPath)
}

func pinnedEndpoints(pinPath string) ([]Endpoint, error) {
	root := filepath.Join(pinPath, endpointsDir)
	pods, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var eps []Endpoint
	for _, p := range pods {
		ifaces, err := os.ReadDir(filepath.Join(root, p.Name()))
		if err != nil {
			return nil, err
		}
		for _, i := range ifaces {
			eps = append(eps, Endpoint{PodUID: types.UID(p.Name()), Interface: i.Name()})
		}
		if len(ifaces) == 0 {
			_ = os.Remove(filepath.Join(root, p.Name()))
		}
	}
	return eps, nil
}

// Prune detaches the interfaces keep rejects: interfaces of deleted pods,
// removed interfaces and pods no longer enforced by this datapath.
func (d *Datapath) Prune(keep func(Endpoint) bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	eps, err := d.Endpoints()
	if err != nil {
		return fmt.Errorf("list pinned endpoints: %w", err)
	}
	var errs []error
	for _, ep := range eps {
		if keep(ep) {
			continue
		}
		klog.V(2).Infof("tcx: removing policy of pod %s interface %s", ep.PodUID, ep.Interface)
		delete(d.applied, endpointKey{podUID: ep.PodUID, ifname: ep.Interface})
		if err := removeEndpoint(d.cfg.PinPath, ep); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RemoveAll detaches every policed interface. The flow tables stay pinned.
func (d *Datapath) RemoveAll() error {
	return d.Prune(func(Endpoint) bool { return false })
}

// RemovePinned detaches every interface pinned below pinPath by an earlier run
// of the daemon. It is used when the TCX datapath is disabled, so programs of
// a run that had it enabled do not keep enforcing a stale policy.
func RemovePinned(pinPath string) error {
	eps, err := pinnedEndpoints(pinPath)
	if err != nil {
		return fmt.Errorf("list pinned endpoints: %w", err)
	}
	var errs []error
	for _, ep := range eps {
		if err := removeEndpoint(pinPath, ep); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeEndpoint(pinPath string, ep Endpoint) error {
	dir := filepath.Join(pinPath, endpointsDir, string(ep.PodUID), ep.Interface)
	var errs []error
	for _, name := range []string{ingressPin, egressPin} {
		pin := filepath.Join(dir, name)
		if l, err := link.LoadPinnedLink(pin, nil); err == nil {
			// Detach right away instead of waiting for the last reference
			// to the link to go away.
			if err := l.Detach(); err != nil && !errors.Is(err, os.ErrNotExist) {
				klog.V(4).Infof("tcx: detach %s: %v", pin, err)
			}
			_ = l.Close()
		}
		if err := os.Remove(pin); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("unpin %s: %w", pin, err))
		}
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove %s: %w", dir, err))
	}
	_ = os.Remove(filepath.Dir(dir)) // succeeds once the pod's last interface is gone
	return errors.Join(errs...)
}
