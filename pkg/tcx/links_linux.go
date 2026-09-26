//go:build linux

package tcx

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// listLinks dumps the network interfaces of the calling thread's network
// namespace.
func listLinks() ([]linkInfo, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("dump links: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, fmt.Errorf("parse link dump: %w", err)
	}
	var links []linkInfo
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != unix.RTM_NEWLINK || len(m.Data) < unix.SizeofIfInfomsg {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			return nil, fmt.Errorf("parse link attributes: %w", err)
		}
		l := linkInfo{
			Index:       int(int32(binary.NativeEndian.Uint32(m.Data[4:8]))), //nolint:gosec // ifi_index is a signed int
			LinkNetnsID: -1,
		}
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.IFLA_IFNAME:
				l.Name = cString(a.Value)
			case unix.IFLA_LINK:
				if len(a.Value) >= 4 {
					l.Link = int(binary.NativeEndian.Uint32(a.Value))
				}
			case unix.IFLA_LINK_NETNSID:
				if len(a.Value) >= 4 {
					l.LinkNetnsID = int(int32(binary.NativeEndian.Uint32(a.Value))) //nolint:gosec // netnsid is signed
				}
			case unix.IFLA_LINKINFO:
				l.Kind = linkKind(a.Value)
			}
		}
		links = append(links, l)
	}
	return links, nil
}

// linkKind returns IFLA_INFO_KIND from a nested IFLA_LINKINFO attribute.
func linkKind(b []byte) string {
	for len(b) >= unix.SizeofRtAttr {
		alen := int(binary.NativeEndian.Uint16(b[0:2]))
		atype := binary.NativeEndian.Uint16(b[2:4])
		if alen < unix.SizeofRtAttr || alen > len(b) {
			return ""
		}
		if atype == unix.IFLA_INFO_KIND {
			return cString(b[unix.SizeofRtAttr:alen])
		}
		// attributes are 4-byte aligned
		next := (alen + 3) &^ 3
		if next > len(b) {
			return ""
		}
		b = b[next:]
	}
	return ""
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
