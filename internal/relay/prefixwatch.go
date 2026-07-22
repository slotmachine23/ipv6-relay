package relay

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// prefixDeprecationEnabled/prefixMismatchThreshold/prefixDeprecationInterval
// are the global tunables the user gets for this feature (config.json's
// global.notify_prefix_deprecation / global.prefix_mismatch_packet_threshold
// / global.prefix_deprecation_interval_seconds - see config.go's
// loadConfigJSON). Deliberately package vars with sane defaults rather than
// requiring config: this is a mitigation for upstream routers that
// renumber a delegated prefix without ever sending a proper RFC 4861
// zero-lifetime withdrawal for the old one, left on by default.
//
// *Detection* is driven entirely by real-time snooping of the actual
// Router Advertisements received on each master (WAN) interface - not by a
// timer or by polling the kernel's address list: every RA that carries a
// ULA/GUA prefix different from the interface's currently-known prefix
// counts as one "mismatch" packet; once prefixMismatchThreshold consecutive
// mismatches for the *same* candidate prefix are seen, that candidate is
// promoted to "current" and the previous one is treated as dead. Once dead,
// *notifying* LAN neighbors still using it IS periodic/timer-based (see
// startPrefixDeprecationWatch), repeating every prefixDeprecationInterval
// until none remain.
var (
	prefixDeprecationEnabled  = true
	prefixMismatchThreshold   = 3
	prefixDeprecationInterval = 300 * time.Second
)

// isULA reports whether addr is a Unique Local Address (fc00::/7, RFC 4193).
func isULA(addr netip.Addr) bool {
	if !addr.Is6() {
		return false
	}
	b := addr.As16()
	return b[0]&0xfe == 0xfc
}

// trackablePrefixAddr reports whether addr should ever participate in WAN
// prefix-deprecation tracking: only ULA or globally routable unicast
// addresses, exactly like the user asked - never link-local, multicast or
// loopback (those are never a "prefix" worth comparing/tracking here).
func trackablePrefixAddr(addr netip.Addr) bool {
	if !addr.Is6() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsLoopback() {
		return false
	}
	return true
}

// isGlobalUnicast reports whether addr is a globally routable unicast
// address, i.e. not link-local/multicast/loopback and not ULA (tracked
// separately by isULA - the two are mutually exclusive categories the user
// asked to both snoop).
func isGlobalUnicast(addr netip.Addr) bool {
	return trackablePrefixAddr(addr) && !isULA(addr)
}

// parsePIOPrefixes walks a Router Advertisement's options (data must start
// at the ICMPv6 header, i.e. include the fixed 16-byte RA header) and
// returns every Prefix Information Option's prefix that is ULA or globally
// routable unicast, masked to its advertised prefix length.
func parsePIOPrefixes(data []byte) []netip.Prefix {
	const raHdrLen = 16
	const pioOptType = 3
	const pioOptLen = 32 // 4 * 8 bytes

	if len(data) < raHdrLen {
		return nil
	}

	var out []netip.Prefix
	opt := raHdrLen
	for opt+2 <= len(data) {
		optType := data[opt]
		optLen := int(data[opt+1]) * 8
		if optLen == 0 || opt+optLen > len(data) {
			break
		}

		if optType == pioOptType && optLen >= pioOptLen {
			prefixLen := int(data[opt+2])
			addr, ok := netip.AddrFromSlice(data[opt+16 : opt+32])
			if ok && prefixLen >= 0 && prefixLen <= 128 {
				a := addr.Unmap()
				if isULA(a) || isGlobalUnicast(a) {
					if p, err := a.Prefix(prefixLen); err == nil {
						out = append(out, p.Masked())
					}
				}
			}
		}

		opt += optLen
	}
	return out
}

// trackWANPrefixSnooping is called for every real Router Advertisement
// received on a master interface (see handleICMPv6/captureLastRAHeader in
// router.go). It updates the interface's mismatch-count-based view of
// which single ULA/GUA prefix is currently "live", purely from real-time
// packet snooping (no periodic polling, no kernel address-list involved):
// every RA carrying a prefix other than iface.currentWANPrefix counts as
// one mismatch against that candidate prefix, and once
// prefixMismatchThreshold consecutive mismatches for the *same* candidate
// are seen, it is promoted to current and the old one is handed off to
// startPrefixDeprecationWatch. The very first real RA observed on an
// interface only silently seeds currentWANPrefix (so a fresh (re)start
// never misjudges an already-legitimate prefix as a mismatch just because
// it hasn't been observed before). Must run on the Engine goroutine.
func trackWANPrefixSnooping(iface *Interface, data []byte) {
	prefixes := parsePIOPrefixes(data)

	if !iface.wanPrefixSeeded {
		iface.wanPrefixSeeded = true
		if len(prefixes) > 0 {
			iface.currentWANPrefix = prefixes[0]
		}
		return
	}

	for _, p := range prefixes {
		if p == iface.currentWANPrefix {
			iface.mismatchCandidate = netip.Prefix{}
			iface.mismatchCount = 0
			continue
		}

		if p != iface.mismatchCandidate {
			iface.mismatchCandidate = p
			iface.mismatchCount = 1
		} else {
			iface.mismatchCount++
		}

		if iface.mismatchCount < prefixMismatchThreshold {
			continue
		}

		old := iface.currentWANPrefix
		iface.currentWANPrefix = p
		iface.mismatchCandidate = netip.Prefix{}
		iface.mismatchCount = 0

		if !old.IsValid() || old == p {
			continue
		}

		Noticef("WAN prefix %s on %s replaced by %s after %d mismatching packets, notifying LAN neighbors under it",
			old, iface.Ifname, p, prefixMismatchThreshold)

		startPrefixDeprecationWatch(iface, old)
	}
}

// activePrefixWatches tracks, per dead prefix, the periodic notifier
// started by trackWANPrefixSnooping. Only ever touched from the Engine
// goroutine.
var activePrefixWatches = map[netip.Prefix]*prefixDeprecationWatch{}

type prefixDeprecationWatch struct {
	timer *time.Timer
}

// startPrefixDeprecationWatch begins (if not already running, and if not
// disabled by global.notify_prefix_deprecation) repeatedly notifying LAN
// neighbors still using an address under prefix that it is dead, every
// prefixDeprecationInterval, until no such neighbor remains.
func startPrefixDeprecationWatch(masterIface *Interface, prefix netip.Prefix) {
	if _, exists := activePrefixWatches[prefix]; exists {
		return
	}
	if !prefixDeprecationEnabled {
		Noticef("Prefix deprecation notifications disabled by config, not notifying LAN for %s", prefix)
		return
	}

	w := &prefixDeprecationWatch{}
	activePrefixWatches[prefix] = w
	firePrefixDeprecationWatch(masterIface, prefix, w)
}

// firePrefixDeprecationWatch sends one round of the deprecation RA and
// either reschedules itself in prefixDeprecationInterval, or - once no LAN
// neighbor remains under prefix - stops and forgets this watch.
func firePrefixDeprecationWatch(masterIface *Interface, prefix netip.Prefix, w *prefixDeprecationWatch) {
	remaining := sendPrefixDeprecationRA(masterIface, prefix)
	if remaining == 0 {
		delete(activePrefixWatches, prefix)
		Noticef("No LAN neighbors remain under deprecated WAN prefix %s, stopping notifications", prefix)
		return
	}

	w.timer = time.AfterFunc(prefixDeprecationInterval, func() {
		Eng.Post(func() { firePrefixDeprecationWatch(masterIface, prefix, w) })
	})
}

// sendPrefixDeprecationRA sends a synthesized zero-lifetime PIO RA for
// prefix to every LAN (non-master) relay interface that currently has at
// least one real (non-proxy) neighbor-cache entry under it, and returns the
// total number of such neighbors found across all LAN interfaces (0 means
// the caller should stop repeating).
func sendPrefixDeprecationRA(masterIface *Interface, prefix netip.Prefix) int {
	pkt := buildPrefixDeprecationRAPacket(masterIface, prefix)

	total := 0
	for _, c := range interfaces {
		if c.Master || c.RA != ModeRelay || c.router == nil {
			continue
		}

		n := countNeighborsUnderPrefix(c, prefix)
		if n == 0 {
			continue
		}
		total += n

		if pkt != nil {
			sendICMP6(c, allIPv6Nodes, c.Ifindex, netip.Addr{}, pkt)
		}
	}
	return total
}

// countNeighborsUnderPrefix returns how many of iface's real (non-proxy)
// IPv6 neighbor-cache entries are ULA/GUA addresses falling under prefix.
func countNeighborsUnderPrefix(iface *Interface, prefix netip.Prefix) int {
	link, err := netlink.LinkByIndex(iface.Ifindex)
	if err != nil {
		return 0
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET6)
	if err != nil {
		return 0
	}

	count := 0
	for _, n := range neighs {
		if n.Flags&unix.NTF_PROXY != 0 {
			continue // our own proxy-NDP entries, not real neighbors
		}

		addr, ok := netip.AddrFromSlice(n.IP.To16())
		if !ok {
			continue
		}
		addr = addr.Unmap()

		if !trackablePrefixAddr(addr) || !prefix.Contains(addr) {
			continue
		}
		count++
	}
	return count
}

// buildPrefixDeprecationRAPacket synthesizes a Router Advertisement whose
// only content of interest is a single Prefix Information Option for prefix
// with both Valid and Preferred Lifetime set to 0 (RFC 4861 withdrawal).
// Every other RA header field is copied from masterIface's last real RA
// (see captureLastRAHeader in router.go) so this doesn't affect default-
// router selection on downstream hosts; if no real RA has been seen yet on
// masterIface, nil is returned (the caller still counts neighbors, but
// skips the actual send until a real header is available to copy).
func buildPrefixDeprecationRAPacket(masterIface *Interface, prefix netip.Prefix) []byte {
	if !masterIface.haveLastRA {
		return nil
	}

	const raHdrLen = 16
	const pioLen = 32
	pkt := make([]byte, raHdrLen+pioLen)

	pkt[0] = ndRouterAdvert
	pkt[1] = 0 // code
	// pkt[2:4] checksum left 0 - computed by the kernel (IPV6_CHECKSUM sockopt)
	pkt[4] = masterIface.lastRAHopLimit
	pkt[5] = masterIface.lastRAFlags
	binary.BigEndian.PutUint16(pkt[6:8], masterIface.lastRARouterLifetime)
	binary.BigEndian.PutUint32(pkt[8:12], masterIface.lastRAReachableTime)
	binary.BigEndian.PutUint32(pkt[12:16], masterIface.lastRARetransTimer)

	opt := pkt[raHdrLen:]
	opt[0] = ndOptPrefixInfo
	opt[1] = pioLen / 8
	opt[2] = uint8(prefix.Bits())
	opt[3] = pioFlagOnLink | pioFlagAutonomous
	binary.BigEndian.PutUint32(opt[4:8], 0)  // Valid Lifetime = 0
	binary.BigEndian.PutUint32(opt[8:12], 0) // Preferred Lifetime = 0
	// opt[12:16] reserved2 = 0
	copy(opt[16:32], prefix.Addr().AsSlice())

	return pkt
}

const (
	ndOptPrefixInfo = 3

	pioFlagOnLink     = 0x80
	pioFlagAutonomous = 0x40
)
