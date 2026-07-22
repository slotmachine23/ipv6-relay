package relay

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// prefixDeprecationEnabled/prefixDeprecationInterval are the two global
// tunables the user gets for this feature (config.json's global.
// notify_prefix_deprecation / global.prefix_deprecation_interval_seconds -
// see config.go's loadConfigJSON). Deliberately package vars with sane
// defaults rather than requiring config: this is a mitigation for upstream
// routers that renumber a delegated prefix without ever sending a proper
// RFC 4861 zero-lifetime withdrawal for the old one, left on by default.
var (
	prefixDeprecationEnabled  = true
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

// betterPreferred reports whether candidate's remaining preferred lifetime
// (absolute epoch seconds, 0 = infinite) outranks existing's, treating
// "infinite" as always the best.
func betterPreferred(candidate, existing uint32) bool {
	if candidate == 0 {
		return true
	}
	if existing == 0 {
		return false
	}
	return candidate > existing
}

// evaluateWANPrefixes recomputes iface's set of "currently live" ULA/GUA
// prefixes purely from its own current kernel address list (iface.Addr6) -
// no RA/PIO packet parsing involved, per the user's explicit simplification
// request. Among any ULA/GUA prefixes simultaneously present with a
// still-valid lifetime, the one(s) with the longest remaining (or infinite)
// preferred lifetime are considered "current"; any other such prefix is
// considered superseded/stale, since a real upstream keeps refreshing the
// preferred lifetime of whichever prefix it still considers current. The
// very first evaluation for an interface only silently seeds this state
// (so a restart never mistakes an already-legitimate prefix for a stale
// one just because it hasn't been observed before) - only evaluations
// after that trigger sendPrefixDeprecationRA. Must run on the Engine
// goroutine (called from refreshInterfaceAddresses).
func evaluateWANPrefixes(iface *Interface) {
	now := uint32(nowMono())
	prefixLifetime := map[netip.Prefix]uint32{}
	haveInfinite := false

	for _, a := range iface.Addr6 {
		if a.Tentative || !(isULA(a.Addr) || isGlobalUnicast(a.Addr)) {
			continue
		}
		if a.ValidLT != 0 && a.ValidLT <= now {
			continue // already expired, kernel just hasn't reaped it yet
		}

		p := netip.PrefixFrom(a.Addr, int(a.PrefixLen)).Masked()

		if a.PreferredLT == 0 {
			haveInfinite = true
		}

		if existing, ok := prefixLifetime[p]; !ok || betterPreferred(a.PreferredLT, existing) {
			prefixLifetime[p] = a.PreferredLT
		}
	}

	if len(prefixLifetime) == 0 {
		return // no trackable address right now; don't churn known state on a transient gap
	}

	current := map[netip.Prefix]bool{}
	if haveInfinite {
		for p, lt := range prefixLifetime {
			if lt == 0 {
				current[p] = true
			}
		}
	} else {
		var bestPrefix netip.Prefix
		var bestLT uint32
		first := true
		for p, lt := range prefixLifetime {
			if first || lt > bestLT {
				bestPrefix, bestLT, first = p, lt, false
			}
		}
		current[bestPrefix] = true
	}

	if iface.knownWANPrefixes == nil {
		iface.knownWANPrefixes = map[netip.Prefix]bool{}
	}

	seeding := !iface.wanPrefixSeeded
	iface.wanPrefixSeeded = true

	for p := range prefixLifetime {
		if current[p] {
			iface.knownWANPrefixes[p] = true
			continue
		}

		wasCurrent := iface.knownWANPrefixes[p]
		if !wasCurrent {
			continue // already known-stale (or never seen as current) - nothing new
		}

		delete(iface.knownWANPrefixes, p)
		if seeding {
			continue
		}

		Noticef("WAN prefix %s on %s superseded by a fresher prefix, notifying LAN neighbors under it", p, iface.Ifname)
		startPrefixDeprecationWatch(iface, p)
	}
}

// isGlobalUnicast reports whether addr is a globally routable unicast
// address, i.e. not link-local/multicast/loopback and not ULA (tracked
// separately by isULA - the two are mutually exclusive categories the user
// asked to both snoop).
func isGlobalUnicast(addr netip.Addr) bool {
	return trackablePrefixAddr(addr) && !isULA(addr)
}

// activePrefixWatches tracks, per stale prefix, the periodic notifier
// started by evaluateWANPrefixes. Only ever touched from the Engine
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
