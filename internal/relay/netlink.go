package relay

import (
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// mirroredNeigh tracks a downstream neighbor we have already mirrored
// (proxy-NDP entry + host route), mirroring struct mirrored_neigh /
// mirrored_neighs in ndp.c: we only want to touch the kernel on a real
// appear/disappear transition, not on every NUD reconfirmation cycle.
type mirroredNeighKey struct {
	addr    netip.Addr
	ifindex int
}

var mirroredNeighs = map[mirroredNeighKey]bool{}

// StartNetlinkMonitor subscribes to link/address/neighbor changes and
// forwards them to the Engine, mirroring netlink_init()'s RTNLGRP_LINK /
// RTNLGRP_IPV6_IFADDR / RTNLGRP_NEIGH membership (route events are
// deliberately not subscribed to: the C daemon receives them too but never
// actually acts on NETEV_ROUTE6_ADD/DEL).
func StartNetlinkMonitor(done <-chan struct{}) error {
	linkCh := make(chan netlink.LinkUpdate, 64)
	if err := netlink.LinkSubscribe(linkCh, done); err != nil {
		return err
	}

	addrCh := make(chan netlink.AddrUpdate, 64)
	if err := netlink.AddrSubscribe(addrCh, done); err != nil {
		return err
	}

	neighCh := make(chan netlink.NeighUpdate, 64)
	if err := netlink.NeighSubscribe(neighCh, done); err != nil {
		return err
	}

	go func() {
		for {
			select {
			case u, ok := <-linkCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleLinkEvent(u) })
			case u, ok := <-addrCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleAddrEvent(u) })
			case u, ok := <-neighCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleNeighEvent(u) })
			case <-done:
				return
			}
		}
	}()

	return nil
}

// handleLinkEvent mirrors handle_rtm_link(): react to a real carrier
// up/down transition (IFF_RUNNING toggling) on a tracked interface by
// (re)enabling or tearing down its relay services.
func handleLinkEvent(u netlink.LinkUpdate) {
	ifname := u.Attrs().Name

	iface := ifaceByIfname(ifname)
	if iface == nil {
		return
	}

	nowRunning := u.IfInfomsg.Flags&unix.IFF_RUNNING != 0

	if iface.Ifindex == int(u.Index) {
		wasRunning := iface.Running
		iface.Running = nowRunning

		if wasRunning != nowRunning {
			reloadServices(iface)
		}
		return
	}

	// ifindex changed (e.g. interface was recreated) - just adopt it, the
	// C daemon fires NETEV_IFINDEX_CHANGE here but nothing outside
	// netlink.c actually consumes that event.
	iface.Ifindex = int(u.Index)
	iface.Running = nowRunning
}

// handleAddrEvent mirrors handle_rtm_addr()'s effects: refresh the cached
// address list for the interface, and mirror the changed address into
// proxy-NDP/host-route state exactly like NETEV_ADDR6_ADD/DEL do in ndp.c.
func handleAddrEvent(u netlink.AddrUpdate) {
	if u.LinkAddress.IP.To4() != nil {
		return // IPv4, irrelevant to this daemon
	}

	iface := ifaceByIndex(u.LinkIndex)
	if iface == nil {
		return
	}

	iface.Addr6 = fetchAddr6(iface.Ifindex)

	addr, ok := netip.AddrFromSlice(u.LinkAddress.IP.To16())
	if !ok {
		return
	}
	addr = addr.Unmap()

	if iface.NDP == ModeRelay && !addr.IsLoopback() && !addr.IsMulticast() &&
		(!addr.IsLinkLocalUnicast() || iface.LearnRoutes) {
		ndpMirrorAddr(addr, iface, u.NewAddr)
	}

	if addr.IsLinkLocalUnicast() {
		iface.cachedLLValid = false
		iface.HaveLinkLocal = u.NewAddr
	}
}

// handleNeighEvent mirrors the NETEV_NEIGH6_ADD branch of
// ndp_netevent_cb(): once the kernel resolves a downstream host's address
// (NUD_REACHABLE/STALE/DELAY/PROBE/PERMANENT/NOARP), mirror it into
// proxy-NDP + a host route; only an explicit NUD_FAILED reaps that mirror
// again. A plain deletion (idle STALE GC) intentionally leaves the mirror
// in place, exactly as upstream does, so idle-but-present hosts are not
// blackholed.
func handleNeighEvent(u netlink.NeighUpdate) {
	if u.Type != unix.RTM_NEWNEIGH {
		return
	}

	iface := ifaceByIndex(u.LinkIndex)
	if iface == nil || iface.NDP != ModeRelay {
		return
	}

	ip4 := u.IP.To4()
	if ip4 != nil {
		return
	}

	addr, ok := netip.AddrFromSlice(u.IP.To16())
	if !ok {
		return
	}
	addr = addr.Unmap()

	if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return
	}

	key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
	mirrored := mirroredNeighs[key]

	const resolvedMask = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY |
		unix.NUD_PROBE | unix.NUD_PERMANENT | unix.NUD_NOARP

	resolved := u.State&resolvedMask != 0
	failed := u.State&unix.NUD_FAILED != 0

	if resolved && !mirrored {
		mirroredNeighs[key] = true
		ndpMirrorAddr(addr, iface, true)
	} else if failed && mirrored {
		delete(mirroredNeighs, key)
		ndpMirrorAddr(addr, iface, false)
	}
}

// ndpMirrorAddr mirrors setup_addr_for_relaying() + setup_route(): install
// (or remove) a proxy-NDP entry on every other master/relay interface, plus
// a host route pointing back at the interface the address actually lives
// behind.
func ndpMirrorAddr(addr netip.Addr, iface *Interface, add bool) {
	for _, c := range interfaces {
		if c.Ifindex == iface.Ifindex || !c.Master || c.NDP != ModeRelay {
			continue
		}
		if err := setupProxyNeigh(addr, c.Ifindex, add); err != nil {
			Warnf("proxy neigh %s on %s: %v", addr, c.Ifname, err)
		}
	}

	if !iface.LearnRoutes || addr.IsLinkLocalUnicast() {
		return
	}

	if err := setupRoute(addr, 128, iface.Ifindex, nil, 1024, add); err != nil {
		Warnf("route %s/128 via %s: %v", addr, iface.Ifname, err)
	}
}

// setupRoute mirrors netlink_setup_route().
func setupRoute(addr netip.Addr, prefixlen int, ifindex int, gw *netip.Addr, metric int, add bool) error {
	dst := &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(prefixlen, 128)}

	route := &netlink.Route{
		LinkIndex: ifindex,
		Dst:       dst,
		Priority:  metric,
		Table:     unix.RT_TABLE_MAIN,
		Scope:     netlink.SCOPE_LINK,
	}

	if gw != nil {
		gwIP := net.IP(gw.AsSlice())
		route.Gw = gwIP
		route.Scope = netlink.SCOPE_UNIVERSE
	}

	if add {
		route.Protocol = unix.RTPROT_STATIC
		return netlink.RouteReplace(route)
	}

	return netlink.RouteDel(route)
}

// setupProxyNeigh mirrors netlink_setup_proxy_neigh().
func setupProxyNeigh(addr netip.Addr, ifindex int, add bool) error {
	n := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    unix.AF_INET6,
		Flags:     unix.NTF_PROXY,
		IP:        net.IP(addr.AsSlice()),
	}

	if add {
		return netlink.NeighSet(n)
	}
	return netlink.NeighDel(n)
}

// seedMirroredNeighbors mirrors netlink_dump_neigh_table(true) + the
// resulting NETEV_NEIGH6_ADD replay: after (re)enabling NDP relay on an
// interface, walk the kernel's existing neighbor table so hosts resolved
// before the daemon (re)started are mirrored immediately instead of only
// on their next NUD transition.
func seedMirroredNeighbors(iface *Interface) {
	link, err := netlink.LinkByIndex(iface.Ifindex)
	if err != nil {
		return
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET6)
	if err != nil {
		return
	}

	const resolvedMask = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY |
		unix.NUD_PROBE | unix.NUD_PERMANENT | unix.NUD_NOARP

	for _, n := range neighs {
		if n.State&resolvedMask == 0 {
			continue
		}

		addr, ok := netip.AddrFromSlice(n.IP.To16())
		if !ok {
			continue
		}
		addr = addr.Unmap()

		if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			continue
		}

		key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
		if mirroredNeighs[key] {
			continue
		}

		mirroredNeighs[key] = true
		ndpMirrorAddr(addr, iface, true)
	}
}
