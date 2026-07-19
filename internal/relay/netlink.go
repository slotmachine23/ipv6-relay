package relay

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

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
// RTNLGRP_IPV6_IFADDR / RTNLGRP_NEIGH membership. It additionally subscribes
// to route changes (which the C daemon receives but ignores): they are the
// event that lets the daemon self-heal after an external network manager -
// notably systemd-networkd driven by `netplan apply` - flushes the /128 host
// routes we install and, in the same reconfigure pass, resets
// net.ipv6.conf.<if>.proxy_ndp back to 0. See handleRouteEvent.
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

	// A flush (e.g. ManageForeignRoutes on `netplan apply`) deletes every one
	// of our host routes in a single burst, so give this channel plenty of
	// slack to avoid dropping updates before the reader drains them.
	routeCh := make(chan netlink.RouteUpdate, 256)
	if err := netlink.RouteSubscribe(routeCh, done); err != nil {
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
			case u, ok := <-routeCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleRouteEvent(u) })
			case <-done:
				return
			}
		}
	}()

	return nil
}

// ourRouteMetric is the priority the daemon installs its persistent downstream
// /128 host routes with (see ndpMirrorAddr). relay_ping's throwaway route uses
// a different metric, so filtering on this value keeps that churn from
// triggering reconciliation.
const ourRouteMetric = 1024

// reconcileDebounce coalesces the burst of RTM_DELROUTE events an external
// flush produces into a single re-assertion pass, and lets the flush finish
// before we re-add so our routes stick instead of racing the deleter.
const reconcileDebounce = 2 * time.Second

// reconcileScheduled guards against stacking debounce timers. Only ever
// touched from the Engine goroutine.
var reconcileScheduled bool

// handleRouteEvent watches for deletion of the host routes the daemon owns.
// systemd-networkd (on `netplan apply`, with its default ManageForeignRoutes)
// flushes them and, in the same pass, resets proxy_ndp to 0 - neither of which
// produces a link/address/neighbor event and neither of which the
// mirroredNeighs cache notices. The route deletion is the one observable
// signal, so a single (debounced) reconcile off it restores proxy_ndp, the
// proxy-NDP entries and the host routes together. Runs on the Engine goroutine.
func handleRouteEvent(u netlink.RouteUpdate) {
	if u.Type != unix.RTM_DELROUTE || u.Priority != ourRouteMetric || u.Dst == nil {
		return
	}
	if ones, bits := u.Dst.Mask.Size(); bits != 128 || ones != 128 {
		return // only our /128 host routes
	}
	if iface := ifaceByIndex(u.LinkIndex); iface == nil || iface.NDP != ModeRelay {
		return
	}
	scheduleReconcile()
}

// scheduleReconcile arranges for exactly one reconcileKernelState() to run
// reconcileDebounce from now, collapsing a flush's event burst into a single
// pass. Runs on (and only touches state from) the Engine goroutine.
func scheduleReconcile() {
	if reconcileScheduled {
		return
	}
	reconcileScheduled = true
	time.AfterFunc(reconcileDebounce, func() {
		Eng.Post(func() {
			reconcileScheduled = false
			reconcileKernelState()
		})
	})
}

// reconcileKernelState re-applies the proxy_ndp sysctl, proxy-NDP neighbor
// entries and host routes the daemon is responsible for. Every underlying
// operation (sysctl write, NeighSet, RouteReplace) is idempotent, so on the
// steady-state happy path this is a cheap no-op; it only actually changes
// anything when something external removed our state. Runs on the Engine
// goroutine.
func reconcileKernelState() {
	for _, iface := range interfaces {
		if iface.NDP != ModeRelay || iface.ndp == nil {
			continue
		}
		if err := setProxyNDP(iface.Ifname, true); err != nil {
			Debugf("reconcile proxy_ndp on %s: %v", iface.Ifname, err)
		}
	}

	// Re-assert the mirror for every interface's own downstream addresses.
	for _, iface := range interfaces {
		if iface.NDP != ModeRelay {
			continue
		}
		for _, a := range iface.Addr6 {
			addr := a.Addr
			if addr.IsLoopback() || addr.IsMulticast() {
				continue
			}
			if addr.IsLinkLocalUnicast() && !iface.LearnRoutes {
				continue
			}
			ndpMirrorAddr(addr, iface, true)
		}
	}

	// Re-assert the mirror for every downstream host we have learned.
	for key := range mirroredNeighs {
		iface := ifaceByIndex(key.ifindex)
		if iface == nil {
			continue
		}
		ndpMirrorAddr(key.addr, iface, true)
	}
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

	if u.Header.Type == unix.RTM_DELLINK {
		if iface.Ifindex != int(u.Index) {
			return
		}

		disableServices(iface)
		clearMirroredState(iface)
		iface.Ifindex = 0
		iface.Running = false
		iface.Addr6 = nil
		iface.cachedLLValid = false
		iface.HaveLinkLocal = false
		return
	}

	nowRunning := u.IfInfomsg.Flags&unix.IFF_RUNNING != 0

	if iface.Ifindex == int(u.Index) {
		wasRunning := iface.Running
		iface.Running = nowRunning

		if wasRunning != nowRunning {
			if nowRunning {
				refreshInterfaceAddresses(iface)
			}
			reloadServices(iface)
		}
		return
	}

	// A same-name interface can come back with a new ifindex. Sockets,
	// multicast memberships, routes, and mirrored-neighbor bookkeeping all
	// refer to the old index and must be replaced as one lifecycle change.
	disableServices(iface)
	clearMirroredState(iface)
	iface.Ifindex = int(u.Index)
	iface.Running = nowRunning
	refreshInterfaceAddresses(iface)
	reloadServices(iface)
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

	refreshInterfaceAddresses(iface)

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
		// refreshInterfaceAddresses derives this from the complete current
		// list, so removing one of multiple link-local addresses stays correct.
		iface.cachedLLValid = false
	}
}

func clearMirroredState(iface *Interface) {
	for _, cached := range iface.Addr6 {
		addr := cached.Addr
		if iface.NDP == ModeRelay && !addr.IsLoopback() && !addr.IsMulticast() &&
			(!addr.IsLinkLocalUnicast() || iface.LearnRoutes) {
			ndpMirrorAddr(addr, iface, false)
		}
	}

	for key := range mirroredNeighs {
		if key.ifindex != iface.Ifindex {
			continue
		}
		ndpMirrorAddr(key.addr, iface, false)
		delete(mirroredNeighs, key)
	}
}

// handleNeighEvent mirrors the NETEV_NEIGH6_ADD branch of
// ndp_netevent_cb(): once the kernel resolves a downstream host's address
// (NUD_REACHABLE/STALE/DELAY/PROBE/PERMANENT/NOARP), mirror it into
// proxy-NDP + a host route; only an explicit NUD_FAILED reaps that mirror
// again. A plain deletion (idle STALE GC) intentionally leaves the mirror
// in place, exactly as upstream does, so idle-but-present hosts are not
// blackholed.
//
// A NUD_FAILED entry is also reaped from the kernel's neighbor cache
// unconditionally, not just when it was mirrored. relay_ping's speculative
// probes (see relayPing) create a real neighbor entry on every relay
// interface other than the one the target actually lives behind; on those
// "wrong" interfaces resolution can never succeed, so the entry just sits
// there FAILED forever - the kernel does not otherwise age these out under
// normal gc thresholds. Left alone, this is exactly what accumulates as a
// growing pile of stale FAILED entries in `ip -6 neigh show`.
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
	} else if failed {
		if mirrored {
			delete(mirroredNeighs, key)
			ndpMirrorAddr(addr, iface, false)
		}
		deleteFailedNeigh(addr, iface.Ifindex)
	}
}

// deleteFailedNeigh removes a real (non-proxy) NUD_FAILED neighbor cache
// entry so it doesn't linger indefinitely; see handleNeighEvent. ESRCH/ENOENT
// just means it's already gone (e.g. raced with the kernel's own GC) and
// isn't worth logging.
func deleteFailedNeigh(addr netip.Addr, ifindex int) {
	n := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    unix.AF_INET6,
		IP:        net.IP(addr.AsSlice()),
	}
	if err := netlink.NeighDel(n); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
		Debugf("delete failed neigh %s on ifindex %d: %v", addr, ifindex, err)
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
		// A proxy-NDP entry is inert unless proxy_ndp is enabled on its
		// interface, so re-assert it here: this keeps proxy_ndp correct even
		// after an external reset (e.g. `netplan apply`) for which no host
		// route existed to trigger handleRouteEvent.
		if add {
			if err := setProxyNDP(c.Ifname, true); err != nil {
				Debugf("proxy_ndp on %s: %v", c.Ifname, err)
			}
		}
		if err := setupProxyNeigh(addr, c.Ifindex, add); err != nil {
			Warnf("proxy neigh %s on %s: %v", addr, c.Ifname, err)
		}
	}

	if !iface.LearnRoutes || addr.IsLinkLocalUnicast() {
		return
	}

	if err := setupRoute(addr, 128, iface.Ifindex, nil, ourRouteMetric, add); err != nil {
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

	// ESRCH ("no such process") from RouteDel just means the route is
	// already gone (e.g. the kernel/network stack flushed it itself when
	// the delegated prefix changed and the address was removed). The
	// desired end state - no route - already holds, so this isn't a real
	// error and shouldn't be logged as one.
	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
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
	if err := netlink.NeighDel(n); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
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
