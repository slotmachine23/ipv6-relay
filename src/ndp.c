/*
 * ipv6-relay - Lightweight IPv6 Relay Daemon
 * Copyright (C) 2026
 *
 * Based on odhcpd by Steven Barth
 * Licensed under GPLv2
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>

#include <linux/filter.h>
#include <linux/neighbour.h>

#include "dhcpv6.h"
#include "ipv6_relay.h"

static void ndp_netevent_cb(unsigned long event, struct netevent_handler_info *info);
static void setup_route(struct in6_addr *addr, struct interface *iface, bool add);
static void setup_addr_for_relaying(struct in6_addr *addr, struct interface *iface, bool add);
static void relay_ping(const struct in6_addr *target, struct interface *iface);
static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface, void *dest);

static struct netevent_handler ndp_netevent_handler = { .cb = ndp_netevent_cb, };

/*
 * Tracks downstream neighbors we've already mirrored (proxy-NDP entry +
 * host route) so that ndp_netevent_cb() only touches the kernel when a
 * neighbor actually appears or disappears, not on every NUD state
 * transition (REACHABLE -> STALE -> DELAY -> PROBE -> REACHABLE, which
 * recurs every base_reachable_time for hosts with no confirming traffic
 * of their own). Without this, every benign reconfirmation of an
 * existing, still-valid neighbor would trigger a redundant netlink
 * route/proxy replace, which was observed to cause several-second
 * forwarding stalls for that host (repeated FIB/proxy churn disrupts
 * in-flight traffic far more than the underlying NUD aging itself does).
 */
struct mirrored_neigh {
	struct list_head head;
	struct in6_addr addr;
	int ifindex;
};
static struct list_head mirrored_neighs = LIST_HEAD_INIT(mirrored_neighs);

static struct mirrored_neigh *find_mirrored_neigh(const struct in6_addr *addr, int ifindex)
{
	struct mirrored_neigh *m;

	list_for_each_entry(m, &mirrored_neighs, head)
		if (m->ifindex == ifindex && IN6_ARE_ADDR_EQUAL(&m->addr, addr))
			return m;

	return NULL;
}

/* Initialize NDP-proxy */
int ndp_init(void)
{
	int ret = 0;

	if (netlink_add_netevent_handler(&ndp_netevent_handler) < 0) {
		error("Failed to add ndp netevent handler");
		ret = -1;
	}

	return ret;
}

int ndp_setup_interface(struct interface *iface, bool enable)
{
	/* Drop everything */
	static const struct sock_filter bpf_drop_filter[] = {
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	static const struct sock_fprog bpf_drop = {
		.len = ARRAY_SIZE(bpf_drop_filter),
		.filter = (struct sock_filter *)bpf_drop_filter,
	};

	/* Filter ICMPv6 messages of type neighbor solicitation */
	static const struct sock_filter bpf[] = {
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 3),
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, sizeof(struct ip6_hdr) +
			 offsetof(struct icmp6_hdr, icmp6_type)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	static const struct sock_fprog bpf_prog = {
		.len = ARRAY_SIZE(bpf),
		.filter = (struct sock_filter *)bpf,
	};

	int ret = 0, procfd;
	bool dump_neigh = false;
	char procbuf[64];

	enable = enable && (iface->ndp == MODE_RELAY);

	snprintf(procbuf, sizeof(procbuf), "/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface->ifname);
	procfd = open(procbuf, O_WRONLY);

	if (procfd < 0) {
		ret = -1;
		goto out;
	}

	if (iface->ndp_ping_fd >= 0) {
		close(iface->ndp_ping_fd);
		iface->ndp_ping_fd = -1;
	}

	if (iface->ndp_event.uloop.fd >= 0) {
		uloop_fd_delete(&iface->ndp_event.uloop);
		close(iface->ndp_event.uloop.fd);
		iface->ndp_event.uloop.fd = -1;
	}

	if (enable) {
		int val = 2;
		struct icmp6_filter filt;
		struct sockaddr_ll ll;
		struct packet_mreq mreq;

		/*
		 * ICMPv6 raw socket used purely for transmitting: relay_ping()
		 * sends an Echo Request to a solicited target out this
		 * interface to actively resolve (and thereby learn) the
		 * neighbor. Previously ndp_ping_fd was left at -1, so every
		 * send in the solicit path silently failed with EBADF and the
		 * daemon could only ever learn downstream hosts that happened
		 * to originate their own traffic - inbound-initiated resolution
		 * (a WAN host reaching a so-far-unseen LAN client) never worked.
		 */
		iface->ndp_ping_fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
		if (iface->ndp_ping_fd < 0) {
			error("socket(AF_INET6): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->ndp_ping_fd, SOL_SOCKET, SO_BINDTODEVICE,
				iface->ifname, strlen(iface->ifname)) < 0) {
			error("setsockopt(SO_BINDTODEVICE): %m");
			ret = -1;
			goto out;
		}

		/* Let the kernel compute our checksums */
		if (setsockopt(iface->ndp_ping_fd, IPPROTO_RAW, IPV6_CHECKSUM,
				&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_CHECKSUM): %m");
			ret = -1;
			goto out;
		}

		/* This is required by RFC 4861 */
		val = 255;
		if (setsockopt(iface->ndp_ping_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
				&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_MULTICAST_HOPS): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->ndp_ping_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_UNICAST_HOPS): %m");
			ret = -1;
			goto out;
		}

		/* We only ever transmit on this socket, so drop everything received */
		ICMP6_FILTER_SETBLOCKALL(&filt);
		if (setsockopt(iface->ndp_ping_fd, IPPROTO_ICMPV6, ICMP6_FILTER,
				&filt, sizeof(filt)) < 0) {
			error("setsockopt(ICMP6_FILTER): %m");
			ret = -1;
			goto out;
		}

		/*
		 * Bind with protocol ETH_P_ALL, not ETH_P_IPV6.
		 *
		 * The kernel only ever invokes the "outgoing frame" NIT tap
		 * (dev_queue_xmit_nit(), used for locally-transmitted/self-
		 * sent frames - see PACKET_RECV_TYPE / PACKET_OUTGOING below)
		 * for packet sockets registered against ETH_P_ALL. A packet
		 * socket bound to a specific protocol such as ETH_P_IPV6 is
		 * only ever fed from netif_receive_skb(), i.e. genuinely
		 * incoming frames - self-generated frames the local machine
		 * transmits are invisible to it no matter how PACKET_RECV_TYPE
		 * is configured. This was verified experimentally: a minimal
		 * ETH_P_IPV6 socket never observes the kernel's self-generated
		 * neighbor solicitations, while the identical socket bound to
		 * ETH_P_ALL does.
		 *
		 * We still only want IPv6 neighbor solicitations, so the BPF
		 * filter below (bpf_prog) does the real protocol/type
		 * filtering; with SOCK_DGRAM the datagram delivered to
		 * userspace never includes the link-layer header regardless of
		 * which protocol matched, so the filter's fixed offsets
		 * (assuming an IPv6 header at offset 0) remain correct for the
		 * frames that pass it.
		 */
		iface->ndp_event.uloop.fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC,
				htons(ETH_P_ALL));
		if (iface->ndp_event.uloop.fd < 0) {
			ret = -1;
			goto out;
		}

		if (write(procfd, "1\n", 2) < 0) {
			ret = -1;
			goto out;
		}

#ifdef PACKET_RECV_TYPE
		/*
		 * We want multicast frames (neighbor solicitations to the
		 * solicited-node group) - including ones *we* transmit, not
		 * just ones we receive from the wire.
		 *
		 * A frame the local machine itself puts on the wire is always
		 * classified PACKET_OUTGOING by AF_PACKET, *regardless* of its
		 * L2/L3 destination being multicast - PACKET_MULTICAST/
		 * PACKET_HOST/etc classification only ever applies to frames
		 * genuinely received from elsewhere. So a mask of only
		 * "1 << PACKET_MULTICAST" (as used here previously) silently
		 * discards every self-generated NS, on every interface,
		 * without exception.
		 *
		 * That includes the self-generated NS handle_solicit() below
		 * explicitly says it wants to keep on a master (upstream)
		 * interface: when inbound traffic for a not-yet-learned
		 * downstream host arrives, the kernel's own routing lookup
		 * resolves it via the shared prefix's on-link route *on the
		 * master interface itself* and emits exactly such a
		 * self-originated NS there - this is the primary way an
		 * inbound-initiated (host never spoke to us first) downstream
		 * client ever gets its proxy-NDP/host-route mirror set up.
		 * With PACKET_OUTGOING excluded, that NS was silently dropped
		 * by this filter before ever reaching handle_solicit(), so the
		 * mirror was simply never created: the client kept a working
		 * link-local neighbor entry (plain L2 traffic on its own LAN
		 * segment) while its global address stayed forever unreachable
		 * from the outside - i.e. "got an address via SLAAC/DHCPv6 but
		 * has no working IPv6 connectivity", surfacing only for hosts
		 * that never happen to be the target of a genuine externally-
		 * originated NS first.
		 *
		 * Adding PACKET_OUTGOING restores that intended behavior. It
		 * does not reopen the recursive-loop this filter was
		 * originally introduced to prevent (relay_ping()'s own /128
		 * probe route causing an NS on the *downstream* interface it
		 * probes): handle_solicit() already discards a self-sent NS
		 * whose source MAC matches our own precisely when the
		 * receiving interface is not the master (!iface->master), which
		 * is exactly relay_ping()'s case.
		 */
		int pktt = (1 << PACKET_MULTICAST) | (1 << PACKET_OUTGOING);
		if (setsockopt(iface->ndp_event.uloop.fd, SOL_PACKET, PACKET_RECV_TYPE,
				&pktt, sizeof(pktt)) < 0) {
			error("setsockopt(PACKET_RECV_TYPE): %m");
			ret = -1;
			goto out;
		}
#endif

		/*
		 * AF_PACKET sockets start receiving as soon as they exist, so
		 * install a drop-all filter, drain anything already queued, and
		 * only then swap in the real neighbor-solicitation filter. This
		 * avoids a startup race where stray frames slip through before
		 * the filter is in place.
		 */
		if (setsockopt(iface->ndp_event.uloop.fd, SOL_SOCKET, SO_ATTACH_FILTER,
				&bpf_drop, sizeof(bpf_drop)) < 0) {
			error("setsockopt(SO_ATTACH_FILTER): %m");
			ret = -1;
			goto out;
		}

		while (true) {
			char null[1];
			if (recv(iface->ndp_event.uloop.fd, null, sizeof(null),
					MSG_DONTWAIT | MSG_TRUNC) < 0)
				break;
		}

		if (setsockopt(iface->ndp_event.uloop.fd, SOL_SOCKET, SO_ATTACH_FILTER,
				&bpf_prog, sizeof(bpf_prog)) < 0) {
			error("setsockopt(SO_ATTACH_FILTER): %m");
			ret = -1;
			goto out;
		}

		/*
		 * Bind to the interface so this socket only ever sees frames
		 * from its own segment. Without the bind every interface's
		 * capture socket receives every interface's IPv6 frames, which
		 * would dispatch handle_solicit() against the wrong interface.
		 */
		memset(&ll, 0, sizeof(ll));
		ll.sll_family = AF_PACKET;
		ll.sll_ifindex = iface->ifindex;
		ll.sll_protocol = htons(ETH_P_ALL);

		if (bind(iface->ndp_event.uloop.fd, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
			error("bind(): %m");
			ret = -1;
			goto out;
		}

		/*
		 * Enable all-multicast so we receive solicited-node multicast
		 * frames for addresses the local stack itself has not joined -
		 * i.e. neighbor solicitations aimed at the downstream hosts we
		 * relay for.
		 */
		memset(&mreq, 0, sizeof(mreq));
		mreq.mr_ifindex = iface->ifindex;
		mreq.mr_type = PACKET_MR_ALLMULTI;
		mreq.mr_alen = ETH_ALEN;

		if (setsockopt(iface->ndp_event.uloop.fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
				&mreq, sizeof(mreq)) < 0) {
			error("setsockopt(PACKET_ADD_MEMBERSHIP): %m");
			ret = -1;
			goto out;
		}

		iface->ndp_event.handle_dgram = handle_solicit;
		odhcpd_register(&iface->ndp_event);
		dump_neigh = true;
	} else {
		if (write(procfd, "0\n", 2) < 0) {
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->ndp_event.uloop.fd, SOL_SOCKET, SO_DETACH_FILTER,
				&bpf_drop, sizeof(bpf_drop)) < 0)
			ret = -1;
	}

out:
	close(procfd);

	if (ret < 0 && iface->ndp_event.uloop.fd >= 0) {
		close(iface->ndp_event.uloop.fd);
		iface->ndp_event.uloop.fd = -1;
	}

	if (ret < 0 && iface->ndp_ping_fd >= 0) {
		close(iface->ndp_ping_fd);
		iface->ndp_ping_fd = -1;
	}

	if (dump_neigh)
		netlink_dump_neigh_table(true);

	return ret;
}

/*
 * Send an ICMPv6 Echo Request to a solicited target out a single relay
 * interface. This is not about reachability testing but about making the
 * kernel resolve - and therefore learn - the target's neighbor entry on the
 * interface it actually lives behind. Once learned, ndp_netevent_cb() mirrors
 * it into a proxy-NDP entry (on the other relay interfaces) plus a host route.
 */
static void relay_ping(const struct in6_addr *target, struct interface *iface)
{
	struct sockaddr_in6 dest = { .sin6_family = AF_INET6, .sin6_addr = *target };
	struct icmp6_hdr echo = { .icmp6_type = ICMP6_ECHO_REQUEST };
	struct iovec iov = { .iov_base = &echo, .iov_len = sizeof(echo) };

	if (iface->ndp_ping_fd < 0)
		return;

	/*
	 * Pin a temporary /128 route for the target via this interface so the
	 * echo egresses here: the shared prefix's on-link route points at a
	 * different interface, so without this the kernel would try (and fail)
	 * to resolve the target there instead of where it really is. The route
	 * only needs to exist for the duration of the synchronous sendmsg();
	 * the persistent mirror route (metric 1024) is installed separately
	 * once the neighbor is learned, so removing this higher-priority
	 * metric-128 entry afterwards is safe.
	 */
	netlink_setup_route(target, 128, iface->ifindex, NULL, 128, true);
	odhcpd_try_send_with_src(iface->ndp_ping_fd, &dest, &iov, 1, iface);
	netlink_setup_route(target, 128, iface->ifindex, NULL, 128, false);
}

/* Handle solicitations */
static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface, void *dest)
{
	(void)dest;
	struct ip6_hdr *ip6 = data;
	struct nd_neighbor_solicit *req = (struct nd_neighbor_solicit *)&ip6[1];
	struct sockaddr_ll *sll = addr;
	struct interface *c;
	uint8_t mac[6];

	if (iface->ndp != MODE_RELAY)
		return;

	if (len < sizeof(*ip6) + sizeof(*req))
		return; /* Truncated */

	/* A solicitation from the unspecified address is a DAD probe. */
	bool ns_is_dad = IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src);

	/* Only forward DAD probes for external interfaces. */
	if (iface->external && !ns_is_dad)
		return;

	/*
	 * RFC 4861 §7.1.1: silently discard a Neighbor Solicitation whose IP
	 * Hop Limit is not 255 or whose ICMP Code is non-zero. The hop-limit
	 * check is what prevents off-link attackers from forging NS/DAD; since
	 * we capture on an AF_PACKET socket (not a kernel-managed ICMPv6
	 * socket) we have to enforce it ourselves.
	 */
	if (ip6->ip6_hlim != 255 || req->nd_ns_code != 0)
		return;

	/* Nothing to learn for link-local/loopback/multicast targets. */
	if (IN6_IS_ADDR_LINKLOCAL(&req->nd_ns_target) ||
			IN6_IS_ADDR_LOOPBACK(&req->nd_ns_target) ||
			IN6_IS_ADDR_MULTICAST(&req->nd_ns_target))
		return;

	/*
	 * Ignore a solicitation we ourselves emitted that looped back on a
	 * non-master interface. Self-sent NS on a master interface are kept:
	 * they are exactly how inbound traffic for a not-yet-learned
	 * downstream host announces itself (the kernel tries to resolve the
	 * target over the shared prefix's on-link route), and we want to react
	 * by resolving it out the downstream interface.
	 */
	odhcpd_get_mac(iface, mac);
	if (!memcmp(sll->sll_addr, mac, sizeof(mac)) && !iface->master)
		return;

	/*
	 * Actively resolve the target on every other relay interface; whichever
	 * one the host actually sits behind will learn it and trigger the
	 * proxy/host-route mirror in ndp_netevent_cb().
	 */
	avl_for_each_element(&interfaces, c, avl) {
		if (c != iface && c->ndp == MODE_RELAY &&
				(ns_is_dad || !c->external))
			relay_ping(&req->nd_ns_target, c);
	}
}

static void ndp_netevent_cb(unsigned long event, struct netevent_handler_info *info)
{
	if (event == NETEV_ADDR6_ADD) {
		struct interface *iface = info->iface;
		struct in6_addr *addr = &info->addr.in6;

		if (!iface)
			return;

		/* Check for address:able proxies */
		if (iface->ndp == MODE_RELAY && !IN6_IS_ADDR_LOOPBACK(addr) &&
				!IN6_IS_ADDR_MULTICAST(addr) &&
				(!IN6_IS_ADDR_LINKLOCAL(addr) || iface->learn_routes)) {
			setup_addr_for_relaying(addr, iface, true);
			setup_route(addr, iface, true);
		}

		if (IN6_IS_ADDR_LINKLOCAL(addr)) {
			iface->cached_linklocal_valid = false;
			iface->have_link_local = true;
		}
	} else if (event == NETEV_ADDR6_DEL) {
		struct interface *iface = info->iface;
		struct in6_addr *addr = &info->addr.in6;

		if (!iface)
			return;

		if (iface->ndp == MODE_RELAY && !IN6_IS_ADDR_LOOPBACK(addr) &&
				!IN6_IS_ADDR_MULTICAST(addr) &&
				(!IN6_IS_ADDR_LINKLOCAL(addr) || iface->learn_routes)) {
			setup_addr_for_relaying(addr, iface, false);
			setup_route(addr, iface, false);
		}

		if (IN6_IS_ADDR_LINKLOCAL(addr)) {
			iface->cached_linklocal_valid = false;
			iface->have_link_local = false;
		}
	} else if (event == NETEV_ADDRLIST_CHANGE) {
		struct interface *i;
		avl_for_each_element(&interfaces, i, avl) {
			ssize_t cnt = netlink_get_interface_addrs(i->ifindex, true, &i->addr6);
			if (cnt >= 0)
				i->addr6_len = cnt;
		}
	} else if (event == NETEV_NEIGH6_ADD || event == NETEV_NEIGH6_DEL) {
		struct interface *iface = info->iface;
		struct in6_addr *addr = &info->neigh.dst.in6;
		struct mirrored_neigh *m;

		if (!iface)
			return;

		if (!(iface->ndp == MODE_RELAY && !IN6_IS_ADDR_LOOPBACK(addr) &&
				!IN6_IS_ADDR_MULTICAST(addr) && !IN6_IS_ADDR_LINKLOCAL(addr)))
			return;

		/*
		 * When ND resolves a downstream host's address on a relayed
		 * interface (e.g. a LAN client that SLAAC'd an address out of
		 * a prefix relayed from WAN), that address is otherwise
		 * unreachable: the kernel's on-link route for the shared
		 * prefix points at the WAN interface, and WAN-side hosts have
		 * no way to resolve the LAN host's link-layer address. Mirror
		 * the learned neighbor into a proxy-NDP entry on the other
		 * relayed (master) interfaces and a host route via the
		 * interface that actually learned it, exactly as already done
		 * for locally-assigned addresses above.
		 *
		 * The mirror is tracked in mirrored_neighs so we only touch the
		 * kernel on real transitions, never on the benign
		 * STALE/DELAY/PROBE/REACHABLE re-confirmation cycle an
		 * already-mirrored, forwarded-only host goes through roughly
		 * every base_reachable_time (re-issuing the route/proxy netlink
		 * calls on every such cycle was observed to itself cause
		 * multi-second forwarding stalls).
		 *
		 * Crucially, the mirror lifetime is decoupled from the volatile
		 * neighbor cache entry:
		 *
		 *  - A plain RTM_DELNEIGH (NETEV_NEIGH6_DEL) means the kernel
		 *    merely garbage-collected an idle STALE entry after
		 *    gc_stale_time. The downstream host is almost always still
		 *    present (a quiet SSH/terminal session generates no traffic
		 *    of its own), so tearing the mirror down here would blackhole
		 *    that host's inbound/return traffic until it happens to send
		 *    something again - observed as IPv6 "cutting in and out" for
		 *    otherwise-idle clients. We therefore keep the mirror on
		 *    NEIGH6_DEL and let it be re-validated on demand.
		 *
		 *  - Only an explicit NUD_FAILED (the kernel actively probed the
		 *    host, exhausted its retransmits and got no answer) is
		 *    treated as a genuine departure that reaps the mirror. This
		 *    still bounds stale mirrors: as soon as anything tries to
		 *    reach a host that has really left, the resulting failed
		 *    resolution removes its proxy entry and host route.
		 *
		 * NUD_INCOMPLETE (first-time/in-progress resolution) is neither a
		 * confirmation nor a failure and is ignored.
		 */
		m = find_mirrored_neigh(addr, iface->ifindex);

		if (event == NETEV_NEIGH6_ADD) {
			bool resolved = info->neigh.state &
				(NUD_REACHABLE | NUD_STALE | NUD_DELAY |
				 NUD_PROBE | NUD_PERMANENT | NUD_NOARP);
			bool failed = info->neigh.state & NUD_FAILED;

			if (resolved && !m) {
				m = calloc(1, sizeof(*m));
				if (!m)
					return;
				m->addr = *addr;
				m->ifindex = iface->ifindex;
				list_add(&m->head, &mirrored_neighs);
				setup_addr_for_relaying(addr, iface, true);
				setup_route(addr, iface, true);
			} else if (failed && m) {
				list_del(&m->head);
				free(m);
				setup_addr_for_relaying(addr, iface, false);
				setup_route(addr, iface, false);
			}
		}
		/* NETEV_NEIGH6_DEL: keep the mirror (see comment above). */
	}
}

static void setup_route(struct in6_addr *addr, struct interface *iface, bool add)
{
	if (!iface->learn_routes)
		return;

	if (IN6_IS_ADDR_LINKLOCAL(addr))
		return;

	netlink_setup_route(addr, 128, iface->ifindex, NULL, 1024, add);
}

static void setup_addr_for_relaying(struct in6_addr *addr, struct interface *iface, bool add)
{
	struct interface *c;
	avl_for_each_element(&interfaces, c, avl) {
		if (c->ifindex == iface->ifindex || !c->master || c->ndp != MODE_RELAY)
			continue;

		netlink_setup_proxy_neigh(addr, c->ifindex, add);
	}
}