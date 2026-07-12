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
		iface->ndp_event.uloop.fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC,
				htons(ETH_P_IPV6));
		if (iface->ndp_event.uloop.fd < 0) {
			ret = -1;
			goto out;
		}

		if (write(procfd, "1\n", 2) < 0) {
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->ndp_event.uloop.fd, SOL_SOCKET, SO_ATTACH_FILTER,
				&bpf_prog, sizeof(bpf_prog)) < 0) {
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

	if (dump_neigh)
		netlink_dump_neigh_table(true);

	return ret;
}

/* Handle solicitations */
static void handle_solicit(void *addr, void *data, size_t len,
		struct interface *iface, void *dest)
{
	(void)dest;
	struct ip6_hdr *ip6 = data;
	struct nd_neighbor_solicit *req = (struct nd_neighbor_solicit *)&ip6[1];
	struct sockaddr_ll *sll = addr;

	/* Don't forward definite duplicate */
	if (ip6->ip6_hlim != 255)
		return;

	/* Only use first address in list */
	if (!IN6_IS_ADDR_MULTICAST(&req->nd_ns_target) &&
			req->nd_ns_target.s6_addr32[0] != htonl(0xff000000)) {
		struct interface *c;

		avl_for_each_element(&interfaces, c, avl) {
			if (!c->master || c->ndp != MODE_RELAY || c->ifindex == sll->sll_ifindex)
				continue;

			if (!IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) &&
					IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)) {
				odhcpd_send_with_src(iface->ndp_ping_fd,
						&(struct sockaddr_in6) {
							AF_INET6, 0, 0,
							IN6ADDR_LINKLOCAL_ALLNODES_INIT,
							c->ifindex
						}, &(struct iovec) {ip6, len}, 1, c,
						&ip6->ip6_src);
			} else {
				odhcpd_send(iface->ndp_ping_fd,
						&(struct sockaddr_in6) {
							AF_INET6, 0, 0,
							IN6ADDR_LINKLOCAL_ALLNODES_INIT,
							c->ifindex
						}, &(struct iovec) {ip6, len}, 1, c);
			}
		}
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
		/* Only consider neighbor entries that are actually resolved;
		 * treat INCOMPLETE/FAILED the same as a deletion. */
		bool resolved = (event == NETEV_NEIGH6_ADD) &&
			(info->neigh.state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY |
					       NUD_PROBE | NUD_PERMANENT | NUD_NOARP));

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
		 * Only act on an actual appear/disappear transition (tracked
		 * via mirrored_neighs), not on every intermediate NUD state
		 * change of an already-mirrored neighbor: kernel neighbor
		 * entries for hosts whose traffic is merely being forwarded
		 * (rather than locally originated/terminated) don't get the
		 * usual "confirmed reachable" feedback, so they cycle through
		 * STALE/DELAY/PROBE roughly every base_reachable_time even
		 * while the host is continuously active. Re-issuing the
		 * route/proxy netlink calls on every such cycle was observed
		 * to itself cause multi-second forwarding stalls for that
		 * host, which is worse than the harmless aging it reacted to.
		 */
		m = find_mirrored_neigh(addr, iface->ifindex);
		if (resolved && !m) {
			m = calloc(1, sizeof(*m));
			if (!m)
				return;
			m->addr = *addr;
			m->ifindex = iface->ifindex;
			list_add(&m->head, &mirrored_neighs);
			setup_addr_for_relaying(addr, iface, true);
			setup_route(addr, iface, true);
		} else if (!resolved && m) {
			list_del(&m->head);
			free(m);
			setup_addr_for_relaying(addr, iface, false);
			setup_route(addr, iface, false);
		}
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