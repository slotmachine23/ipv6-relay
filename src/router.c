/*
 * ipv6-relay - Lightweight IPv6 Relay Daemon
 * Copyright (C) 2026
 *
 * Based on odhcpd by Steven Barth
 * Licensed under GPLv2
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <netinet/ip6.h>

#include "ipv6_relay.h"

/*
 * RFC 4861 host constants for router solicitation. We (ab)use them on the
 * master (upstream-facing) relay interface: after (re)start or a link-up
 * event the daemon proactively solicits a Router Advertisement instead of
 * passively waiting for the next unsolicited one (which upstream may only
 * emit every MaxRtrAdvInterval - up to several minutes), so downstream
 * clients regain their prefix/default route within seconds.
 */
#define MAX_RTR_SOLICITATIONS		3
#define RTR_SOLICITATION_INTERVAL	4000	/* milliseconds */

static void send_router_solicitation(const struct interface *iface);
static void forward_router_solicitation(const struct interface *iface);
static void forward_router_advertisement(const struct interface *iface, uint8_t *data, size_t len);
static void solicit_timer_cb(struct uloop_timeout *t);

static void handle_icmpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest);
static void router_netevent_cb(unsigned long event, struct netevent_handler_info *info);

static struct netevent_handler router_netevent_handler = { .cb = router_netevent_cb, };

int router_init(void)
{
	int ret = 0;

	if (netlink_add_netevent_handler(&router_netevent_handler) < 0) {
		error("Failed to add router netevent handler");
		ret = -1;
	}

	return ret;
}

int router_setup_interface(struct interface *iface, bool enable)
{
	int ret = 0;

	enable = enable && (iface->ra != MODE_DISABLED);

	if (!enable && iface->router_event.uloop.fd >= 0) {
		uloop_timeout_cancel(&iface->timer_rs);
		uloop_fd_delete(&iface->router_event.uloop);
		close(iface->router_event.uloop.fd);
		iface->router_event.uloop.fd = -1;
	} else if (enable) {
		struct icmp6_filter filt;
		struct ipv6_mreq mreq;
		int val = 2;

		if (iface->router_event.uloop.fd < 0) {
			/* Open ICMPv6 socket */
			iface->router_event.uloop.fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC,
								IPPROTO_ICMPV6);
			if (iface->router_event.uloop.fd < 0) {
				error("socket(AF_INET6): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, SOL_SOCKET, SO_BINDTODEVICE,
						iface->ifname, strlen(iface->ifname)) < 0) {
				error("setsockopt(SO_BINDTODEVICE): %m");
				ret = -1;
				goto out;
			}

			/* Let the kernel compute our checksums */
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_RAW, IPV6_CHECKSUM,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_CHECKSUM): %m");
				ret = -1;
				goto out;
			}

			/* This is required by RFC 4861 */
			val = 255;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_MULTICAST_HOPS): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_UNICAST_HOPS): %m");
				ret = -1;
				goto out;
			}

			/* We need to know the source interface */
			val = 1;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_RECVPKTINFO): %m");
				ret = -1;
				goto out;
			}

			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_RECVHOPLIMIT): %m");
				ret = -1;
				goto out;
			}

			/* Don't loop back */
			val = 0;
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
						&val, sizeof(val)) < 0) {
				error("setsockopt(IPV6_MULTICAST_LOOP): %m");
				ret = -1;
				goto out;
			}

			/* Filter ICMPv6 package types */
			ICMP6_FILTER_SETBLOCKALL(&filt);
			ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
			ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filt);
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_ICMPV6, ICMP6_FILTER,
						&filt, sizeof(filt)) < 0) {
				error("setsockopt(ICMP6_FILTER): %m");
				ret = -1;
				goto out;
			}

			iface->router_event.handle_dgram = handle_icmpv6;
			iface->ra_sent = 0;
			odhcpd_register(&iface->router_event);
		} else {
			memset(&mreq, 0, sizeof(mreq));
			mreq.ipv6mr_interface = iface->ifindex;
			inet_pton(AF_INET6, ALL_IPV6_NODES, &mreq.ipv6mr_multiaddr);
			setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
				   &mreq, sizeof(mreq));

			inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &mreq.ipv6mr_multiaddr);
			setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
				   &mreq, sizeof(mreq));
		}

		memset(&mreq, 0, sizeof(mreq));
		mreq.ipv6mr_interface = iface->ifindex;

		if (iface->master) {
			/* Master (upstream) interface receives unsolicited RAs,
			 * which are sent to the all-nodes multicast address. */
			inet_pton(AF_INET6, ALL_IPV6_NODES, &mreq.ipv6mr_multiaddr);
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
						&mreq, sizeof(mreq)) < 0) {
				error("setsockopt(IPV6_ADD_MEMBERSHIP): %m");
				ret = -1;
				goto out;
			}

			/*
			 * Kick off proactive router solicitation so downstream
			 * clients get an RA within seconds of (re)start or link-up
			 * instead of waiting for the next unsolicited upstream RA.
			 */
			iface->ra_sent = 0;
			iface->timer_rs.cb = solicit_timer_cb;
			uloop_timeout_set(&iface->timer_rs, 100);
		} else {
			/* Slave (downstream) interface receives RSs from hosts,
			 * which are sent to the all-routers multicast address. */
			inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &mreq.ipv6mr_multiaddr);
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
						&mreq, sizeof(mreq)) < 0) {
				error("setsockopt(IPV6_ADD_MEMBERSHIP): %m");
				ret = -1;
				goto out;
			}
		}
	}

out:
	if (ret < 0 && iface->router_event.uloop.fd >= 0) {
		close(iface->router_event.uloop.fd);
		iface->router_event.uloop.fd = -1;
	}

	return ret;
}

/* Send a router solicitation out a single (master) interface */
static void send_router_solicitation(const struct interface *iface)
{
	struct sockaddr_in6 all_routers;
	struct nd_router_solicit rs = {
		.nd_rs_type = ND_ROUTER_SOLICIT,
		.nd_rs_code = 0,
		.nd_rs_cksum = 0,
		.nd_rs_reserved = 0,
	};

	if (iface->router_event.uloop.fd < 0)
		return;

	memset(&all_routers, 0, sizeof(all_routers));
	all_routers.sin6_family = AF_INET6;
	all_routers.sin6_port = htons(IPPROTO_ICMPV6);
	inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &all_routers.sin6_addr);

	odhcpd_send(iface->router_event.uloop.fd, &all_routers,
			&(struct iovec){&rs, sizeof(rs)}, 1, iface);
}

/*
 * Timer callback: proactively solicit an RA from upstream on the master
 * interface. Repeated a few times (RFC 4861 MAX_RTR_SOLICITATIONS) to
 * survive a lost packet and to cover the case where the upstream link
 * only became usable shortly after we started.
 */
static void solicit_timer_cb(struct uloop_timeout *t)
{
	struct interface *iface = container_of(t, struct interface, timer_rs);

	if (!iface->master || iface->ra != MODE_RELAY ||
			iface->router_event.uloop.fd < 0)
		return;

	send_router_solicitation(iface);

	if (++iface->ra_sent < MAX_RTR_SOLICITATIONS)
		uloop_timeout_set(&iface->timer_rs, RTR_SOLICITATION_INTERVAL);
}

/* Forward router solicitation */
static void forward_router_solicitation(const struct interface *iface)
{
	struct interface *c;

	avl_for_each_element(&interfaces, c, avl) {
		if (c->ifindex == iface->ifindex || !c->master || c->ra != MODE_RELAY)
			continue;

		/* Must send on the destination interface's own socket, since
		 * each socket is bound (SO_BINDTODEVICE) to its own iface. */
		send_router_solicitation(c);
	}
}

/* Forward router advertisement */
static void forward_router_advertisement(const struct interface *iface, uint8_t *data, size_t len)
{
	struct interface *c;
	struct sockaddr_in6 all_nodes;

	memset(&all_nodes, 0, sizeof(all_nodes));
	all_nodes.sin6_family = AF_INET6;
	all_nodes.sin6_port = htons(IPPROTO_ICMPV6);
	inet_pton(AF_INET6, ALL_IPV6_NODES, &all_nodes.sin6_addr);

	avl_for_each_element(&interfaces, c, avl) {
		if (c->ifindex == iface->ifindex || c->master || c->ra != MODE_RELAY)
			continue;

		/* Must send on the destination interface's own socket, since
		 * each socket is bound (SO_BINDTODEVICE) to its own iface. */
		odhcpd_send(c->router_event.uloop.fd, &all_nodes,
				&(struct iovec){data, len}, 1, c);
	}
}

/* Handle ICMPv6 messages of the incoming socket */
static void handle_icmpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest)
{
	(void)addr;
	(void)dest;
	/*
	 * Raw AF_INET6/IPPROTO_ICMPV6 sockets deliver only the ICMPv6
	 * payload on receive - unlike IPv4 raw sockets, the IPv6 header is
	 * never prepended (RFC 3542 Section 3). "data" therefore already
	 * starts at the ICMPv6 header.
	 */
	struct icmp6_hdr *hdr = data;

	/* Ignore if too short to contain an ICMPv6 header */
	if (len < sizeof(*hdr))
		return;

	/* For relay mode, just forward RS and RA between interfaces */
	if (iface->ra == MODE_RELAY) {
		if (hdr->icmp6_type == ND_ROUTER_SOLICIT) {
			forward_router_solicitation(iface);
		} else if (hdr->icmp6_type == ND_ROUTER_ADVERT) {
			forward_router_advertisement(iface, data, len);
		}
	}
}

static void router_netevent_cb(unsigned long event, struct netevent_handler_info *info)
{
	if (event == NETEV_ADDR6_ADD || event == NETEV_ADDR6_DEL ||
	    event == NETEV_ADDRLIST_CHANGE) {
		struct interface *i;
		avl_for_each_element(&interfaces, i, avl) {
			ssize_t cnt = netlink_get_interface_addrs(i->ifindex, true, &i->addr6);
			if (cnt >= 0)
				i->addr6_len = cnt;
		}
	}
}