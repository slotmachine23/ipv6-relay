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

static void forward_router_solicitation(const struct interface *iface);
static void forward_router_advertisement(const struct interface *iface, uint8_t *data, size_t len);

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
			inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &mreq.ipv6mr_multiaddr);
			if (setsockopt(iface->router_event.uloop.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
						&mreq, sizeof(mreq)) < 0) {
				error("setsockopt(IPV6_ADD_MEMBERSHIP): %m");
				ret = -1;
				goto out;
			}
		} else {
			inet_pton(AF_INET6, ALL_IPV6_NODES, &mreq.ipv6mr_multiaddr);
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

/* Forward router solicitation */
static void forward_router_solicitation(const struct interface *iface)
{
	struct interface *c;
	struct sockaddr_in6 all_routers;

	memset(&all_routers, 0, sizeof(all_routers));
	all_routers.sin6_family = AF_INET6;
	all_routers.sin6_port = htons(IPPROTO_ICMPV6);
	inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &all_routers.sin6_addr);

	avl_for_each_element(&interfaces, c, avl) {
		if (c->ifindex == iface->ifindex || !c->master || c->ra != MODE_RELAY)
			continue;

		odhcpd_send(iface->router_event.uloop.fd, &all_routers,
				&(struct iovec){NULL, 0}, 1, c);
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

		odhcpd_send(iface->router_event.uloop.fd, &all_nodes,
				&(struct iovec){data, len}, 1, c);
	}
}

/* Handle ICMPv6 messages of the incoming socket */
static void handle_icmpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest)
{
	(void)addr;
	(void)dest;
	struct ip6_hdr *ip6 = data;
	struct icmp6_hdr *hdr = (struct icmp6_hdr *)&ip6[1];

	/* Ignore if not ICMPv6 or wrong length */
	if (len < sizeof(*ip6) + sizeof(*hdr))
		return;

	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
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