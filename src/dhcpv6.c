/*
 * ipv6-relay - Lightweight IPv6 Relay Daemon
 * Copyright (C) 2026
 *
 * Based on odhcpd by Steven Barth
 * Licensed under GPLv2
 */

#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <arpa/inet.h>

#include "ipv6_relay.h"
#include "dhcpv6.h"

static void relay_client_request(struct sockaddr_in6 *source,
		const void *data, size_t len, struct interface *iface,
		struct in6_addr *dest);
static void relay_server_response(uint8_t *data, size_t len);

static void handle_dhcpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest_addr);

/* Create socket and register events */
int dhcpv6_init(void)
{
	return 0;
}

int dhcpv6_setup_interface(struct interface *iface, bool enable)
{
	int ret = 0;

	enable = enable && (iface->dhcpv6 != MODE_DISABLED);

	if (iface->dhcpv6_event.uloop.fd >= 0) {
		uloop_fd_delete(&iface->dhcpv6_event.uloop);
		close(iface->dhcpv6_event.uloop.fd);
		iface->dhcpv6_event.uloop.fd = -1;
	}

	/* Configure multicast settings */
	if (enable) {
		struct sockaddr_in6 bind_addr = {AF_INET6, htons(DHCPV6_SERVER_PORT),
					0, IN6ADDR_ANY_INIT, 0};
		struct ipv6_mreq mreq;
		int val = 1;

		iface->dhcpv6_event.uloop.fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
		if (iface->dhcpv6_event.uloop.fd < 0) {
			error("socket(AF_INET6): %m");
			ret = -1;
			goto out;
		}

		/* Basic IPv6 configuration */
		if (setsockopt(iface->dhcpv6_event.uloop.fd, SOL_SOCKET, SO_BINDTODEVICE,
					iface->ifname, strlen(iface->ifname)) < 0) {
			error("setsockopt(SO_BINDTODEVICE): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_V6ONLY,
					&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_V6ONLY): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv6_event.uloop.fd, SOL_SOCKET, SO_REUSEADDR,
					&val, sizeof(val)) < 0) {
			error("setsockopt(SO_REUSEADDR): %m");
			ret = -1;
			goto out;
		}

		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
					&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_RECVPKTINFO): %m");
			ret = -1;
			goto out;
		}

		val = DHCPV6_HOP_COUNT_LIMIT;
		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
					&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_MULTICAST_HOPS): %m");
			ret = -1;
			goto out;
		}

		val = 0;
		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
					&val, sizeof(val)) < 0) {
			error("setsockopt(IPV6_MULTICAST_LOOP): %m");
			ret = -1;
			goto out;
		}

		if (bind(iface->dhcpv6_event.uloop.fd, (struct sockaddr*)&bind_addr,
					sizeof(bind_addr)) < 0) {
			error("bind(): %m");
			ret = -1;
			goto out;
		}

		memset(&mreq, 0, sizeof(mreq));
		inet_pton(AF_INET6, ALL_DHCPV6_RELAYS, &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = iface->ifindex;

		if (setsockopt(iface->dhcpv6_event.uloop.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
					&mreq, sizeof(mreq)) < 0) {
			error("setsockopt(IPV6_ADD_MEMBERSHIP): %m");
			ret = -1;
			goto out;
		}

		iface->dhcpv6_event.handle_dgram = handle_dhcpv6;
		odhcpd_register(&iface->dhcpv6_event);
	}

out:
	if (ret < 0 && iface->dhcpv6_event.uloop.fd >= 0) {
		close(iface->dhcpv6_event.uloop.fd);
		iface->dhcpv6_event.uloop.fd = -1;
	}

	return ret;
}

/* Central DHCPv6-relay handler */
static void handle_dhcpv6(void *addr, void *data, size_t len,
		struct interface *iface, void *dest_addr)
{
	(void)dest_addr;

	if (iface->dhcpv6 == MODE_RELAY) {
		if (iface->master)
			relay_server_response(data, len);
		else
			relay_client_request(addr, data, len, iface, NULL);
	}
}

/* Relay server response (regular relay server handling) */
static void relay_server_response(uint8_t *data, size_t len)
{
	/* Information we need to gather */
	uint8_t *payload_data = NULL;
	size_t payload_len = 0;
	int32_t ifaceidx = 0;
	struct sockaddr_in6 target = {AF_INET6, htons(DHCPV6_CLIENT_PORT),
		0, IN6ADDR_ANY_INIT, 0};
	uint16_t otype, olen;
	uint8_t *odata, *end = data + len;
	/* Relay DHCPv6 reply from server to client */
	struct dhcpv6_relay_header *h = (void*)data;

	debug("Got a DHCPv6-relay-reply");

	if (len < sizeof(*h) || h->msg_type != DHCPV6_MSG_RELAY_REPL)
		return;

	memcpy(&target.sin6_addr, &h->peer_address, sizeof(struct in6_addr));

	/* Go through options and find what we need */
	dhcpv6_for_each_option(h->options, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_INTERFACE_ID
				&& olen == sizeof(ifaceidx)) {
			memcpy(&ifaceidx, odata, sizeof(ifaceidx));
		} else if (otype == DHCPV6_OPT_RELAY_MSG) {
			payload_data = odata;
			payload_len = olen;
		}
	}

	/* Invalid interface-id or basic payload */
	struct interface *iface = odhcpd_get_interface_by_index(ifaceidx);
	if (!iface || iface->master || !payload_data || payload_len < 4)
		return;

	/* If the payload is relay-reply we have to send to the server port */
	if (payload_data[0] == DHCPV6_MSG_RELAY_REPL)
		target.sin6_port = htons(DHCPV6_SERVER_PORT);

	struct iovec iov = {payload_data, payload_len};

	debug("Sending a DHCPv6-reply on %s", iface->name);

	odhcpd_send(iface->dhcpv6_event.uloop.fd, &target, &iov, 1, iface);
}

static struct odhcpd_ipaddr *relay_link_address(struct interface *iface)
{
	struct odhcpd_ipaddr *addr = NULL;
	time_t now = odhcpd_time();

	for (size_t i = 0; i < iface->addr6_len; i++) {
		if (iface->addr6[i].valid_lt <= (uint32_t)now)
			continue;

		if (iface->addr6[i].preferred_lt > (uint32_t)now) {
			addr = &iface->addr6[i];
			break;
		}

		if (!addr || (iface->addr6[i].valid_lt > addr->valid_lt))
			addr = &iface->addr6[i];
	}

	return addr;
}

/* Relay client request (regular DHCPv6-relay) */
static void relay_client_request(struct sockaddr_in6 *source,
		const void *data, size_t len, struct interface *iface,
		struct in6_addr *dest)
{
	const struct dhcpv6_relay_header *h = data;
	/* Construct our forwarding envelope */
	struct dhcpv6_relay_forward_envelope hdr = {
		.msg_type = DHCPV6_MSG_RELAY_FORW,
		.hop_count = 0,
		.interface_id_type = htons(DHCPV6_OPT_INTERFACE_ID),
		.interface_id_len = htons(sizeof(uint32_t)),
		.relay_message_type = htons(DHCPV6_OPT_RELAY_MSG),
		.relay_message_len = htons(len),
	};
	struct iovec iov[2] = {{&hdr, sizeof(hdr)}, {(void *)data, len}};
	struct interface *c;
	struct odhcpd_ipaddr *ip;
	struct sockaddr_in6 s;

	if (len < offsetof(struct dhcpv6_relay_header, link_address))
		return;

	switch (h->msg_type) {
	/* Valid message types from clients */
	case DHCPV6_MSG_SOLICIT:
	case DHCPV6_MSG_REQUEST:
	case DHCPV6_MSG_CONFIRM:
	case DHCPV6_MSG_RENEW:
	case DHCPV6_MSG_REBIND:
	case DHCPV6_MSG_RELEASE:
	case DHCPV6_MSG_DECLINE:
	case DHCPV6_MSG_INFORMATION_REQUEST:
	case DHCPV6_MSG_RELAY_FORW:
		break;
	/* Invalid message types from clients i.e. server messages */
	case DHCPV6_MSG_ADVERTISE:
	case DHCPV6_MSG_REPLY:
	case DHCPV6_MSG_RECONFIGURE:
	case DHCPV6_MSG_RELAY_REPL:
		return;
	default:
		break;
	}

	debug("Got a DHCPv6-request on %s", iface->name);

	if (h->msg_type == DHCPV6_MSG_RELAY_FORW) { /* handle relay-forward */
		if (h->hop_count >= DHCPV6_HOP_COUNT_LIMIT)
			return; /* Invalid hop count */

		hdr.hop_count = h->hop_count + 1;
	}

	/* use memcpy here as the destination fields are unaligned */
	memcpy(&hdr.peer_address, &source->sin6_addr, sizeof(struct in6_addr));
	memcpy(&hdr.interface_id_data, &iface->ifindex, sizeof(iface->ifindex));

	/* Detect public IP of slave interface to use as link-address */
	ip = relay_link_address(iface);
	if (ip)
		memcpy(&hdr.link_address, &ip->addr.in6, sizeof(hdr.link_address));

	memset(&s, 0, sizeof(s));
	s.sin6_family = AF_INET6;
	s.sin6_port = htons(DHCPV6_SERVER_PORT);

	if (dest)
		s.sin6_addr = *dest;
	else
		inet_pton(AF_INET6, ALL_DHCPV6_SERVERS, &s.sin6_addr);

	avl_for_each_element(&interfaces, c, avl) {
		if (!c->master || c->dhcpv6 != MODE_RELAY)
			continue;

		if (!ip) {
			/* No suitable address! Is the slave not configured yet?
			 * Detect public IP of master interface and use it instead
			 * This is WRONG and probably violates the RFC. However
			 * otherwise we have a hen and egg problem because the
			 * slave-interface cannot be auto-configured. */
			ip = relay_link_address(c);
			if (!ip)
				continue; /* Could not obtain a suitable address */

			memcpy(&hdr.link_address, &ip->addr.in6, sizeof(hdr.link_address));
			ip = NULL;
		}

		debug("Sending a DHCPv6-relay-forward on %s", c->name);

		odhcpd_send(c->dhcpv6_event.uloop.fd, &s, iov, 2, c);
	}
}