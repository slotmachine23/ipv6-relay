/*
 * ipv6-relay - Lightweight IPv6 Relay Daemon
 * Copyright (C) 2026
 *
 * Based on odhcpd by Steven Barth
 * Licensed under GPLv2
 */

#include <errno.h>
#include <string.h>

#include <linux/netlink.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>

#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/attr.h>

#include <arpa/inet.h>

#include "ipv6_relay.h"

struct event_socket {
	struct odhcpd_event ev;
	struct nl_sock *sock;
	int sock_bufsize;
};

static void handle_rtnl_event(struct odhcpd_event *ev);
static int cb_rtnl_valid(struct nl_msg *msg, void *arg);
static void catch_rtnl_err(struct odhcpd_event *e, int error);
static struct nl_sock *create_socket(int protocol);

static struct nl_sock *rtnl_socket = NULL;
struct list_head netevent_handler_list = LIST_HEAD_INIT(netevent_handler_list);
static struct event_socket rtnl_event = {
	.ev = {
		.uloop = {.fd = - 1, },
		.handle_dgram = NULL,
		.handle_error = catch_rtnl_err,
		.recv_msgs = handle_rtnl_event,
	},
	.sock = NULL,
	.sock_bufsize = 133120,
};

/* Shut down and free netlink sockets/registration. Safe to call multiple times. */
static void netlink_shutdown(void)
{
	/* Deregister event and free the event socket */
	if (rtnl_event.sock) {
		odhcpd_deregister(&rtnl_event.ev);

		if (rtnl_event.ev.uloop.fd >= 0) {
			close(rtnl_event.ev.uloop.fd);
			rtnl_event.ev.uloop.fd = -1;
		}

		nl_socket_free(rtnl_event.sock);
		rtnl_event.sock = NULL;
	}

	/* Free the primary rtnl socket */
	if (rtnl_socket) {
		nl_socket_free(rtnl_socket);
		rtnl_socket = NULL;
	}
}

int netlink_init(void)
{
	rtnl_socket = create_socket(NETLINK_ROUTE);
	if (!rtnl_socket) {
		error("Unable to open nl socket: %m");
		goto err;
	}

	rtnl_event.sock = create_socket(NETLINK_ROUTE);
	if (!rtnl_event.sock) {
		error("Unable to open nl event socket: %m");
		goto err;
	}

	rtnl_event.ev.uloop.fd = nl_socket_get_fd(rtnl_event.sock);

	if (nl_socket_set_buffer_size(rtnl_event.sock, rtnl_event.sock_bufsize, 0))
		goto err;

	nl_socket_disable_seq_check(rtnl_event.sock);

	nl_socket_modify_cb(rtnl_event.sock, NL_CB_VALID, NL_CB_CUSTOM,
			cb_rtnl_valid, NULL);

	/* Receive IPv6 address, IPv6 routes and neighbor events */
	if (nl_socket_add_memberships(rtnl_event.sock,
				RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_ROUTE,
				RTNLGRP_NEIGH, RTNLGRP_LINK, 0))
		goto err;

	odhcpd_register(&rtnl_event.ev);

	atexit(netlink_shutdown);

	return 0;

err:
	netlink_shutdown();

	return -1;
}


int netlink_add_netevent_handler(struct netevent_handler *handler)
{
	if (!handler->cb)
		return -1;

	list_add(&handler->head, &netevent_handler_list);

	return 0;
}

static void call_netevent_handler_list(unsigned long event, struct netevent_handler_info *info)
{
	struct netevent_handler *handler;

	list_for_each_entry(handler, &netevent_handler_list, head)
		handler->cb(event, info);
}

static void handle_rtnl_event(struct odhcpd_event *e)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	nl_recvmsgs_default(ev_sock->sock);
}

static void refresh_iface_addr6(int ifindex)
{
	struct odhcpd_ipaddr *oaddrs6 = NULL;
	struct interface *iface;
	ssize_t oaddrs6_cnt = netlink_get_interface_addrs(ifindex, true, &oaddrs6);
	time_t now = odhcpd_time();
	bool change = false;

	if (oaddrs6_cnt < 0)
		return;

	avl_for_each_element(&interfaces, iface, avl) {
		struct netevent_handler_info event_info;

		if (iface->ifindex != ifindex)
			continue;

		memset(&event_info, 0, sizeof(event_info));
		event_info.iface = iface;
		event_info.addrs_old.addrs = iface->addr6;
		event_info.addrs_old.len = iface->addr6_len;

		if (!change) {
			change = oaddrs6_cnt != (ssize_t)iface->addr6_len;
			for (ssize_t i = 0; !change && i < oaddrs6_cnt; ++i) {
				if (!IN6_ARE_ADDR_EQUAL(&oaddrs6[i].addr.in6, &iface->addr6[i].addr.in6) ||
				    oaddrs6[i].prefix_len != iface->addr6[i].prefix_len ||
				    (oaddrs6[i].preferred_lt > (uint32_t)now) != (iface->addr6[i].preferred_lt > (uint32_t)now) ||
				    oaddrs6[i].valid_lt < iface->addr6[i].valid_lt || oaddrs6[i].preferred_lt < iface->addr6[i].preferred_lt)
					change = true;
			}
		}

		iface->addr6 = oaddrs6;
		iface->addr6_len = oaddrs6_cnt;

		if (change)
			call_netevent_handler_list(NETEV_ADDR6LIST_CHANGE, &event_info);

		free(event_info.addrs_old.addrs);

		if (!oaddrs6_cnt)
			continue;

		oaddrs6 = malloc(oaddrs6_cnt * sizeof(*oaddrs6));
		if (!oaddrs6)
			break;

		memcpy(oaddrs6, iface->addr6, oaddrs6_cnt * sizeof(*oaddrs6));
	}

	free(oaddrs6);
}

static int handle_rtm_link(struct nlmsghdr *hdr)
{
	struct ifinfomsg *ifi = nlmsg_data(hdr);
	struct nlattr *nla[__IFLA_MAX];
	struct interface *iface;
	struct netevent_handler_info event_info;
	const char *ifname;

	memset(&event_info, 0, sizeof(event_info));

	if (!nlmsg_valid_hdr(hdr, sizeof(*ifi)) || ifi->ifi_family != AF_UNSPEC)
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);
	if (!nla[IFLA_IFNAME])
		return NL_SKIP;

	ifname = nla_get_string(nla[IFLA_IFNAME]);

	avl_for_each_element(&interfaces, iface, avl) {
		if (strcmp(iface->ifname, ifname))
			continue;

		if (iface->ifindex == ifi->ifi_index) {
			bool was_running = iface->ifflags & IFF_RUNNING;
			bool now_running = ifi->ifi_flags & IFF_RUNNING;

			iface->ifflags = ifi->ifi_flags;

			/*
			 * Only reload services when the RUNNING state actually
			 * toggled (a real carrier up/down), not on every link
			 * notification for this interface. Unrelated flag churn
			 * - notably IFF_ALLMULTI/IFF_PROMISC, which
			 * ndp_setup_interface() itself flips via
			 * PACKET_ADD_MEMBERSHIP/AF_PACKET every time it
			 * (re)opens the NDP capture socket - also generates a
			 * RTM_NEWLINK. Reacting to that here by unconditionally
			 * reloading would tear down and recreate the very socket
			 * that just caused the flag change, toggling it again and
			 * producing a self-sustaining reload loop: the NDP raw
			 * socket (and the proxy_ndp state, and the neighbor table
			 * dump) never gets a stable window to actually capture and
			 * relay Neighbor Solicitations, breaking NDP relay/proxy
			 * entirely.
			 */
			if (was_running != now_running)
				reload_services(iface);
			continue;
		}

		iface->ifflags = ifi->ifi_flags;
		iface->ifindex = ifi->ifi_index;
		event_info.iface = iface;
		call_netevent_handler_list(NETEV_IFINDEX_CHANGE, &event_info);
	}

	return NL_OK;
}

static int handle_rtm_route(struct nlmsghdr *hdr, bool add)
{
	struct rtmsg *rtm = nlmsg_data(hdr);
	struct nlattr *nla[__RTA_MAX];
	struct interface *iface;
	struct netevent_handler_info event_info;
	int ifindex = 0;

	if (!nlmsg_valid_hdr(hdr, sizeof(*rtm)) || rtm->rtm_family != AF_INET6)
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*rtm), nla, __RTA_MAX - 1, NULL);

	memset(&event_info, 0, sizeof(event_info));
	event_info.rt.dst_len = rtm->rtm_dst_len;

	if (nla[RTA_DST])
		nla_memcpy(&event_info.rt.dst, nla[RTA_DST],
				sizeof(event_info.rt.dst));

	if (nla[RTA_OIF])
		ifindex = nla_get_u32(nla[RTA_OIF]);

	if (nla[RTA_GATEWAY])
		nla_memcpy(&event_info.rt.gateway, nla[RTA_GATEWAY],
				sizeof(event_info.rt.gateway));

	avl_for_each_element(&interfaces, iface, avl) {
		if (ifindex && iface->ifindex != ifindex)
			continue;

		event_info.iface = ifindex ? iface : NULL;
		call_netevent_handler_list(add ? NETEV_ROUTE6_ADD : NETEV_ROUTE6_DEL,
						&event_info);
	}

	return NL_OK;
}

static int handle_rtm_addr(struct nlmsghdr *hdr, bool add)
{
	struct ifaddrmsg *ifa = nlmsg_data(hdr);
	struct nlattr *nla[__IFA_MAX];
	struct interface *iface;
	struct netevent_handler_info event_info;
	char buf[INET6_ADDRSTRLEN];

	if (!nlmsg_valid_hdr(hdr, sizeof(*ifa)) ||
			ifa->ifa_family != AF_INET6)
		return NL_SKIP;

	memset(&event_info, 0, sizeof(event_info));

	nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);

	if (!nla[IFA_ADDRESS])
		return NL_SKIP;

	nla_memcpy(&event_info.addr, nla[IFA_ADDRESS], sizeof(event_info.addr));

	if (IN6_IS_ADDR_MULTICAST(&event_info.addr))
		return NL_SKIP;

	inet_ntop(AF_INET6, &event_info.addr, buf, sizeof(buf));

	avl_for_each_element(&interfaces, iface, avl) {
		if (iface->ifindex != (int)ifa->ifa_index)
			continue;

		if (add && IN6_IS_ADDR_LINKLOCAL(&event_info.addr)) {
			iface->have_link_local = true;
			return NL_SKIP;
		}

		debug("Netlink %s %s on %s", add ? "newaddr" : "deladdr",
		      buf, iface->name);

		event_info.iface = iface;
		call_netevent_handler_list(add ? NETEV_ADDR6_ADD : NETEV_ADDR6_DEL,
						&event_info);
	}

	refresh_iface_addr6(ifa->ifa_index);

	return NL_OK;
}

static int handle_rtm_neigh(struct nlmsghdr *hdr, bool add)
{
	struct ndmsg *ndm = nlmsg_data(hdr);
	struct nlattr *nla[__NDA_MAX];
	struct interface *iface;
	struct netevent_handler_info event_info;
	char buf[INET6_ADDRSTRLEN];

	if (!nlmsg_valid_hdr(hdr, sizeof(*ndm)) ||
			ndm->ndm_family != AF_INET6)
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ndm), nla, __NDA_MAX - 1, NULL);

	memset(&event_info, 0, sizeof(event_info));

	struct nlattr *nla_addr = nlmsg_find_attr(hdr, sizeof(*ndm), NDA_DST);

	if (nla_addr)
		nla_memcpy(&event_info.neigh.dst, nla_addr, sizeof(event_info.neigh.dst));

	if (!nla_addr || IN6_IS_ADDR_LINKLOCAL(&event_info.neigh.dst) ||
			IN6_IS_ADDR_MULTICAST(&event_info.neigh.dst))
		return NL_SKIP;

	inet_ntop(AF_INET6, &event_info.neigh.dst, buf, sizeof(buf));

	avl_for_each_element(&interfaces, iface, avl) {
		if (iface->ifindex != ndm->ndm_ifindex)
			continue;

		debug("Netlink %s %s on %s", add ? "newneigh" : "delneigh",
		      buf, iface->name);

		event_info.iface = iface;
		event_info.neigh.state = ndm->ndm_state;
		event_info.neigh.flags = ndm->ndm_flags;

		call_netevent_handler_list(add ? NETEV_NEIGH6_ADD : NETEV_NEIGH6_DEL,
						&event_info);
	}

	return NL_OK;
}

/* Handler for neighbor cache entries from the kernel. */
static int cb_rtnl_valid(struct nl_msg *msg, _o_unused void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	int ret = NL_SKIP;
	bool add = false;

	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
		ret = handle_rtm_link(hdr);
		break;

	case RTM_NEWROUTE:
		add = true;
		_o_fallthrough;
	case RTM_DELROUTE:
		ret = handle_rtm_route(hdr, add);
		break;

	case RTM_NEWADDR:
		add = true;
		_o_fallthrough;
	case RTM_DELADDR:
		ret = handle_rtm_addr(hdr, add);
		break;

	case RTM_NEWNEIGH:
		add = true;
		_o_fallthrough;
	case RTM_DELNEIGH:
		ret = handle_rtm_neigh(hdr, add);
		break;

	default:
		break;
	}

	return ret;
}

static void catch_rtnl_err(struct odhcpd_event *e, int error)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	if (error != ENOBUFS)
		goto err;

	/* Double netlink event buffer size */
	ev_sock->sock_bufsize *= 2;

	if (nl_socket_set_buffer_size(ev_sock->sock, ev_sock->sock_bufsize, 0))
		goto err;

	netlink_dump_addr_table(true);
	return;

err:
	odhcpd_deregister(e);
}

static struct nl_sock *create_socket(int protocol)
{
	struct nl_sock *nl_sock;

	nl_sock = nl_socket_alloc();
	if (!nl_sock)
		goto err;

	if (nl_connect(nl_sock, protocol) < 0)
		goto err;

	return nl_sock;

err:
	if (nl_sock)
		nl_socket_free(nl_sock);

	return NULL;
}


struct addr_info {
	int ifindex;
	int af;
	struct odhcpd_ipaddr **oaddrs;
	bool pending;
	ssize_t ret;
};


static int cb_addr_valid(struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;
	struct odhcpd_ipaddr *oaddrs;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ifaddrmsg *ifa;
	struct nlattr *nla[__IFA_MAX], *nla_addr = NULL;

	if (hdr->nlmsg_type != RTM_NEWADDR)
		return NL_SKIP;

	ifa = NLMSG_DATA(hdr);
	if (ifa->ifa_scope != RT_SCOPE_UNIVERSE ||
			(ctxt->af != ifa->ifa_family) ||
			(ctxt->ifindex && ifa->ifa_index != (unsigned)ctxt->ifindex))
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);

	switch (ifa->ifa_family) {
	case AF_INET6:
		if (nla[IFA_ADDRESS])
			nla_addr = nla[IFA_ADDRESS];
		break;

	default:
		break;
	}
	if (!nla_addr)
		return NL_SKIP;

	oaddrs = realloc(*(ctxt->oaddrs), sizeof(*oaddrs) * (ctxt->ret + 1));
	if (!oaddrs)
		return NL_SKIP;

	memset(&oaddrs[ctxt->ret], 0, sizeof(oaddrs[ctxt->ret]));
        oaddrs[ctxt->ret].prefix_len = ifa->ifa_prefixlen;

	nla_memcpy(&oaddrs[ctxt->ret].addr, nla_addr, sizeof(oaddrs[ctxt->ret].addr));

	if (nla[IFA_CACHEINFO]) {
		struct ifa_cacheinfo *ifc = nla_data(nla[IFA_CACHEINFO]);

		oaddrs[ctxt->ret].preferred_lt = ifc->ifa_prefered;
		oaddrs[ctxt->ret].valid_lt = ifc->ifa_valid;
	}

	if (ifa->ifa_flags & IFA_F_DEPRECATED)
		oaddrs[ctxt->ret].preferred_lt = 0;

	if (ifa->ifa_flags & IFA_F_TENTATIVE)
		oaddrs[ctxt->ret].tentative = true;

	ctxt->ret++;
	*(ctxt->oaddrs) = oaddrs;

	return NL_OK;
}


static int cb_addr_finish(_o_unused struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = false;

	return NL_STOP;
}


static int cb_addr_error(_o_unused struct sockaddr_nl *nla, struct nlmsgerr *err,
		void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = false;
	ctxt->ret = err->error;

	return NL_STOP;
}


/* compare IPv6 prefixes */
static int prefix6_cmp(const void *va, const void *vb)
{
	const struct odhcpd_ipaddr *a = va, *b = vb;
	uint32_t a_pref_lt = a->preferred_lt;
	uint32_t b_pref_lt = b->preferred_lt;
	return (a_pref_lt < b_pref_lt) ? 1 : (a_pref_lt > b_pref_lt) ? -1 : 0;
}


/* Detect all IPv6 addresses currently assigned to the given interface */
ssize_t netlink_get_interface_addrs(int ifindex, bool v6, struct odhcpd_ipaddr **oaddrs)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = AF_INET6,
		.ifa_prefixlen = 0,
		.ifa_flags = 0,
		.ifa_scope = 0,
		.ifa_index = ifindex,
	};
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct addr_info ctxt = {
		.ifindex = ifindex,
		.af = AF_INET6,
		.oaddrs = oaddrs,
		.ret = 0,
		.pending = true,
	};

	if (!cb) {
		ctxt.ret = -1;
		goto out;
	}

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);

	if (!msg) {
		ctxt.ret = - 1;
		goto out;
	}

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_addr_valid, &ctxt);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_addr_finish, &ctxt);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_addr_error, &ctxt);

	ctxt.ret = nl_send_auto_complete(rtnl_socket, msg);
	if (ctxt.ret < 0)
		goto free;

	ctxt.ret = 0;
	while (ctxt.pending)
		nl_recvmsgs(rtnl_socket, cb);

	if (ctxt.ret <= 0)
		goto free;

	time_t now = odhcpd_time();
	struct odhcpd_ipaddr *oaddr = *oaddrs;

	qsort(oaddr, ctxt.ret, sizeof(*oaddr), prefix6_cmp);

	for (ssize_t i = 0; i < ctxt.ret; ++i) {
		if (oaddr[i].preferred_lt < UINT32_MAX - now)
			oaddr[i].preferred_lt += now;

		if (oaddr[i].valid_lt < UINT32_MAX - now)
			oaddr[i].valid_lt += now;
	}

free:
	nlmsg_free(msg);
out:
	nl_cb_put(cb);

	return ctxt.ret;
}


static int cb_linklocal_valid(struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;
	struct odhcpd_ipaddr *oaddrs;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ifaddrmsg *ifa;
	struct nlattr *nla[__IFA_MAX], *nla_addr = NULL;
	struct in6_addr addr;

	if (hdr->nlmsg_type != RTM_NEWADDR)
		return NL_SKIP;

	ifa = NLMSG_DATA(hdr);
	if (ifa->ifa_scope != RT_SCOPE_LINK ||
			(ctxt->af != ifa->ifa_family) ||
			(ctxt->ifindex && ifa->ifa_index != (unsigned)ctxt->ifindex))
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);

	switch (ifa->ifa_family) {
	case AF_INET6:
		if (nla[IFA_ADDRESS])
			nla_addr = nla[IFA_ADDRESS];
		break;

	default:
		break;
	}
	if (!nla_addr)
		return NL_SKIP;

	nla_memcpy(&addr, nla_addr, sizeof(addr));

	if (!IN6_IS_ADDR_LINKLOCAL(&addr))
		return NL_SKIP;

	/* oaddrs may be NULL when the caller only wants a count */
	if (ctxt->oaddrs) {
		oaddrs = realloc(*(ctxt->oaddrs), sizeof(*oaddrs) * (ctxt->ret + 1));
		if (!oaddrs)
			return NL_SKIP;

		memset(&oaddrs[ctxt->ret], 0, sizeof(oaddrs[ctxt->ret]));
		memcpy(&oaddrs[ctxt->ret].addr, &addr, sizeof(oaddrs[ctxt->ret].addr));

		if (ifa->ifa_flags & IFA_F_TENTATIVE)
			oaddrs[ctxt->ret].tentative = true;

		*(ctxt->oaddrs) = oaddrs;
	}

	ctxt->ret++;

	return NL_OK;
}


static int cb_linklocal_finish(_o_unused struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = false;

	return NL_STOP;
}


static int cb_linklocal_error(_o_unused struct sockaddr_nl *nla, struct nlmsgerr *err,
		void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = false;
	ctxt->ret = err->error;

	return NL_STOP;
}


/* Detect link-local IPv6-addresses currently assigned to the given interface */
ssize_t netlink_get_interface_linklocal(int ifindex, struct odhcpd_ipaddr **oaddrs)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = AF_INET6,
		.ifa_prefixlen = 0,
		.ifa_flags = 0,
		.ifa_scope = 0,
		.ifa_index = ifindex,
	};
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct addr_info ctxt = {
		.ifindex = ifindex,
		.af = AF_INET6,
		.oaddrs = oaddrs,
		.ret = 0,
		.pending = true,
	};

	if (!cb) {
		ctxt.ret = -1;
		goto out;
	}

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);

	if (!msg) {
		ctxt.ret = - 1;
		goto out;
	}

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_linklocal_valid, &ctxt);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_linklocal_finish, &ctxt);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_linklocal_error, &ctxt);

	ctxt.ret = nl_send_auto_complete(rtnl_socket, msg);
	if (ctxt.ret < 0)
		goto free;

	ctxt.ret = 0;
	while (ctxt.pending)
		nl_recvmsgs(rtnl_socket, cb);

	if (ctxt.ret <= 0)
		goto free;

free:
	nlmsg_free(msg);
out:
	nl_cb_put(cb);

	return ctxt.ret;
}


struct neigh_info {
	int ifindex;
	bool pending;
	const struct in6_addr *addr;
	int ret;
};


static int cb_proxy_neigh_valid(struct nl_msg *msg, void *arg)
{
	struct neigh_info *ctxt = (struct neigh_info *)arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ndmsg *ndm;
	struct nlattr *nla_dst;

	if (hdr->nlmsg_type != RTM_NEWNEIGH)
		return NL_SKIP;

	ndm = NLMSG_DATA(hdr);
	if (ndm->ndm_family != AF_INET6 ||
			(ctxt->ifindex && ndm->ndm_ifindex != ctxt->ifindex))
		return NL_SKIP;

	if (!(ndm->ndm_flags & NTF_PROXY))
		return NL_SKIP;

	nla_dst = nlmsg_find_attr(hdr, sizeof(*ndm), NDA_DST);
	if (!nla_dst)
		return NL_SKIP;

	if (nla_memcmp(nla_dst,ctxt->addr, 16) == 0)
		ctxt->ret = 1;

	return NL_OK;
}


static int cb_proxy_neigh_finish(_o_unused struct nl_msg *msg, void *arg)
{
	struct neigh_info *ctxt = (struct neigh_info *)arg;

	ctxt->pending = false;

	return NL_STOP;
}


static int cb_proxy_neigh_error(_o_unused struct sockaddr_nl *nla, struct nlmsgerr *err,
		void *arg)
{
	struct neigh_info *ctxt = (struct neigh_info *)arg;

	ctxt->pending = false;
	ctxt->ret = err->error;

	return NL_STOP;
}

/* Detect an IPV6-address proxy neighbor for the given interface */
int netlink_get_interface_proxy_neigh(int ifindex, const struct in6_addr *addr)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = NTF_PROXY,
		.ndm_ifindex = ifindex,
	};
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct neigh_info ctxt = {
		.ifindex = ifindex,
		.addr = addr,
		.ret = 0,
		.pending = true,
	};

	if (!cb) {
		ctxt.ret = -1;
		goto out;
	}

	msg = nlmsg_alloc_simple(RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_MATCH);

	if (!msg) {
		ctxt.ret = -1;
		goto out;
	}

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);
	nla_put(msg, NDA_DST, sizeof(*addr), addr);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_proxy_neigh_valid, &ctxt);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_proxy_neigh_finish, &ctxt);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_proxy_neigh_error, &ctxt);

	ctxt.ret = nl_send_auto_complete(rtnl_socket, msg);
	if (ctxt.ret < 0)
		goto free;

	while (ctxt.pending)
		nl_recvmsgs(rtnl_socket, cb);

free:
	nlmsg_free(msg);
out:
	nl_cb_put(cb);

	return ctxt.ret;
}


int netlink_setup_route(const struct in6_addr *addr, const int prefixlen,
		const int ifindex, const struct in6_addr *gw,
		const uint32_t metric, const bool add)
{
	struct nl_msg *msg;
	struct rtmsg rtm = {
		.rtm_family = AF_INET6,
		.rtm_dst_len = prefixlen,
		.rtm_src_len = 0,
		.rtm_table = RT_TABLE_MAIN,
		.rtm_protocol = (add ? RTPROT_STATIC : RTPROT_UNSPEC),
		.rtm_scope = (add ? (gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK) : RT_SCOPE_NOWHERE),
		.rtm_type = (add ? RTN_UNICAST : RTN_UNSPEC),
	};
	int ret = 0;

	msg = nlmsg_alloc_simple(add ? RTM_NEWROUTE : RTM_DELROUTE,
					add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
	if (!msg)
		return -1;

	nlmsg_append(msg, &rtm, sizeof(rtm), 0);

	nla_put(msg, RTA_DST, sizeof(*addr), addr);
	nla_put_u32(msg, RTA_OIF, ifindex);
	nla_put_u32(msg, RTA_PRIORITY, metric);

	if (gw)
		nla_put(msg, RTA_GATEWAY, sizeof(*gw), gw);

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}


int netlink_setup_proxy_neigh(const struct in6_addr *addr,
		const int ifindex, const bool add)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = NTF_PROXY,
		.ndm_ifindex = ifindex,
	};
	int ret = 0, flags = NLM_F_REQUEST;

	if (add)
		flags |= NLM_F_REPLACE | NLM_F_CREATE;

	msg = nlmsg_alloc_simple(add ? RTM_NEWNEIGH : RTM_DELNEIGH, flags);
	if (!msg)
		return -1;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	nla_put(msg, NDA_DST, sizeof(*addr), addr);

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}


int netlink_setup_addr(struct odhcpd_ipaddr *oaddr,
		       const int ifindex, const bool v6, const bool add)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = v6 ? AF_INET6 : AF_INET,
		.ifa_prefixlen = oaddr->prefix_len,
		.ifa_flags = 0,
		.ifa_scope = 0,
		.ifa_index = ifindex,
	};
	int ret = 0, flags = NLM_F_REQUEST;

	if (add)
		flags |= NLM_F_REPLACE | NLM_F_CREATE;

	msg = nlmsg_alloc_simple(add ? RTM_NEWADDR : RTM_DELADDR, 0);
	if (!msg)
		return -1;

	nlmsg_append(msg, &ifa, sizeof(ifa), flags);
	nla_put(msg, IFA_LOCAL, v6 ? 16 : 4, &oaddr->addr);
	if (v6) {
		struct ifa_cacheinfo cinfo = {
			.ifa_prefered = 0xffffffffU,
			.ifa_valid = 0xffffffffU,
			.cstamp = 0,
			.tstamp = 0,
		};
		time_t now = odhcpd_time();

		if (oaddr->preferred_lt) {
			int64_t preferred_lt = oaddr->preferred_lt - now;
			if (preferred_lt < 0)
				preferred_lt = 0;
			else if (preferred_lt > UINT32_MAX)
				preferred_lt = UINT32_MAX;

			cinfo.ifa_prefered = preferred_lt;
		}

		if (oaddr->valid_lt) {
			int64_t valid_lt = oaddr->valid_lt - now;
			if (valid_lt <= 0) {
				nlmsg_free(msg);
				return -1;
			}
			else if (valid_lt > UINT32_MAX)
				valid_lt = UINT32_MAX;

			cinfo.ifa_valid = valid_lt;
		}

		nla_put(msg, IFA_CACHEINFO, sizeof(cinfo), &cinfo);

		nla_put_u32(msg, IFA_FLAGS, IFA_F_NOPREFIXROUTE);
	}

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}

void netlink_dump_neigh_table(const bool proxy)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = proxy ? NTF_PROXY : 0,
	};

	msg = nlmsg_alloc_simple(RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg)
		return;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	nl_send_auto_complete(rtnl_event.sock, msg);

	nlmsg_free(msg);
}

void netlink_dump_addr_table(const bool v6)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = v6 ? AF_INET6 : AF_INET,
	};

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg)
		return;

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	nl_send_auto_complete(rtnl_event.sock, msg);

	nlmsg_free(msg);
}