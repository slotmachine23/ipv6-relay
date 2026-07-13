/*
 * ipv6-relay - Lightweight IPv6 Relay Daemon
 * Copyright (C) 2026
 *
 * Based on odhcpd by Steven Barth
 * Licensed under GPLv2
 */

#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

#include <json-c/json.h>

#include "ipv6_relay.h"


static void set_interface_defaults(struct interface *iface)
{
	/* This daemon only ever does relaying, so every interface listed in
	 * the config is fully relayed (RA + DHCPv6 + NDP) by default - there
	 * is no per-service "disabled" mode to configure anymore. */
	iface->ignore = false;
	iface->ra = MODE_RELAY;
	iface->dhcpv6 = MODE_RELAY;
	iface->ndp = MODE_RELAY;
	iface->learn_routes = 1;
	iface->ndp_from_link_local = true;
	iface->cached_linklocal_valid = false;
}

static void clean_interface(struct interface *iface)
{
	free(iface->upstream);
	memset(&iface->ra, 0, sizeof(*iface) - offsetof(struct interface, ra));
	set_interface_defaults(iface);
}

static void close_interface(struct interface *iface)
{
	avl_delete(&interfaces, &iface->avl);

	router_setup_interface(iface, false);
	dhcpv6_setup_interface(iface, false);
	ndp_setup_interface(iface, false);

	uloop_timeout_cancel(&iface->timer_rs);

	clean_interface(iface);
	free(iface->addr6);
	free(iface->ifname);
	free(iface);
}

int config_parse_interface_json(const char *name, struct json_object *obj)
{
	struct interface *iface;
	ssize_t oaddrs_cnt;
	bool get_addrs = false;
	const char *ifname = NULL;
	struct json_object *tmp;

	if (!name)
		return -1;

	iface = avl_find_element(&interfaces, name, iface, avl);
	if (!iface) {
		char *new_name;

		iface = calloc_a(sizeof(*iface), &new_name, strlen(name) + 1, NULL);
		if (!iface)
			return -1;

		iface->name = strcpy(new_name, name);
		iface->avl.key = iface->name;
		iface->router_event.uloop.fd = -1;
		iface->dhcpv6_event.uloop.fd = -1;
		iface->ndp_event.uloop.fd = -1;
		iface->ndp_ping_fd = -1;

		set_interface_defaults(iface);

		avl_insert(&interfaces, &iface->avl);
		get_addrs = true;
	}

	if (json_object_object_get_ex(obj, "ifname", &tmp))
		ifname = json_object_get_string(tmp);

	if (!iface->ifname && !ifname) {
		warn("Interface '%s' has no ifname configured", name);
		goto err;
	}

	if (ifname) {
		free(iface->ifname);
		iface->ifname = strdup(ifname);

		if (!iface->ifname)
			goto err;

		if (!iface->ifindex &&
			(iface->ifindex = if_nametoindex(iface->ifname)) <= 0)
			goto err;

		if ((iface->ifflags = odhcpd_get_flags(iface)) < 0)
			goto err;
	}

	if (get_addrs) {
		oaddrs_cnt = netlink_get_interface_addrs(iface->ifindex,
							 true, &iface->addr6);

		if (oaddrs_cnt > 0)
			iface->addr6_len = oaddrs_cnt;
	}

	ssize_t ll_cnt = netlink_get_interface_linklocal(iface->ifindex, NULL);
	if (ll_cnt > 0)
		iface->have_link_local = true;

	iface->inuse = true;

	/* ra/dhcpv6/ndp are no longer configurable per interface: this daemon
	 * only ever relays, so every interface listed here gets all three
	 * services enabled (see set_interface_defaults()). Only "master"
	 * (which side is the WAN/upstream) is still meaningful to set. */

	if (json_object_object_get_ex(obj, "master", &tmp))
		iface->master = json_object_get_boolean(tmp);

	if (json_object_object_get_ex(obj, "ndproxy_routing", &tmp))
		iface->learn_routes = json_object_get_boolean(tmp);

	if (json_object_object_get_ex(obj, "ndp_from_link_local", &tmp))
		iface->ndp_from_link_local = json_object_get_boolean(tmp);

	return 0;

err:
	close_interface(iface);
	return -1;
}

void config_load_json(const char *path)
{
	struct json_object *root, *interfaces_obj, *global_obj;
	struct json_object *tmp;

	root = json_object_from_file(path);
	if (!root) {
		error("Failed to parse JSON config from %s", path);
		return;
	}

	if (json_object_object_get_ex(root, "global", &global_obj)) {
		if (!config.log_level_cmdline &&
		    json_object_object_get_ex(global_obj, "log_level", &tmp)) {
			config.log_level = json_object_get_int(tmp) & LOG_PRIMASK;
			if (config.log_syslog)
				setlogmask(LOG_UPTO(config.log_level));
			notice("Log level set to %d", config.log_level);
		}
	}

	if (json_object_object_get_ex(root, "interfaces", &interfaces_obj)) {
		json_object_object_foreach(interfaces_obj, name, iface_obj) {
			config_parse_interface_json(name, iface_obj);
		}
	}

	json_object_put(root);
}

void reload_services(struct interface *iface)
{
	if (iface->ifflags & IFF_RUNNING) {
		debug("Enabling services with %s running", iface->ifname);
		router_setup_interface(iface, iface->ra != MODE_DISABLED);
		dhcpv6_setup_interface(iface, iface->dhcpv6 != MODE_DISABLED);
		ndp_setup_interface(iface, iface->ndp != MODE_DISABLED);
	} else {
		debug("Disabling services with %s not running", iface->ifname);
		router_setup_interface(iface, false);
		dhcpv6_setup_interface(iface, false);
		ndp_setup_interface(iface, false);
	}
}

void odhcpd_reload(void)
{
	struct interface *i, *tmp;

	avl_for_each_element(&interfaces, i, avl)
		clean_interface(i);

	config_load_json(config.config_file);

	bool any_dhcpv6_slave = false, any_ra_slave = false, any_ndp_slave = false;

	avl_for_each_element(&interfaces, i, avl) {
		if (i->master)
			continue;

		if (i->dhcpv6 == MODE_RELAY)
			any_dhcpv6_slave = true;

		if (i->ra == MODE_RELAY)
			any_ra_slave = true;

		if (i->ndp == MODE_RELAY)
			any_ndp_slave = true;
	}

	struct interface *master = NULL;

	avl_for_each_element(&interfaces, i, avl) {
		if (!i->master)
			continue;

		if (i->dhcpv6 == MODE_RELAY && !any_dhcpv6_slave)
			i->dhcpv6 = MODE_DISABLED;

		if (i->ra == MODE_RELAY && !any_ra_slave)
			i->ra = MODE_DISABLED;

		if (i->ndp == MODE_RELAY && !any_ndp_slave)
			i->ndp = MODE_DISABLED;

		if (i->dhcpv6 == MODE_RELAY || i->ra == MODE_RELAY || i->ndp == MODE_RELAY)
			master = i;
	}

	avl_for_each_element_safe(&interfaces, i, avl, tmp) {
		/*
		 * Only drop an interface here if it is no longer present in
		 * the (re)loaded config at all. An interface that is still
		 * configured but simply not IFF_RUNNING yet - e.g. at daemon
		 * startup, before the link has finished autonegotiating or
		 * before systemd-networkd/dhcp has brought it up, which on a
		 * fresh boot commonly races with this very reload - must stay
		 * registered so the RTM_NEWLINK handler in netlink.c can find
		 * and (re)enable it once it actually comes up.
		 *
		 * Previously this branch called close_interface() (avl_delete
		 * + free) for any not-yet-running interface, permanently
		 * forgetting it: handle_rtm_link() only ever updates an
		 * *existing* entry in the interfaces tree matched by ifname,
		 * so once the object was deleted a later carrier-up event had
		 * nothing to attach to and the interface was never revived -
		 * requiring a manual service restart to recover. This is what
		 * made the relay come up broken after every router reboot
		 * whenever "wan"/"lan" wasn't already running by the time
		 * ipv6-relay started (network.target does not wait for that).
		 *
		 * reload_services() already does the right thing regardless
		 * of link state: it enables the relay sockets when running
		 * and cleanly tears them down (fd == -1, sysctls off) when
		 * not, so calling it unconditionally here for every in-use
		 * interface is safe.
		 */
		if (i->inuse)
			reload_services(i);
		else
			close_interface(i);
	}
}