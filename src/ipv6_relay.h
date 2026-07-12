/*
 * ipv6-relay - Lightweight IPv6 Relay Daemon
 * Copyright (C) 2026
 *
 * Based on odhcpd by Steven Barth
 * Licensed under GPLv2
 */

#ifndef _IPV6_RELAY_H_
#define _IPV6_RELAY_H_

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdbool.h>
#include <syslog.h>
#include <json-c/json.h>

#include "compat.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define ND_OPT_ROUTE_INFO 24
#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNS_SEARCH 31

#define ALL_IPV6_NODES "ff02::1"
#define ALL_IPV6_ROUTERS "ff02::2"
#define ALL_DHCPV6_RELAYS "ff02::1:2"
#define ALL_DHCPV6_SERVERS "ff05::1:3"

#ifndef IN6ADDR_LINKLOCAL_ALLNODES_INIT
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT {{{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}}}
#endif

#define DHCPV6_SERVER_PORT 547
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_HOP_COUNT_LIMIT 32

#define INFINITE_VALID(x) ((x) == 0)

#ifndef _o_fallthrough
#define _o_fallthrough __attribute__((__fallthrough__))
#endif

#ifndef _o_packed
#define _o_packed __attribute__((packed))
#endif

#ifndef _o_unused
#define _o_unused __attribute__((unused))
#endif

#ifndef _o_noreturn
#define _o_noreturn __attribute__((__noreturn__))
#endif

struct interface;

extern struct config config;

void __iflog(int lvl, const char *fmt, ...);
#define debug(fmt, ...) __iflog(LOG_DEBUG, fmt __VA_OPT__(, ) __VA_ARGS__)
#define info(fmt, ...) __iflog(LOG_INFO, fmt __VA_OPT__(, ) __VA_ARGS__)
#define notice(fmt, ...) __iflog(LOG_NOTICE, fmt __VA_OPT__(, ) __VA_ARGS__)
#define warn(fmt, ...) __iflog(LOG_WARNING, fmt __VA_OPT__(, ) __VA_ARGS__)
#define error(fmt, ...) __iflog(LOG_ERR, fmt __VA_OPT__(, ) __VA_ARGS__)

struct odhcpd_event {
	struct uloop_fd uloop;
	void (*handle_dgram)(void *addr, void *data, size_t len,
			struct interface *iface, void *dest_addr);
	void (*handle_error)(struct odhcpd_event *e, int error);
	void (*recv_msgs)(struct odhcpd_event *e);
};

union in46_addr {
	struct in_addr in;
	struct in6_addr in6;
};

struct netevent_handler_info {
	struct interface *iface;
	union {
		struct {
			union in46_addr dst;
			uint8_t dst_len;
			union in46_addr gateway;
		} rt;
		struct {
			union in46_addr dst;
			uint16_t state;
			uint8_t flags;
		} neigh;
		struct {
			struct odhcpd_ipaddr *addrs;
			size_t len;
		} addrs_old;
		union in46_addr addr;
	};
};

enum netevents {
	NETEV_IFINDEX_CHANGE,
	NETEV_ADDR_ADD,
	NETEV_ADDR_DEL,
	NETEV_ADDRLIST_CHANGE,
	NETEV_ADDR6_ADD,
	NETEV_ADDR6_DEL,
	NETEV_ADDR6LIST_CHANGE,
	NETEV_ROUTE6_ADD,
	NETEV_ROUTE6_DEL,
	NETEV_NEIGH6_ADD,
	NETEV_NEIGH6_DEL,
};

struct netevent_handler {
	struct list_head head;
	void (*cb) (unsigned long event, struct netevent_handler_info *info);
};

struct odhcpd_ipaddr {
	union in46_addr addr;
	uint8_t prefix_len;
	uint32_t preferred_lt;
	uint32_t valid_lt;

	struct {
		uint8_t dprefix_len;
		bool tentative;
	};
};

enum odhcpd_mode {
	MODE_DISABLED,
	MODE_RELAY,
};

struct config {
	int log_level;
	bool log_level_cmdline;
	bool log_syslog;
	char *config_file;
};

struct interface {
	struct avl_node avl;

	int ifflags;
	int ifindex;
	char *ifname;
	const char *name;
	bool external;
	bool master;

	// IPv6 runtime data
	struct odhcpd_ipaddr *addr6;
	size_t addr6_len;

	// RA runtime data
	struct odhcpd_event router_event;
	struct uloop_timeout timer_rs;
	uint32_t ra_sent;

	// DHCPv6 runtime data
	struct odhcpd_event dhcpv6_event;

	// NDP runtime data
	struct odhcpd_event ndp_event;
	int ndp_ping_fd;

	// Services
	enum odhcpd_mode ra;
	enum odhcpd_mode dhcpv6;
	enum odhcpd_mode ndp;

	// Config
	bool inuse;
	bool ignore;
	bool ndp_from_link_local;
	struct in6_addr cached_linklocal_addr;
	bool cached_linklocal_valid;
	int learn_routes;
	bool have_link_local;

	char *upstream;
	size_t upstream_len;
};

extern struct avl_tree interfaces;

// Exported main functions
int odhcpd_register(struct odhcpd_event *event);
int odhcpd_deregister(struct odhcpd_event *event);
void odhcpd_process(struct odhcpd_event *event);

ssize_t odhcpd_send_with_src(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface, const struct in6_addr *src_addr);
ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface);
ssize_t odhcpd_try_send_with_src(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		struct interface *iface);
int odhcpd_get_interface_linklocal_addr(struct interface *iface,
		struct in6_addr *addr);
int odhcpd_get_interface_config(const char *ifname, const char *what);
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6]);
int odhcpd_get_flags(const struct interface *iface);
struct interface* odhcpd_get_interface_by_index(int ifindex);
void odhcpd_urandom(void *data, size_t len);

int odhcpd_run(void);
time_t odhcpd_time(void);
ssize_t odhcpd_unhexlify(uint8_t *dst, size_t len, const char *src);
void odhcpd_hexlify(char *dst, const uint8_t *src, size_t len);
const char *odhcpd_print_mac(const uint8_t *mac, const size_t len);

int odhcpd_bmemcmp(const void *av, const void *bv, size_t bits);
void odhcpd_bmemcpy(void *av, const void *bv, size_t bits);

int netlink_add_netevent_handler(struct netevent_handler *hdlr);
ssize_t netlink_get_interface_addrs(const int ifindex, bool v6,
				    struct odhcpd_ipaddr **oaddrs);
ssize_t netlink_get_interface_linklocal(int ifindex, struct odhcpd_ipaddr **oaddrs);
int netlink_get_interface_proxy_neigh(int ifindex, const struct in6_addr *addr);
int netlink_setup_route(const struct in6_addr *addr, const int prefixlen,
			const int ifindex, const struct in6_addr *gw,
			const uint32_t metric, const bool add);
int netlink_setup_proxy_neigh(const struct in6_addr *addr,
			      const int ifindex, const bool add);
int netlink_setup_addr(struct odhcpd_ipaddr *oaddr,
		       const int ifindex, const bool v6, const bool add);
void netlink_dump_neigh_table(const bool proxy);
void netlink_dump_addr_table(const bool v6);

// Exported module initializers
int netlink_init(void);
int router_init(void);
int dhcpv6_init(void);
int ndp_init(void);

int router_setup_interface(struct interface *iface, bool enable);
int dhcpv6_setup_interface(struct interface *iface, bool enable);
int ndp_setup_interface(struct interface *iface, bool enable);
void reload_services(struct interface *iface);

void odhcpd_reload(void);

// JSON config parsing
int config_parse_interface_json(const char *name, struct json_object *obj);
void config_load_json(const char *path);

#endif /* _IPV6_RELAY_H_ */