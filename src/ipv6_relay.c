/*
 * ipv6-relay - Lightweight IPv6 Relay Daemon
 * Copyright (C) 2026
 *
 * Based on odhcpd by Steven Barth
 * Licensed under GPLv2
 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <inttypes.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <linux/netlink.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/random.h>

#include "ipv6_relay.h"

static int ioctl_sock = -1;

struct config config = {
	.log_level = LOG_WARNING,
	.log_level_cmdline = false,
	.log_syslog = true,
	.config_file = NULL,
};

AVL_TREE(interfaces, avl_strcmp, false, NULL);

void __iflog(int lvl, const char *fmt, ...)
{
	va_list ap;

	if (lvl > config.log_level)
		return;

	va_start(ap, fmt);

	if (config.log_syslog) {
		vsyslog(lvl, fmt, ap);
	} else {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}

	va_end(ap);
}

_o_noreturn static void print_usage(const char *app, int exit_status)
{
	printf("== %s Usage ==\n"
	       "Lightweight IPv6 Relay Daemon (DHCPv6/RA/ND relay)\n\n"
	       "	-c <file>	Read JSON configuration from <file>\n"
	       "	-l <int>	Specify log level 0..7 (default %d)\n"
	       "	-f		Log to stderr instead of syslog\n"
	       "	-h		Print this help text and exit\n",
	       app, config.log_level);

	exit(exit_status);
}

static bool ipv6_enabled(void)
{
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (fd < 0)
		return false;

	close(fd);

	return true;
}

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "c:l:fh")) != -1) {
		switch (opt) {
		case 'c':
			free(config.config_file);
			config.config_file = strdup(optarg);
			break;

		case 'l':
			config.log_level = (atoi(optarg) & LOG_PRIMASK);
			config.log_level_cmdline = true;
			fprintf(stderr, "Log level set to %d\n", config.log_level);
			break;
		case 'f':
			config.log_syslog = false;
			fprintf(stderr, "Logging to stderr\n");
			break;
		case 'h':
			print_usage(argv[0], EXIT_SUCCESS);
		case '?':
		default:
			print_usage(argv[0], EXIT_FAILURE);
		}
	}

	if (getuid() != 0) {
		error("Must be run as root!");
		return 2;
	}

	if (!config.config_file) {
		error("No configuration file specified. Use -c <file>");
		return 2;
	}

	if (config.log_syslog) {
		openlog("ipv6-relay", LOG_PERROR | LOG_PID, LOG_DAEMON);
		setlogmask(LOG_UPTO(config.log_level));
	}

	uloop_init();

	ioctl_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ioctl_sock < 0)
		return 4;

	if (netlink_init())
		return 4;

	if (ipv6_enabled()) {
		if (router_init())
			return 4;

		if (dhcpv6_init())
			return 4;

		if (ndp_init())
			return 4;
	} else {
		error("IPv6 is not enabled on this system");
		return 4;
	}

	return odhcpd_run();
}

/* Read IPv6 config for interface */
int odhcpd_get_interface_config(const char *ifname, const char *what)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "/proc/sys/net/ipv6/conf/%s/%s", ifname, what);

	int fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -1;

	ssize_t len = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (len < 0)
		return -1;

	buf[len] = 0;
	return atoi(buf);
}

/* Read MAC for interface */
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6])
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name) - 1);
	if (ioctl(ioctl_sock, SIOCGIFHWADDR, &ifr) < 0)
		return -1;

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

int odhcpd_get_flags(const struct interface *iface)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name) - 1);
	if (ioctl(ioctl_sock, SIOCGIFFLAGS, &ifr) < 0)
		return -1;

	return ifr.ifr_flags;
}

/* Forwards a packet on a specific interface with optional source address */
ssize_t odhcpd_send_with_src(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface, const struct in6_addr *src_addr)
{
	/* Construct headers */
	uint8_t cmsg_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
	struct msghdr msg = {
		.msg_name = (void *) dest,
		.msg_namelen = sizeof(*dest),
		.msg_iov = iov,
		.msg_iovlen = iov_len,
		.msg_control = cmsg_buf,
		.msg_controllen = sizeof(cmsg_buf),
		.msg_flags = 0
	};

	/* Set control data (define destination interface) */
	struct cmsghdr *chdr = CMSG_FIRSTHDR(&msg);
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_PKTINFO;
	chdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	struct in6_pktinfo *pktinfo = (struct in6_pktinfo*)CMSG_DATA(chdr);
	pktinfo->ipi6_ifindex = iface->ifindex;

	/* Set source address if provided */
	if (src_addr)
		pktinfo->ipi6_addr = *src_addr;

	/* Also set scope ID if link-local */
	if (IN6_IS_ADDR_LINKLOCAL(&dest->sin6_addr)
			|| IN6_IS_ADDR_MC_LINKLOCAL(&dest->sin6_addr))
		dest->sin6_scope_id = iface->ifindex;

	char ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &dest->sin6_addr, ipbuf, sizeof(ipbuf));

	ssize_t sent = sendmsg(socket, &msg, MSG_DONTWAIT);
	if (sent < 0)
		error("Failed to send to %s%%%s@%s (%m)",
		      ipbuf, iface->name, iface->ifname);
	else
		debug("Sent %zd bytes to %s%%%s@%s",
		      sent, ipbuf, iface->name, iface->ifname);
	return sent;
}

/* Forwards a packet on a specific interface */
ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface)
{
	return odhcpd_send_with_src(socket, dest, iov, iov_len, iface, NULL);
}

int odhcpd_get_interface_linklocal_addr(struct interface *iface, struct in6_addr *addr)
{
	/* Return cached address if valid */
	if (iface->cached_linklocal_valid) {
		*addr = iface->cached_linklocal_addr;
		return 0;
	}

	/* First try to get link-local address from interface addresses */
	for (size_t i = 0; i < iface->addr6_len; ++i) {
		if (IN6_IS_ADDR_LINKLOCAL(&iface->addr6[i].addr.in6)) {
			*addr = iface->addr6[i].addr.in6;
			/* Cache the result for future use */
			iface->cached_linklocal_addr = *addr;
			iface->cached_linklocal_valid = true;
			return 0;
		}
	}

	/* Fallback to socket-based method */
	struct sockaddr_in6 sockaddr;
	socklen_t alen = sizeof(sockaddr);
	int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

	if (sock >= 0) {
		memset(&sockaddr, 0, sizeof(sockaddr));
		sockaddr.sin6_family = AF_INET6;
		inet_pton(AF_INET6, ALL_IPV6_ROUTERS, &sockaddr.sin6_addr);
		sockaddr.sin6_scope_id = iface->ifindex;

		if (!connect(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) &&
				!getsockname(sock, (struct sockaddr*)&sockaddr, &alen)) {
			*addr = sockaddr.sin6_addr;
			/* Cache the result for future use */
			iface->cached_linklocal_addr = *addr;
			iface->cached_linklocal_valid = true;
			close(sock);
			return 0;
		}
		close(sock);
	}

	return -1;
}

/* Try to send with link-local source address for RFC 4861 compliance */
ssize_t odhcpd_try_send_with_src(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		struct interface *iface)
{
	struct in6_addr src_addr;

	if (iface->ndp_from_link_local && odhcpd_get_interface_linklocal_addr(iface, &src_addr) == 0) {
		return odhcpd_send_with_src(socket, dest, iov, iov_len, iface, &src_addr);
	} else {
		return odhcpd_send(socket, dest, iov, iov_len, iface);
	}
}

struct interface* odhcpd_get_interface_by_index(int ifindex)
{
	struct interface *iface;

	avl_for_each_element(&interfaces, iface, avl) {
		if (iface->ifindex == ifindex)
			return iface;
	}

	return NULL;
}

/* Convenience function to receive and do basic validation of packets */
static void odhcpd_receive_packets(struct uloop_fd *u, _o_unused unsigned int events)
{
	struct odhcpd_event *e = container_of(u, struct odhcpd_event, uloop);

	uint8_t data_buf[8192], cmsg_buf[128];
	union {
		struct sockaddr_in6 in6;
		struct sockaddr_nl nl;
	} addr;

	if (u->error) {
		int ret = -1;
		socklen_t ret_len = sizeof(ret);

		u->error = false;
		if (e->handle_error && getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &ret, &ret_len) == 0)
			e->handle_error(e, ret);
	}

	if (e->recv_msgs) {
		e->recv_msgs(e);
		return;
	}

	while (true) {
		struct iovec iov = {data_buf, sizeof(data_buf)};
		struct msghdr msg = {
			.msg_name = (void *) &addr,
			.msg_namelen = sizeof(addr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmsg_buf,
			.msg_controllen = sizeof(cmsg_buf),
			.msg_flags = 0
		};

		ssize_t len = recvmsg(u->fd, &msg, MSG_DONTWAIT);
		if (len < 0) {
			if (errno == EAGAIN)
				break;
			else
				continue;
		}

		/* Extract destination interface */
		int destiface = 0;
		int *hlim = NULL;
		void *dest = NULL;
		struct in6_pktinfo *pktinfo;

		for (struct cmsghdr *ch = CMSG_FIRSTHDR(&msg); ch != NULL; ch = CMSG_NXTHDR(&msg, ch)) {
			if (ch->cmsg_level == IPPROTO_IPV6 &&
					ch->cmsg_type == IPV6_PKTINFO) {
				pktinfo = (struct in6_pktinfo*)CMSG_DATA(ch);
				destiface = pktinfo->ipi6_ifindex;
				dest = &pktinfo->ipi6_addr;
			} else if (ch->cmsg_level == IPPROTO_IPV6 &&
					ch->cmsg_type == IPV6_HOPLIMIT) {
				hlim = (int*)CMSG_DATA(ch);
			}
		}

		/* Check hoplimit if received */
		if (hlim && *hlim != 255)
			continue;

		/* From netlink */
		if (addr.nl.nl_family == AF_NETLINK) {
			debug("Received %zd Bytes from netlink", len);
			e->handle_dgram(&addr, data_buf, len, NULL, dest);
			return;
		} else if (destiface != 0) {
			struct interface *iface;

			avl_for_each_element(&interfaces, iface, avl) {
				if (iface->ifindex != destiface)
					continue;

				debug("Received %zd Bytes from %s%%%s@%s", len,
				      "ipv6", iface->name, iface->ifname);

				e->handle_dgram(&addr, data_buf, len, iface, dest);
			}
		}
	}
}

/* Register events for the multiplexer */
int odhcpd_register(struct odhcpd_event *event)
{
	event->uloop.cb = odhcpd_receive_packets;
	return uloop_fd_add(&event->uloop, ULOOP_READ |
			((event->handle_error) ? ULOOP_ERROR_CB : 0));
}

int odhcpd_deregister(struct odhcpd_event *event)
{
	event->uloop.cb = NULL;
	return uloop_fd_delete(&event->uloop);
}

void odhcpd_process(struct odhcpd_event *event)
{
	odhcpd_receive_packets(&event->uloop, 0);
}

void odhcpd_urandom(void *data, size_t len)
{
	static bool warned_once = false;

	while (true) {
		ssize_t r;

		if (len == 0)
			return;

		r = getrandom(data, len, GRND_INSECURE);
		if (r < 0) {
			if (errno == EINTR)
				continue;

			if (!warned_once) {
				error("getrandom(): %m");
				warned_once = true;
			}

			return;
		}

		len -= r;
		data = (uint8_t *)data + r;
	}
}

time_t odhcpd_time(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
	return ts.tv_sec;
}

static const char hexdigits[] = "0123456789abcdef";
static const int8_t hexvals[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

ssize_t odhcpd_unhexlify(uint8_t *dst, size_t len, const char *src)
{
	size_t c;
	for (c = 0; c < len && src[0] && src[1]; ++c) {
		int8_t x = (int8_t)*src++;
		int8_t y = (int8_t)*src++;
		if (x < 0 || (x = hexvals[x]) < 0
				|| y < 0 || (y = hexvals[y]) < 0)
			return -1;
		dst[c] = x << 4 | y;
		while (((int8_t)*src) < 0 ||
				(*src && hexvals[(uint8_t)*src] < 0))
			src++;
	}

	return c;
}

void odhcpd_hexlify(char *dst, const uint8_t *src, size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		*dst++ = hexdigits[src[i] >> 4];
		*dst++ = hexdigits[src[i] & 0x0f];
	}
	*dst = 0;
}

const char *odhcpd_print_mac(const uint8_t *mac, const size_t len)
{
	static char buf[32];

	snprintf(buf, sizeof(buf), "%02x", mac[0]);
	for (size_t i = 1, j = 2; i < len && j < sizeof(buf); i++, j += 3)
		snprintf(buf + j, sizeof(buf) - j, ":%02x", mac[i]);

	return buf;
}

int odhcpd_bmemcmp(const void *av, const void *bv, size_t bits)
{
	const uint8_t *a = av, *b = bv;
	size_t bytes = bits / 8;
	bits %= 8;

	int res = memcmp(a, b, bytes);
	if (res == 0 && bits > 0)
		res = (a[bytes] >> (8 - bits)) - (b[bytes] >> (8 - bits));

	return res;
}

void odhcpd_bmemcpy(void *av, const void *bv, size_t bits)
{
	uint8_t *a = av;
	const uint8_t *b = bv;

	size_t bytes = bits / 8;
	bits %= 8;
	memcpy(a, b, bytes);

	if (bits > 0) {
		uint8_t mask = (1 << (8 - bits)) - 1;
		a[bytes] = (a[bytes] & mask) | ((~mask) & b[bytes]);
	}
}

static void signal_reload(_o_unused struct uloop_signal *signal)
{
	odhcpd_reload();
}

int odhcpd_run(void)
{
	static struct uloop_signal sighup = { .signo = SIGHUP, .cb = signal_reload };

	odhcpd_reload();

	/* uloop_init() already handles SIGINT/SIGTERM */
	if (uloop_signal_add(&sighup) < 0)
		return EXIT_FAILURE;

	uloop_run();

	return EXIT_SUCCESS;
}
