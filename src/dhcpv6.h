/**
 * Copyright (C) 2012 Steven Barth <steven@midlink.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _DHCPV6_H_
#define _DHCPV6_H_

#include "ipv6_relay.h"

#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

/* RFC8415 */
#define DHCPV6_MSG_SOLICIT 1
#define DHCPV6_MSG_ADVERTISE 2
#define DHCPV6_MSG_REQUEST 3
#define DHCPV6_MSG_CONFIRM 4
#define DHCPV6_MSG_RENEW 5
#define DHCPV6_MSG_REBIND 6
#define DHCPV6_MSG_REPLY 7
#define DHCPV6_MSG_RELEASE 8
#define DHCPV6_MSG_DECLINE 9
#define DHCPV6_MSG_RECONFIGURE 10
#define DHCPV6_MSG_INFORMATION_REQUEST 11
#define DHCPV6_MSG_RELAY_FORW 12
#define DHCPV6_MSG_RELAY_REPL 13

#define DHCPV6_OPT_CLIENTID 1
#define DHCPV6_OPT_SERVERID 2
#define DHCPV6_OPT_IA_NA 3
#define DHCPV6_OPT_IA_ADDR 5
#define DHCPV6_OPT_ORO 6
#define DHCPV6_OPT_STATUS 13
#define DHCPV6_OPT_RELAY_MSG 9
#define DHCPV6_OPT_AUTH 11
#define DHCPV6_OPT_INTERFACE_ID 18
#define DHCPV6_OPT_DNS_SERVERS 23
#define DHCPV6_OPT_DNS_DOMAIN 24
#define DHCPV6_OPT_IA_PD 25
#define DHCPV6_OPT_IA_PREFIX 26

#define DHCPV6_STATUS_OK 0
#define DHCPV6_STATUS_NOADDRSAVAIL 2
#define DHCPV6_STATUS_NOBINDING 3
#define DHCPV6_STATUS_NOTONLINK 4
#define DHCPV6_STATUS_USEMULTICAST 5
#define DHCPV6_STATUS_NOPREFIXAVAIL 6

#define DHCPV6_HOP_COUNT_LIMIT 32

struct dhcpv6_client_header {
	uint8_t msg_type;
	uint8_t transaction_id[3];
} _o_packed;

struct dhcpv6_relay_header {
	uint8_t msg_type;
	uint8_t hop_count;
	struct in6_addr link_address;
	struct in6_addr peer_address;
	uint8_t options[];
} _o_packed;

struct dhcpv6_relay_forward_envelope {
	uint8_t msg_type;
	uint8_t hop_count;
	struct in6_addr link_address;
	struct in6_addr peer_address;
	uint16_t interface_id_type;
	uint16_t interface_id_len;
	uint32_t interface_id_data;
	uint16_t relay_message_type;
	uint16_t relay_message_len;
} _o_packed;

#define dhcpv6_for_each_option(start, end, otype, olen, odata) \
	for (uint8_t *_o = (uint8_t*)(start); _o + 4 <= (end) && \
		((otype) = _o[0] << 8 | _o[1]) && ((odata) = (void*)&_o[4]) && \
		((olen) = _o[2] << 8 | _o[3]) + (odata) <= (end); \
		_o += 4 + (_o[2] << 8 | _o[3]))

#endif /* _DHCPV6_H_ */