/*
 * Copyright (C) 2013, 2014 Giorgio Vazzana
 *
 * This file is part of Seren.
 *
 * Seren is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Seren is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* rfc: http://tools.ietf.org/html/rfc5389 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "stun.h"
#include "rw.h"
#include "udp.h"
#include "msgbook.h"

static const char *stun_host[] = {
	"stun.ekiga.net", /* stun.ekiga.net -> stun.voipbuster.com */
	"stunserver.org",
	"stun.sipgate.net",
	"numb.viagenie.ca",
	"stun.stunprotocol.org",
	NULL };

static const uint16_t stun_port = 3478;

char *stun_get_external_ip(const int *verbose)
{
	int ret, i, sockfd;
	struct timeval timeout;
//	struct sockaddr_in addr;
	socklen_t addr_len;
	ssize_t nr;
	struct udp_packet udp_packet;
	uint8_t *d;
	size_t   l;
	uint16_t htype, hlength;
	uint32_t magic_cookie;
	uint32_t transaction_ID[3];
	int got_ip = 0;
	static char external_ip[16];

	/* fill in remote address */
	msgbook_enqueue(&mb0, MB_TYPE_INFO, "stun", "Using STUN to get external IP address");
	ret = resolve_address(&udp_packet.addr, stun_host[0], stun_port, verbose);
	if (ret == -1)
		goto fail;

	/* create socket */
	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		snprintf(msgbuf, MBS, "socket(): %s", strerror(errno));
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, "stun", msgbuf);
		goto fail;
	}
#if 0
	/* name socket (bind it to local_port) */
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port        = htons(LOCAL_PORT);
	ret = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		snprintf(msgbuf, MBS, "bind(): %s", strerror(errno));
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, "stun", msgbuf);
		goto fail;
	}
#endif
	/* set the timeout */
	timeout.tv_sec  = 2;
	timeout.tv_usec = 0;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (ret == -1) {
		snprintf(msgbuf, MBS, "setsockopt(): %s", strerror(errno));
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, "stun", msgbuf);
		goto fail;
	}

	/* try up to two times */
	for (i = 0; i < 2; i++) {
		/* create stun packet */
		d = udp_packet.data;
		l = 0;
		write_be16(d, 0x0001);           d+=2; l+=2; /* stun message type: method=binding, class=request */
		write_be16(d, 0x0000);           d+=2; l+=2; /* message length */
		write_be32(d, 0x2112A442);       d+=4; l+=4; /* magic cookie */
		write_be32(d, (uint32_t)rand()); d+=4; l+=4; /* transaction id, 96 bit */
		write_be32(d, (uint32_t)rand()); d+=4; l+=4; /* transaction id, 96 bit */
		write_be32(d, (uint32_t)rand()); d+=4; l+=4; /* transaction id, 96 bit */
		udp_packet.len = l;

		/* send stun packet */
		if (*verbose) {
			snprintf(msgbuf, MBS, "Sending stun message: method=binding, class=request (try %d)", i);
			msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, "stun", msgbuf);
		}
		udp_send_packet(sockfd, &udp_packet);

		/* receive packet */
		if (*verbose)
			msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, "stun", "Waiting for a reply...");
		udp_packet.len = UDP_PACKET_MAXLEN;
		addr_len = sizeof(udp_packet.addr);
		nr = recvfrom(sockfd, udp_packet.data, udp_packet.len, 0,
				      (struct sockaddr *)&udp_packet.addr, &addr_len);
		if (nr == -1) {
			if (errno == EAGAIN)
				strncpy(msgbuf, "receive timeout", MBS);
			else
				snprintf(msgbuf, MBS, "recvfrom(): %s", strerror(errno));
			msgbook_enqueue(&mb0, MB_TYPE_WARNING, "stun", msgbuf);
			if (i == 0)
				continue;
			else
				goto fail;
		}
		udp_packet.len = (size_t)nr;
		if (*verbose)
			msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, "stun", "Response packet received!");
		break;
	}

	/* extract info */
	d = udp_packet.data;
	l = udp_packet.len;
	htype             = read_be16(d); d+=2; l-=2;
	hlength           = read_be16(d); d+=2; l-=2;
	magic_cookie      = read_be32(d); d+=4; l-=4;
	transaction_ID[0] = read_be32(d); d+=4; l-=4;
	transaction_ID[1] = read_be32(d); d+=4; l-=4;
	transaction_ID[2] = read_be32(d); d+=4; l-=4;

	if (*verbose >= 2) {
		snprintf(msgbuf, MBS, "Header: type=0x%04x, length=0x%04x, magic_cookie|transaction_ID=0x%08x|%08x%08x%08x",
			     htype, hlength, magic_cookie, transaction_ID[0], transaction_ID[1], transaction_ID[2]);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, "stun", msgbuf);
	}

	while (l > 0) {
		uint16_t type, length;

		type   = read_be16(d); d+=2; l-=2;
		length = read_be16(d); d+=2; l-=2;
		if (*verbose >= 2) {
			snprintf(msgbuf, MBS, "  Attribute: type=0x%04x, length=0x%04x", type, length);
			msgbook_enqueue(&mb0, MB_TYPE_DEBUG, "stun", msgbuf);
		}

		if (type == 0x0001) {
			uint16_t family, port;
			struct in_addr a = { 0 };

			family = read_be16(d);
			port   = read_be16(d+2);
			if (family == 0x01)
				a.s_addr = htonl(read_be32(d+4));

			if (*verbose >= 2) {
				snprintf(msgbuf, MBS, "    MAPPED-ADDRESS: family=0x%04x, port=%hu, address=%s", family, port, inet_ntoa(a));
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, "stun", msgbuf);
			}

			if (!got_ip) {
				strcpy(external_ip, inet_ntoa(a));
				got_ip = 1;
			}
		} else if (type == 0x0020 || type == 0x8020) {
			uint16_t family, port;
			struct in_addr a = { 0 };

			family = read_be16(d);
			port   = read_be16(d+2) ^ 0x2112;
			if (family == 0x01)
				a.s_addr = htonl(read_be32(d+4) ^ 0x2112A442);

			if (*verbose >= 2) {
				snprintf(msgbuf, MBS, "    XOR-MAPPED-ADDRESS: family=0x%04x, port=%hu, address=%s", family, port, inet_ntoa(a));
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, "stun", msgbuf);
			}

			if (!got_ip) {
				strcpy(external_ip, inet_ntoa(a));
				got_ip = 1;
			}
		}

		while (length % 4 != 0)
			length++;

		d+=length; l-=length;
	}

	close(sockfd);

	if (got_ip) {
		snprintf(msgbuf, MBS, "External IP: %s", external_ip);
		msgbook_enqueue(&mb0, MB_TYPE_INFO, "stun", msgbuf);

		return external_ip;
	}

fail:
	msgbook_enqueue(&mb0, MB_TYPE_ERROR, "stun", "Failed to get external IP address");
	return NULL;
}
