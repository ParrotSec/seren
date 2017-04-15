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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "udp.h"
#include "common.h"
#include "msgbook.h"

int resolve_address(struct sockaddr_in *addr, const char *host, uint16_t port, const int *verbose)
{
	struct hostent *hostinfo = NULL;
	char **ppchar;
	size_t l;

	snprintf(msgbuf, MBS, "Resolving '%s'...", host);
	msgbook_enqueue(&mb0, MB_TYPE_INFO, "resolve", msgbuf);

	/* let's see if we already have a valid ip address */
	if (inet_aton(host, &addr->sin_addr)) {
		snprintf(msgbuf, MBS, "Host: %s", host);
	} else {
		/* get host info */
		hostinfo = gethostbyname(host);
		if (!hostinfo) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, "resolve", "Cannot resolve host");
			return -1;
		}
		if (hostinfo->h_addrtype == AF_INET6) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, "resolve", "AF_INET6 not supported");
			return -1;
		}

		/* print host info */
		snprintf(msgbuf, MBS, "Name: %s", hostinfo->h_name);
#if 0
		l = strlen(msgbuf);
		snprintf(msgbuf+l, MBS-l, ", Aliases: [");
		for (ppchar = hostinfo->h_aliases; *ppchar; ppchar++) {
			l = strlen(msgbuf);
			snprintf(msgbuf+l, MBS-l, " %s", *ppchar);
		}
		l = strlen(msgbuf);
		snprintf(msgbuf+l, MBS-l, " ], Type: %s", hostinfo->h_addrtype == AF_INET ? "AF_INET" : "AF_INET6");
#endif
		l = strlen(msgbuf);
		snprintf(msgbuf+l, MBS-l, ", Address list: [");
		for (ppchar = hostinfo->h_addr_list; *ppchar; ppchar++) {
			l = strlen(msgbuf);
			snprintf(msgbuf+l, MBS-l, " %s", inet_ntoa(*(struct in_addr *)*ppchar) );
		}
		l = strlen(msgbuf);
		snprintf(msgbuf+l, MBS-l, " ]");
	}

	l = strlen(msgbuf);
	snprintf(msgbuf+l, MBS-l, ", Port: %hu", port);
	if (*verbose)
		msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, "resolve", msgbuf);

	/* fill in address */
	addr->sin_family   = AF_INET;
	if (hostinfo)
		addr->sin_addr = *(struct in_addr *) *hostinfo->h_addr_list;
	addr->sin_port     = htons(port);

	return 0;
}

void udp_send_packet(int sockfd, const struct udp_packet *udp_packet)
{
	ssize_t nw;

	nw = sendto(sockfd, udp_packet->data, udp_packet->len, 0,
		        (const struct sockaddr *)&udp_packet->addr, sizeof(udp_packet->addr));
	if (nw == -1) {
		snprintf(msgbuf, MBS, "sendto(): %s", strerror(errno));
		die(msgbuf, 1);
	}
	if ((size_t)nw < udp_packet->len) {
		snprintf(msgbuf, MBS, "sendto() returned %zd, expected %zd", nw, udp_packet->len);
		msgbook_enqueue(&mb0, MB_TYPE_WARNING, "udp", msgbuf);
	}
}

void udp_receive_packet(int sockfd, struct udp_packet *udp_packet)
{
	ssize_t   nr;
	socklen_t addr_len;

	udp_packet->len = UDP_PACKET_MAXLEN;
	addr_len = sizeof(udp_packet->addr);
	nr = recvfrom(sockfd, udp_packet->data, udp_packet->len, 0,
		          (struct sockaddr *)&udp_packet->addr, &addr_len);
	if (nr == -1) {
		snprintf(msgbuf, MBS, "recvfrom(): %s", strerror(errno));
		udp_packet->len = 0;
		die(msgbuf, 1);
	}
	if (nr == UDP_PACKET_MAXLEN) {
		snprintf(msgbuf, MBS, "recvfrom() returned UDP_PACKET_MAXLEN (%zd), you may want to increase this value", nr);
		msgbook_enqueue(&mb0, MB_TYPE_WARNING, "udp", msgbuf);
	}

	udp_packet->len = (size_t)nr;
}
