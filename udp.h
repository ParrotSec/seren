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

#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define UDP_PACKET_MAXLEN 4096

struct udp_packet {
	struct sockaddr_in addr;
	uint8_t            data[UDP_PACKET_MAXLEN];
	size_t             len;
};

int  resolve_address(struct sockaddr_in *addr, const char *host, uint16_t port, const int *verbose);
void udp_send_packet(int sockfd, const struct udp_packet *udp_packet);
void udp_receive_packet(int sockfd, struct udp_packet *udp_packet);

#endif
