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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "pc-engine.h"
#include "pc-engine-internal.h"
#include "common.h"
#include "msgbook.h"
#include "rw.h"
#include "adsp.h"
#include "random.h"
#include "xtea.h"
#include "cast-128.h"
#include "blowfish.h"
#include "camellia.h"
#include "twofish.h"
#include "recording.h"

#define MODULE "pc-engine"

const unsigned int samplerate  = 48000;
const unsigned int channels    = 2;

const char * const pc_algo_name[] = {
	"XTEA",
	"CAST5",
	"Blowfish",
	"Camellia",
	"Twofish"
};
unsigned int fd_idx_stdin;
unsigned int fd_idx_udpsocket;
unsigned int fd_idx_audiocapture;
unsigned int fd_idx_audioplayback;

static int is_same_addr(struct sockaddr_in a, struct sockaddr_in b)
{
	if (a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port)
		return 1;
	else
		return 0;
}


static struct pc_event *event_push(struct slist **events, enum pc_event_type type)
{
	struct pc_event *ev;

	ev = xcalloc(1, sizeof(*ev));
	ev->type = type;
	*events = slist_append(*events, ev);

	return ev;
}

#if 0
static void sendrecipe_delete(struct slist **sendrecipes, struct sockaddr_in addr)
{
	struct slist *p;

	p = *sendrecipes;
	while (p) {
		struct slist *pnext = p->next;
		struct pc_sendrecipe *sr = p->data;

		if (is_same_addr(addr, sr->addr)) {
			free(sr);
			*sendrecipes = slist_remove_element(*sendrecipes, p);
		}
		p = pnext;
	}
}
#endif

static struct pc_caller *caller_push(struct slist **callers, struct sockaddr_in addr, const char *nick,
                                     enum dhm_pgid pgid, enum pc_algo algo, size_t pklen, const uint8_t *pk)
{
	struct pc_caller *cl;

	cl = xcalloc(1, sizeof(*cl));
	cl->addr    = addr;
	memcpy(cl->nick, nick, NICKLEN);
	cl->pgid    = pgid;
	cl->algo    = algo;
	cl->pklen   = pklen;
	memcpy(cl->pk, pk, pklen);
	cl->timeout = 250; /* 5s */
	*callers = slist_append(*callers, cl);

	return cl;
}

static struct pc_caller *caller_is_present(struct slist *callers, struct sockaddr_in addr)
{
	struct slist *p;

	p = callers;
	while (p) {
		struct pc_caller *cl = p->data;

		if (is_same_addr(addr, cl->addr))
			return cl;

		p = p->next;
	}
	return NULL;
}


static unsigned int node_get_count(struct pc_node *nodes[])
{
	unsigned int i, n = 0;

	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (nodes[i])
			n++;
	}
	return n;
}

static int node_get_idx(struct pc_node *nodes[], struct sockaddr_in addr)
{
	int i;

	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (nodes[i] && is_same_addr(addr, nodes[i]->addr))
			return i;
	}
	return -1;
}

static void node_delete(struct pc_node *nodes[], int idx, int reason, struct pc_tone *tone, struct slist **events)
{
	struct pc_event *ev;
	struct slist *p;

	/* push event */
	ev = event_push(events, event_type_node_delete);
	ev->addr = nodes[idx]->addr;
	memcpy(ev->nick, nodes[idx]->nick, NICKLEN);
	ev->i = (reason == DELETE_REASON_TIMEOUT);

	tone->play = (tone->play > 10*ONE_OPUS_FRAME) ? tone->play : 10*ONE_OPUS_FRAME;

	/* destroy decoder state */
	opus_decoder_destroy(nodes[idx]->dec);

	/* free pcm opus frames */
	p = nodes[idx]->pcmframes;
	while (p) {
		struct slist *pnext = p->next;
		struct pc_pcmframe *pf = p->data;

		free(pf);
		nodes[idx]->pcmframes = slist_remove_element(nodes[idx]->pcmframes, p);
		p = pnext;
	}

	/* free secure data */
	dhm_clear(&nodes[idx]->dhm);
	free(nodes[idx]->cipher_ctx);

	free(nodes[idx]);
	nodes[idx] = NULL;
}

static int node_add(struct pc_node *nodes[], struct sockaddr_in addr, const char *nick, enum dhm_pgid pgid,
                    enum pc_algo algo, struct pc_tone *tone, struct slist **events)
{
	int i, idx, error;
	struct pc_event *ev;

	/* check if we have space for another node */
	idx = -1;
	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (nodes[i] == NULL) {
			idx = i;
			break;
		}
	}
	if (idx == -1) {
		snprintf(msgbuf, MBS, "Max node capacity reached (%d nodes)", MAX_NUMBER_OF_NODES);
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return -1;
	}

	/* allocate and clear memory for new node */
	nodes[idx] = xcalloc(1, sizeof(struct pc_node));

	/* set non-zero fields */
	nodes[idx]->addr                 = addr;
	if (nick)
		memcpy(nodes[idx]->nick, nick, NICKLEN);
	else
		memset(nodes[idx]->nick,    0, NICKLEN);
	nodes[idx]->timeout              = TIMEOUT;

	/* create decoder state */
	nodes[idx]->dec = opus_decoder_create((opus_int32)samplerate, (int)channels, &error);
	if (error != OPUS_OK) {
		free(nodes[idx]);
		nodes[idx] = NULL;
		snprintf(msgbuf, MBS, "opus error: %s", opus_strerror(error));
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return -1;
	}

	/* secure connection */
	nodes[idx]->pgid = pgid;
	dhm_init(&nodes[idx]->dhm, nodes[idx]->pgid);
	nodes[idx]->algo = algo;

	tone->play = (tone->play > 20*ONE_OPUS_FRAME) ? tone->play : 20*ONE_OPUS_FRAME;

	/* push event */
	ev = event_push(events, event_type_node_add);
	ev->addr = nodes[idx]->addr;
	memcpy(ev->nick, nodes[idx]->nick, NICKLEN);

	return idx;
}

static void node_setup_cipher_and_key(struct pc_node *node, const uint8_t *peer_pk, size_t peer_pklen)
{
	dhm_calc_secret(&node->dhm, peer_pk, peer_pklen);

	free(node->cipher_ctx);

	switch (node->algo) {
	case algo_xtea:
		node->cipher_ctx = xcalloc(1, sizeof(struct xtea_ctx));
		xtea_init(node->cipher_ctx, node->dhm.key128);
		break;
	case algo_cast128:
		node->cipher_ctx = xcalloc(1, sizeof(struct cast128_ctx));
		cast128_init(node->cipher_ctx, node->dhm.key128);
		break;
	case algo_blowfish:
		node->cipher_ctx = xcalloc(1, sizeof(struct blowfish_ctx));
		blowfish_init(node->cipher_ctx, node->dhm.key128, 128);
		break;
	case algo_camellia:
		node->cipher_ctx = xcalloc(1, sizeof(struct camellia_ctx));
		camellia_init(node->cipher_ctx, node->dhm.key128, 128);
		break;
	case algo_twofish:
		node->cipher_ctx = xcalloc(1, sizeof(struct twofish_ctx));
		twofish_init(node->cipher_ctx, node->dhm.key128, 128);
		break;
	}
}

static uint16_t mode_bits(enum pc_mode mode)
{
	switch (mode) {
	case mode_clear:
		return UDP_PACKET_MODE_CLEAR;
	case mode_secure:
		return UDP_PACKET_MODE_SECURE;
	case mode_psk:
		return UDP_PACKET_MODE_PSK;
	}
	return UDP_PACKET_MODE_RESERVED;
}

static void packet_call(struct udp_packet *udp_packet, enum pc_mode mode, const char *nick,
                        enum dhm_pgid pgid, enum pc_algo algo, size_t pklen, const uint8_t *pk)
{
	uint8_t *d;
	size_t   l;
	uint16_t header;

	d = udp_packet->data;
	l = 0;

	header = mode_bits(mode) | UDP_PACKET_FTYPE_CALL;
	write_be16(d, header);               d+=2; l+=2;
	*d = PC_ENGINE_VERSION_MAJOR;        d+=1; l+=1;
	*d = PC_ENGINE_VERSION_MINOR;        d+=1; l+=1;
	*d = PC_ENGINE_VERSION_SUBMINOR;     d+=1; l+=1;
	memcpy(d, nick, NICKLEN);            d+=NICKLEN; l+=NICKLEN;
	*d = pgid;                           d+=1; l+=1;
	*d = algo;                           d+=1; l+=1;
	write_be16(d, (uint16_t)pklen);      d+=2; l+=2;
	memcpy(d, pk, pklen);                d+=pklen; l+=pklen;
	udp_packet->len = l;
}

static void packet_connect(struct udp_packet *udp_packet, enum pc_mode mode, const char *nick,
                           enum dhm_pgid pgid, enum pc_algo algo, size_t pklen, const uint8_t *pk)
{
	packet_call(udp_packet, mode, nick, pgid, algo, pklen, pk);
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_CONNECT);
}

static void packet_refuse(struct udp_packet *udp_packet, enum pc_mode mode, uint16_t reason)
{
	udp_packet->len = 4;
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_REFUSE);
	write_be16(udp_packet->data+2, reason);
}

static void packet_table(struct udp_packet *udp_packet, enum pc_mode mode, size_t pklen, const uint8_t *pk,
                         const char *nick, struct pc_node *nodes[], int exclude_idx)
{
	int i;
	uint8_t *d;
	size_t   l;
	uint16_t header, table_size;

	d = udp_packet->data;
	l = 0;

	header = mode_bits(mode) | UDP_PACKET_FTYPE_TABLE;
	write_be16(d, header);                       d+=2; l+=2;

	/* pklen */
	write_be16(d, (uint16_t)pklen);              d+=2; l+=2;
	memcpy(d, pk, pklen);                        d+=pklen; l+=pklen;

	/* table size: all nodes excluding the sender of the call request */
	table_size = (uint16_t)node_get_count(nodes);
	write_be16(d, table_size);                   d+=2; l+=2;

	/* my nick */
	memcpy(d, nick, NICKLEN);                    d+=NICKLEN; l+=NICKLEN;

	/* other nodes except packet sender */
	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (nodes[i] == NULL || i == exclude_idx)
			continue;
		memcpy(d, nodes[i]->nick, NICKLEN);                   d+=NICKLEN; l+=NICKLEN;
		write_be32(d, ntohl(nodes[i]->addr.sin_addr.s_addr)); d+=4; l+=4;
		write_be16(d, ntohs(nodes[i]->addr.sin_port));        d+=2; l+=2;
	}
	udp_packet->len = l;
}

static void packet_bye(struct udp_packet *udp_packet, enum pc_mode mode)
{
	udp_packet->len = 2;
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_BYE);
}

static void packet_audio(struct udp_packet *udp_packet, enum pc_mode mode,
                         uint32_t sequence_number, uint8_t *payload, size_t payloadlen)
{
	udp_packet->len = UDP_PACKET_AUDIO_HEADER_LEN + payloadlen;
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_AUDIO);
	write_be32(udp_packet->data+2, sequence_number);
	memcpy(udp_packet->data + UDP_PACKET_AUDIO_HEADER_LEN, payload, payloadlen);
}

static void packet_nop(struct udp_packet *udp_packet, enum pc_mode mode)
{
	udp_packet->len = 2;
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_NOP);
}

static void packet_chat(struct udp_packet *udp_packet, enum pc_mode mode, const char *buf, size_t len)
{
	udp_packet->len = 2+len;
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_CHAT);
	memcpy(udp_packet->data+2, buf, len);
}

static void packet_relay(struct udp_packet *udp_packet, enum pc_mode mode, struct sockaddr_in dest_addr)
{
	uint8_t *d;
	size_t   l;
	uint16_t header;

	d = udp_packet->data;
	l = 0;
	memmove(d+8, d, udp_packet->len);

	header = mode_bits(mode) | UDP_PACKET_FTYPE_RELAY;
	write_be16(d, header);                           d+=2; l+=2;
	write_be32(d, ntohl(dest_addr.sin_addr.s_addr)); d+=4; l+=4;
	write_be16(d, ntohs(dest_addr.sin_port));        d+=2; l+=2;
	udp_packet->len += l;
}

static void packet_from_relay_to_relayed(struct udp_packet *udp_packet, enum pc_mode mode)
{
	uint8_t *d;
	size_t   l;
	uint16_t header;
	struct sockaddr_in src_addr, dest_addr;

	/* save source address */
	src_addr = udp_packet->addr;

	/* read destination address */
	memset(&dest_addr, 0, sizeof(dest_addr));
	d = udp_packet->data;
	l = udp_packet->len;
	/* skip header */                                d+=2; l-=2;
	dest_addr.sin_family      = AF_INET;
	dest_addr.sin_addr.s_addr = htonl(read_be32(d)); d+=4; l-=4;
	dest_addr.sin_port        = htons(read_be16(d)); d+=2; l-=2;

	/* this now becomes a relayed packet */
	udp_packet->addr = dest_addr;
	d = udp_packet->data;
	l = 0;
	header = mode_bits(mode) | UDP_PACKET_FTYPE_RELAYED;
	write_be16(d, header);                           d+=2; l+=2;
	write_be32(d, ntohl(src_addr.sin_addr.s_addr));  d+=4; l+=4;
	write_be16(d, ntohs(src_addr.sin_port));         d+=2; l+=2;
}

static void packet_plinfo(struct udp_packet *udp_packet, enum pc_mode mode, uint32_t pl10k)
{
	udp_packet->len = 6;
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_PLINFO);
	write_be32(udp_packet->data+2, pl10k);
}

static void packet_rttreq(struct udp_packet *udp_packet, enum pc_mode mode)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	udp_packet->len = 10;
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_RTTREQ);
	write_be32(udp_packet->data+2, (uint32_t)tv.tv_sec);
	write_be32(udp_packet->data+6, (uint32_t)tv.tv_usec);
}

static void packet_rttans(struct udp_packet *udp_packet, enum pc_mode mode)
{
	udp_packet->len = 10;
	write_be16(udp_packet->data, mode_bits(mode) | UDP_PACKET_FTYPE_RTTANS);
}

static void packet_encrypt(struct udp_packet *udp_packet_enc, const struct udp_packet *udp_packet,
                           enum pc_algo algo, const void *cipher_ctx)
{
	uint8_t *d;
	size_t   l;
	uint16_t packet_header, packet_mode;
	size_t   blocksize;
	uint8_t  padding_size;
	uint32_t iv32[2];
	uint64_t iv64[2];

	/* make sure the encrypted packet will fit */
	if (udp_packet->len > UDP_PACKET_MAXLEN - (/* FAMILY_ENCRYPTED header */ 18 + /* FAMILY_ENCRYPTED padding */ 16)) {
		udp_packet_enc->addr = udp_packet->addr;
		udp_packet_enc->len  = 0;
		snprintf(msgbuf, MBS, "Cannot encrypt packet, size is too big (%zd)", udp_packet->len);
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return;
	}

	/* read packet mode and copy addr */
	packet_mode = read_be16(udp_packet->data) & UDP_PACKET_MASK_MODE;
	udp_packet_enc->addr = udp_packet->addr;

	/* insert header */
	packet_header = packet_mode | UDP_PACKET_FAMILY_ENCRYPTED | (uint16_t)algo;
	d = udp_packet_enc->data;
	l = 0;
	write_be16(d, packet_header);                                     d+=2; l+=2;
	if (algo >= algo_camellia) {
		blocksize = 16;
		iv64[0] = random_rand64();
		iv64[1] = random_rand64();
		write_be64(d, iv64[0]);                                       d+=8; l+=8;
		write_be64(d, iv64[1]);                                       d+=8; l+=8;
	} else {
		blocksize = 8;
		iv32[0] = random_rand32();
		iv32[1] = random_rand32();
		write_be32(d, iv32[0]);                                       d+=4; l+=4;
		write_be32(d, iv32[1]);                                       d+=4; l+=4;
	}

	/* copy payload to new packet */
	memcpy(d, udp_packet->data, udp_packet->len);                     d+=udp_packet->len; l+=udp_packet->len;

	/* insert some padding to make payload size multiple of cipher blocksize */
	padding_size = (uint8_t)(blocksize - (udp_packet->len % blocksize));
	memset(d, padding_size, padding_size);                            d+=padding_size; l+=padding_size;
	udp_packet_enc->len = l;

	/* encrypt payload */
	d = udp_packet_enc->data+(2+blocksize);
	l = udp_packet_enc->len -(2+blocksize);
	switch (algo) {
	case algo_xtea:
		xtea_encrypt_buffer_cbc(cipher_ctx, d, l, iv32);
		break;
	case algo_cast128:
		cast128_encrypt_buffer_cbc(cipher_ctx, d, l, iv32);
		break;
	case algo_blowfish:
		blowfish_encrypt_buffer_cbc(cipher_ctx, d, l, iv32);
		break;
	case algo_camellia:
		camellia_encrypt_buffer_cbc(cipher_ctx, d, l, iv64);
		break;
	case algo_twofish:
		twofish_encrypt_buffer_cbc(cipher_ctx, d, l, iv64);
		break;
	}
}

static void send_udp_packet_enc(struct pc_context *pctx, const struct udp_packet *udp_packet)
{
	struct udp_packet udp_packet_enc;
	uint16_t packet_family;
	int idx;

	switch (pctx->mode) {
	case mode_clear:
		udp_send_packet(pctx->sockfd, udp_packet);
		pctx->bytes_out_per_sec += udp_packet->len;
		break;
	case mode_secure:
		packet_family = read_be16(udp_packet->data) & UDP_PACKET_MASK_FAMILY;
		idx = node_get_idx(pctx->nodes, udp_packet->addr);

		if (packet_family == UDP_PACKET_FAMILY_HANDSHAKE) {
			udp_send_packet(pctx->sockfd, udp_packet);
			pctx->bytes_out_per_sec += udp_packet->len;
		} else if (idx != -1 && pctx->nodes[idx]->status == STATUS_OK) {
			packet_encrypt(&udp_packet_enc, udp_packet, pctx->nodes[idx]->algo, pctx->nodes[idx]->cipher_ctx);
			udp_send_packet(pctx->sockfd, &udp_packet_enc);
			pctx->bytes_out_per_sec += udp_packet_enc.len;
		}
		break;
	case mode_psk:
		packet_encrypt(&udp_packet_enc, udp_packet, pctx->algo, pctx->cipher_ctx);

		udp_send_packet(pctx->sockfd, &udp_packet_enc);
		pctx->bytes_out_per_sec += udp_packet_enc.len;
		break;
	}
}

static void send_udp_packet_enc_to_all(struct pc_context *pctx, const struct udp_packet *udp_packet)
{
	unsigned int i;
	struct udp_packet udp_packet_enc;
	uint16_t packet_family;

	switch (pctx->mode) {
	case mode_clear:
	case mode_psk:
		if (pctx->mode == mode_psk)
			packet_encrypt(&udp_packet_enc, udp_packet, pctx->algo, pctx->cipher_ctx);
		else
			udp_packet_enc = *udp_packet;

		for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
			if (pctx->nodes[i] && pctx->nodes[i]->status == STATUS_OK) {
				udp_packet_enc.addr = pctx->nodes[i]->addr;
				udp_send_packet(pctx->sockfd, &udp_packet_enc);
				pctx->bytes_out_per_sec += udp_packet_enc.len;
			}
		}
		break;
	case mode_secure:
		packet_family = read_be16(udp_packet->data) & UDP_PACKET_MASK_FAMILY;

		for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
			if (pctx->nodes[i] && pctx->nodes[i]->status == STATUS_OK) {

				if (packet_family == UDP_PACKET_FAMILY_HANDSHAKE)
					udp_packet_enc = *udp_packet;
				else
					packet_encrypt(&udp_packet_enc, udp_packet, pctx->nodes[i]->algo, pctx->nodes[i]->cipher_ctx);

				udp_packet_enc.addr = pctx->nodes[i]->addr;
				udp_send_packet(pctx->sockfd, &udp_packet_enc);
				pctx->bytes_out_per_sec += udp_packet_enc.len;
			}
		}
		break;
	}
}


static void connect_new_nodes(struct pc_context *pctx, int force_relay)
{
	unsigned int i;
	int threshold = STATUS_CONNECTING+3;
	struct udp_packet udp_packet;

	/* send connect requests to those who don't know about me */
	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (pctx->nodes[i] && pctx->nodes[i]->status < STATUS_CONNECTING_END) {
			udp_packet.addr = pctx->nodes[i]->addr;
			packet_connect(&udp_packet, pctx->mode, pctx->nick, pctx->nodes[i]->pgid, pctx->nodes[i]->algo,
			               pctx->nodes[i]->dhm.pklen, pctx->nodes[i]->dhm.pk);

			if (pctx->nodes[i]->status < threshold)
				send_udp_packet_enc(pctx, &udp_packet);

			if (force_relay || pctx->nodes[i]->status >= threshold) {
				unsigned int j, relay_count;

				/* prepare packet for relay */
				packet_relay(&udp_packet, pctx->mode, pctx->nodes[i]->addr);

				/* send this packet to (at most) 2 other nodes that can relay it */
				relay_count = 2;
				for (j = 0; j < MAX_NUMBER_OF_NODES; j++) {
					if (pctx->nodes[j] && pctx->nodes[j]->status == STATUS_OK && j != i) {
						udp_packet.addr = pctx->nodes[j]->addr;
						send_udp_packet_enc(pctx, &udp_packet);
						if (--relay_count == 0)
							break;
					}
				}

				if (relay_count < 2) {
					snprintf(msgbuf, MBS, "Cannot connect to %s (%s:%hu), sent %d relay packets",
					         pctx->nodes[i]->nick, inet_ntoa(pctx->nodes[i]->addr.sin_addr),
					         ntohs(pctx->nodes[i]->addr.sin_port), 2-relay_count);
					msgbook_enqueue(&mb0, MB_TYPE_WARNING, MODULE, msgbuf);
				}
			}

			pctx->nodes[i]->status++;
		}
	}
}


static opus_int32 convert_opus_bw(opus_int32 bandwidth)
{
	switch (bandwidth) {
	case OPUS_BANDWIDTH_NARROWBAND:
		return 4000;
	case OPUS_BANDWIDTH_MEDIUMBAND:
		return 6000;
	case OPUS_BANDWIDTH_WIDEBAND:
		return 8000;
	case OPUS_BANDWIDTH_SUPERWIDEBAND:
		return 12000;
	case OPUS_BANDWIDTH_FULLBAND:
		return 20000;
	default: /* OPUS_AUTO */
		return 0;
	}
}

struct version {
	uint8_t maj, min, smin;
};

static int check_version_or_refuse(struct pc_context *pctx, const struct version *v,
                                   const struct udp_packet *udp_packet)
{
	struct udp_packet udp_packet_response;

	if (v->maj != PC_ENGINE_VERSION_MAJOR || v->min != PC_ENGINE_VERSION_MINOR) {
		msgbook_enqueue(&mb0, MB_TYPE_WARNING, MODULE, "CALL/CONNECT packet from incompatible engine, refusing");

		udp_packet_response.addr = udp_packet->addr;
		packet_refuse(&udp_packet_response, pctx->mode, REFUSE_REASON_VERSION);
		send_udp_packet_enc(pctx, &udp_packet_response);
		return -1;
	}
	return 0;
}

static int validate_call_params(uint8_t *nick, uint8_t *pgid, uint8_t *algo, uint16_t *pklen, size_t l)
{
	int i, ret = 0;

	for (i = 0; i < NICKLEN; i++)
		if (nick[i] == '\0')
			break;
	if (i == NICKLEN) {
		nick[NICKLEN-1] = '\0';
		ret = -1;
	}

	if (*pgid != pgid_2048 && *pgid != pgid_3072 && *pgid != pgid_4096) {
		*pgid = pgid_2048;
		ret = -2;
	}
	if (*algo > algo_twofish) {
		*algo = algo_xtea;
		ret = -3;
	}
	if (*pklen == 0 || *pklen != l || *pklen > DHM_MAX_LEN) {
		*pklen = 0;
		ret = -4;
	}

	if (ret < 0) {
		snprintf(msgbuf, MBS, "Invalid CALL/CONNECT parameters (%d)", ret);
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
	}

	return ret;
}

struct address_book {
	int                n;
	char               nick[MAX_NUMBER_OF_NODES][NICKLEN];
	struct sockaddr_in addr[MAX_NUMBER_OF_NODES];
};

static int process_packet(struct pc_context *pctx, const struct udp_packet *udp_packet)
{
	int i, idx, old_timeout;
	struct pc_node **nodes  = pctx->nodes;
	struct pc_tone  *tone   = &pctx->tone;
	struct slist   **events = &pctx->events;
	const uint8_t   *d;
	size_t           l;
	uint16_t         packet_header, packet_ftype, table_size;
	struct version   version;
	uint8_t          nick[NICKLEN], pgid, algo;
	uint16_t         reason, pklen;
	const uint8_t   *pk;
	struct address_book ab;
	struct udp_packet udp_packet_response;
	struct pc_event *ev;

	/* packets should contain at least a header */
	if (udp_packet->len < 2)
		return RES_ERROR;

	d = udp_packet->data;
	l = udp_packet->len;

	/* read packet header */
	packet_header = read_be16(d); d+=2; l-=2;
//	packet_mode   = packet_header & UDP_PACKET_MASK_MODE;
	packet_ftype  = packet_header & UDP_PACKET_MASK_FTYPE;
//	packet_family = packet_header & UDP_PACKET_MASK_FAMILY;
//	packet_type   = packet_header & UDP_PACKET_MASK_TYPE;

	/* do we know this node already? */
	idx = node_get_idx(nodes, udp_packet->addr);
	if (idx == -1 && packet_ftype != UDP_PACKET_FTYPE_CALL && packet_ftype != UDP_PACKET_FTYPE_CONNECT) {
		if (*pctx->verbose >= 2) {
			snprintf(msgbuf, MBS, "Unexpected 0x%04x packet from %s:%hu", packet_ftype,
			         inet_ntoa(udp_packet->addr.sin_addr), ntohs(udp_packet->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		}
		return RES_ERROR;
	}

	/* reset timeout counter */
	old_timeout = 0;
	if (idx != -1) {
		old_timeout = nodes[idx]->timeout;
		nodes[idx]->timeout = TIMEOUT;
	}


	switch (packet_ftype) {
	case UDP_PACKET_FTYPE_CALL:
	case UDP_PACKET_FTYPE_CONNECT:
		if (l < PC_ENGINE_VERSION_BYTES + NICKLEN + 1 + 1 + 2) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid CALL/CONNECT packet minimum size");
			return RES_ERROR;
		}

		version.maj  = *d;    d+=1; l-=1;
		version.min  = *d;    d+=1; l-=1;
		version.smin = *d;    d+=1; l-=1;
		if (check_version_or_refuse(pctx, &version, udp_packet) == -1)
			return RES_REFUSED;

		memcpy(nick, d, NICKLEN); d+=NICKLEN; l-=NICKLEN;
		pgid  = *d;           d+=1; l-=1;
		algo  = *d;           d+=1; l-=1;
		pklen = read_be16(d); d+=2; l-=2;
		pk    = d;
		if (validate_call_params(nick, &pgid, &algo, &pklen, l) < 0)
			return RES_ERROR;

		if (packet_ftype == UDP_PACKET_FTYPE_CALL) {
			if (idx != -1) {
				/* node is already present, check if it's requesting connection with the same parameters */
				if (nodes[idx]->pgid == pgid && nodes[idx]->algo == algo && !dhm_compare_pk(&nodes[idx]->dhm, pk, pklen)) {
					/* send table */
					udp_packet_response.addr = udp_packet->addr;
					packet_table(&udp_packet_response, pctx->mode, nodes[idx]->dhm.pklen,
					             nodes[idx]->dhm.pk, pctx->nick, nodes, idx);
					send_udp_packet_enc(pctx, &udp_packet_response);
				} else {
					node_delete(nodes, idx, DELETE_REASON_LEFT, tone, events);
					return RES_ERROR;
				}
			} else {
				struct pc_caller *cl;

				cl = caller_is_present(pctx->callers, udp_packet->addr);
				if (cl) {
					cl->timeout = 250;
				} else {
					/* push caller */
					caller_push(&pctx->callers, udp_packet->addr, (const char *)nick, pgid, algo, pklen, pk);

					/* push event */
					ev = event_push(events, event_type_incoming_call);
					ev->addr = udp_packet->addr;
					memcpy(ev->nick, (char *)nick, NICKLEN);

					if (pctx->autoaccept_calls)
						pc_engine_cmd_accept_call(pctx);
				}
			}
		}

		if (packet_ftype == UDP_PACKET_FTYPE_CONNECT) {
			if (idx != -1) {
				/* node is already present, check if it's requesting connection with the same parameters */
				if (!(nodes[idx]->pgid == pgid && nodes[idx]->algo == algo && !dhm_compare_pk(&nodes[idx]->dhm, pk, pklen))) {
					node_delete(nodes, idx, DELETE_REASON_LEFT, tone, events);
					return RES_ERROR;
				}
			} else {
				/* insert remote node */
				idx = node_add(nodes, udp_packet->addr, (const char *)nick, pgid, algo, tone, events);
				if (idx == -1) {
					/* send refuse */
					udp_packet_response.addr = udp_packet->addr;
					packet_refuse(&udp_packet_response, pctx->mode, REFUSE_REASON_FULL);
					send_udp_packet_enc(pctx, &udp_packet_response);
					return RES_REFUSED;
				}

				/* setup key */
				node_setup_cipher_and_key(nodes[idx], pk, pklen);
				nodes[idx]->status = STATUS_OK;
			}

			/* send table */
			udp_packet_response.addr = udp_packet->addr;
			packet_table(&udp_packet_response, pctx->mode, nodes[idx]->dhm.pklen,
			             nodes[idx]->dhm.pk, pctx->nick, nodes, idx);
			send_udp_packet_enc(pctx, &udp_packet_response);
		}
		return RES_OK;


	case UDP_PACKET_FTYPE_REFUSE:
		if (l != 2) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid REFUSE packet size");
			return RES_ERROR;
		}
		reason = read_be16(d); d+=2; l-=2;

		/* push event */
		ev = event_push(events, event_type_call_refused);
		ev->addr = nodes[idx]->addr;
		memcpy(ev->nick, nodes[idx]->nick, NICKLEN);
		ev->i = (int)reason;

		/* stop calling */
		if (pctx->call && is_same_addr(pctx->call->addr, nodes[idx]->addr)) {
			free(pctx->call);
			pctx->call = NULL;
		}

		node_delete(nodes, idx, DELETE_REASON_LEFT, tone, events);
		return RES_REFUSED;


	case UDP_PACKET_FTYPE_TABLE:
		if (l < 2) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid TABLE packet minimum size");
			return RES_ERROR;
		}
		pklen = read_be16(d);      d+=2; l-=2;
		if (pklen == 0 || pklen > DHM_MAX_LEN) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid pklen in TABLE packet");
			return RES_ERROR;
		}
		if (l < (size_t)(pklen + 2 + NICKLEN)) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid TABLE packet minimum size");
			return RES_ERROR;
		}
		pk = d;                    d+=pklen; l-=pklen;
		table_size = read_be16(d); d+=2; l-=2;
		if (l != (size_t)(NICKLEN*table_size + 6*(table_size-1))) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid address table size in TABLE packet");
			return RES_ERROR;
		}

		/* stop calling */
		if (pctx->call && is_same_addr(pctx->call->addr, nodes[idx]->addr)) {
			free(pctx->call);
			pctx->call = NULL;
		}

		/* setup key */
		node_setup_cipher_and_key(nodes[idx], pk, pklen);

		/* copy table to addres book */
		ab.n = table_size;
		for (i = 0; i < ab.n; i++) {
			memcpy(ab.nick[i], d, NICKLEN);                       d+=NICKLEN; l-=NICKLEN;
			ab.nick[i][NICKLEN-1] = '\0';
			if (i == 0) {
				ab.addr[i] = udp_packet->addr;
			} else {
				ab.addr[i].sin_family      = AF_INET;
				ab.addr[i].sin_addr.s_addr = htonl(read_be32(d)); d+=4; l-=4;
				ab.addr[i].sin_port        = htons(read_be16(d)); d+=2; l-=2;
			}
		}

		/* copy sender's nick */
		memcpy(nodes[idx]->nick, ab.nick[0], NICKLEN);

		/* packet sender knows about me */
		nodes[idx]->status = STATUS_OK;

		/* push event */
		ev = event_push(events, event_type_call_accepted);
		ev->addr = nodes[idx]->addr;
		memcpy(ev->nick, nodes[idx]->nick, NICKLEN);

		/* insert unknown nodes */
		for (i = 0; i < ab.n; i++) {
			int tidx;

			tidx = node_get_idx(nodes, ab.addr[i]);
			if (tidx == -1)
				node_add(nodes, ab.addr[i], ab.nick[i], pctx->preferred_pgid, pctx->algo, tone, events);
		}

		/* send connect requests to newly added nodes. we don't use relay initially */
		//connect_new_nodes(pctx, 0);
		return RES_OK;


	case UDP_PACKET_FTYPE_BYE:
		if (l != 0) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid BYE packet size");
			return RES_ERROR;
		}
		node_delete(nodes, idx, DELETE_REASON_LEFT, tone, events);
		return RES_OK;


	case UDP_PACKET_FTYPE_AUDIO:
		/* read packet header */
		nodes[idx]->sequence_number = read_be32(d); d+=4; l-=4;

		/* ok, sequence numbers of packets must always increase */
		if (nodes[idx]->sequence_number > nodes[idx]->last_sequence_number || nodes[idx]->packets_received == 0) {
			struct pc_pcmframe *pf;
			const uint8_t *opus_dec_packet;
			opus_int32     opus_dec_packetlen;
			opus_int32     pcmlen;
			int            bandwidth, nb_channels;

			/* check if we lost packets */
			if (nodes[idx]->sequence_number != (nodes[idx]->last_sequence_number + 1) &&
			    nodes[idx]->packets_received != 0) {
				uint32_t k, loss;

				loss = nodes[idx]->sequence_number - (nodes[idx]->last_sequence_number + 1);
				nodes[idx]->packets_lost += loss;
				if (*pctx->verbose >= 2) {
					snprintf(msgbuf, MBS, "Oops, %u audio packets lost for %s", loss, nodes[idx]->nick);
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
				}

				/* call decoder for missing packets if the loss is less than 25 packets */
				for (k = 0; loss < 25 && k < loss; k++) {
					pf = xcalloc(1, sizeof(*pf));
					pf->pcmlen = ONE_OPUS_FRAME;
					pcmlen = opus_decode(nodes[idx]->dec, NULL, 0, pf->pcm, (int)pf->pcmlen, 0);

					if (pcmlen != ONE_OPUS_FRAME || nodes[idx]->nb_frames >= 25) {
						free(pf);
					} else {
						/* add one opus frame to the tail of the queue */
						nodes[idx]->pcmframes = slist_append(nodes[idx]->pcmframes, pf);
						nodes[idx]->nb_frames++;
					}
				}
			}

			nodes[idx]->last_sequence_number = nodes[idx]->sequence_number;
			nodes[idx]->packets_received++;
			nodes[idx]->packet_loss = 100.0f * (float)nodes[idx]->packets_lost /
			                          (float)(nodes[idx]->packets_lost + nodes[idx]->packets_received);

			/* prepare pcmframe and packet pointer/len */
			pf = xcalloc(1, sizeof(*pf));
			pf->pcmlen = ONE_OPUS_FRAME;
			opus_dec_packet    = udp_packet->data + UDP_PACKET_AUDIO_HEADER_LEN;
			opus_dec_packetlen = (opus_int32)(udp_packet->len  - UDP_PACKET_AUDIO_HEADER_LEN);
			/* extract bandwidth and nb_channels */
			bandwidth = opus_packet_get_bandwidth(opus_dec_packet);
			nodes[idx]->bandwidth_hz = convert_opus_bw(bandwidth);
			nb_channels = opus_packet_get_nb_channels(opus_dec_packet);
			nodes[idx]->nb_channels = nb_channels != OPUS_INVALID_PACKET ? nb_channels : 0;
			/* decode */
			pcmlen = opus_decode(nodes[idx]->dec, opus_dec_packet, opus_dec_packetlen, pf->pcm, (int)pf->pcmlen, 0);
			if (pcmlen != ONE_OPUS_FRAME) {
				free(pf);
				if (pcmlen < 0)
					snprintf(msgbuf, MBS, "opus_decode() failed: %s", opus_strerror(pcmlen));
				else
					snprintf(msgbuf, MBS, "pcmlen = %d, discarding pcm data", pcmlen);
				msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
				return RES_ERROR;
			}

			/* limit queue length to 500ms */
			if (nodes[idx]->nb_frames >= 25) {
				free(pf);
			} else {
				/* add one opus frame to the tail of the queue */
				nodes[idx]->pcmframes = slist_append(nodes[idx]->pcmframes, pf);
				nodes[idx]->nb_frames++;
			}
		} else {
			if (*pctx->verbose >= 2) {
				snprintf(msgbuf, MBS, "Oops, audio packet duplicated or out of order for %s", nodes[idx]->nick);
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
			}
		}
		return RES_OK;


	case UDP_PACKET_FTYPE_NOP:
		if (l != 0) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid NOP packet size");
			return RES_ERROR;
		}
		return RES_OK;


	case UDP_PACKET_FTYPE_CHAT:
		if (d[l-1] != '\0') {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "CHAT packet not null terminated");
			return RES_ERROR;
		}
		/* push event */
		ev = event_push(events, event_type_chat);
		ev->addr = nodes[idx]->addr;
		memcpy(ev->nick, nodes[idx]->nick, NICKLEN);
		ev->data = xmalloc(l);
		memcpy(ev->data, d, l);

		if (tone->enable || strstr((const char *)d, pctx->nick))
			tone->play = (tone->play > 5*ONE_OPUS_FRAME) ? tone->play : 5*ONE_OPUS_FRAME;
		return RES_OK;


	case UDP_PACKET_FTYPE_RELAY:
		if (l < 6) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid RELAY packet minimum size");
			return RES_ERROR;
		}

		/* copy received packet */
		udp_packet_response = *udp_packet;

		/* this now becomes a relayed packet */
		packet_from_relay_to_relayed(&udp_packet_response, pctx->mode);

		if (*pctx->verbose >= 2) {
			size_t l0;
			int tidx;

			/* use 2 calls because inet_ntoa returns a string in a statically allocated buffer,
			   which subsequent calls will overwrite */
			snprintf(msgbuf, MBS, "Relay packet from %s (%s:%hu)",
			         nodes[idx]->nick, inet_ntoa(udp_packet->addr.sin_addr), ntohs(udp_packet->addr.sin_port));

			tidx = node_get_idx(nodes, udp_packet_response.addr);
			l0 = strlen(msgbuf);
			snprintf(msgbuf+l0, MBS-l0, ", relaying to %s (%s:%hu)", tidx == -1 ? "?" : nodes[tidx]->nick,
			         inet_ntoa(udp_packet_response.addr.sin_addr), ntohs(udp_packet_response.addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		}

		/* send relayed packet */
		send_udp_packet_enc(pctx, &udp_packet_response);
		return RES_OK;


	case UDP_PACKET_FTYPE_RELAYED:
		if (l < 6) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid RELAYED packet minimum size");
			return RES_ERROR;
		}

		/* copy received packet, discarding relayed header */
		memcpy(udp_packet_response.data, udp_packet->data+8, udp_packet->len-8);
		udp_packet_response.len = udp_packet->len-8;

		/* extract original source */
		udp_packet_response.addr.sin_family      = AF_INET;
		udp_packet_response.addr.sin_addr.s_addr = htonl(read_be32(d)); d+=4; l-=4;
		udp_packet_response.addr.sin_port        = htons(read_be16(d)); d+=2; l-=2;

		if (*pctx->verbose >= 2) {
			size_t l0;
			int tidx;

			/* use 2 calls because inet_ntoa returns a string in a statically allocated buffer,
			   which subsequent calls will overwrite */
			tidx = node_get_idx(nodes, udp_packet_response.addr);
			snprintf(msgbuf, MBS, "Relayed packet from %s (%s:%hu)", tidx == -1 ? "?" : nodes[tidx]->nick,
			         inet_ntoa(udp_packet_response.addr.sin_addr), ntohs(udp_packet_response.addr.sin_port));

			l0 = strlen(msgbuf);
			snprintf(msgbuf+l0, MBS-l0, " via %s (%s:%hu)",
			         nodes[idx]->nick, inet_ntoa(udp_packet->addr.sin_addr), ntohs(udp_packet->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		}
		return process_packet(pctx, &udp_packet_response);


	case UDP_PACKET_FTYPE_PLINFO:
		if (l != 4) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid PLINFO packet size");
			return RES_ERROR;
		}
		nodes[idx]->tm_pl10k = read_be32(d); d+=4; l-=4;
		return RES_OK;


	case UDP_PACKET_FTYPE_RTTREQ:
		if (l != 8) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid RTTREQ packet size");
			return RES_ERROR;
		}
		udp_packet_response = *udp_packet;
		packet_rttans(&udp_packet_response, pctx->mode);
		send_udp_packet_enc(pctx, &udp_packet_response);
		return RES_OK;


	case UDP_PACKET_FTYPE_RTTANS:
		if (l != 8) {
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid RTTANS packet size");
			return RES_ERROR;
		} else {
			struct timeval tv, now;
			double rtt;
			const double alpha = 0.125;

			gettimeofday(&now, NULL);
			tv.tv_sec  =      (time_t)read_be32(d); d+=4; l-=4;
			tv.tv_usec = (suseconds_t)read_be32(d); d+=4; l-=4;

			rtt = (double)(now.tv_sec - tv.tv_sec) * 1000000.0 + (double)(now.tv_usec - tv.tv_usec);

			if (nodes[idx]->rtt_us == 0.0)
				nodes[idx]->rtt_us = rtt;
			else
				nodes[idx]->rtt_us = (1-alpha) * nodes[idx]->rtt_us + alpha * rtt;
		}
		return RES_OK;


	default:
		if (*pctx->verbose >= 2) {
			snprintf(msgbuf, MBS, "Unknown packet type 0x%04X", packet_ftype);
			msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		}
		if (idx != -1)
			nodes[idx]->timeout = old_timeout;
		break;
	}
	return RES_ERROR;
}

static unsigned int mix_audio(struct pc_context *pctx)
{
	unsigned int i, n, m;
	opus_int32 pcm32[2*ONE_OPUS_FRAME], peak;
	float gain;

	memset(pcm32, 0, sizeof(pcm32));

	n = 0;
	if (pctx->tone.pos >= pctx->tone.play) {
		pctx->tone.pos  = 0;
		pctx->tone.play = 0;
	} else {
		n++;

		adsp_sum_s32_s16(pcm32, pctx->tone.pcm + channels * pctx->tone.pos, channels * ONE_OPUS_FRAME);
		pctx->tone.pos += ONE_OPUS_FRAME;
	}

	if (pctx->call) {
		n++;

		if (pctx->calltone.pos >= pctx->calltone.pcmlen)
			pctx->calltone.pos = 0;

		adsp_sum_s32_s16(pcm32, pctx->calltone.pcm + channels * pctx->calltone.pos, channels * ONE_OPUS_FRAME);
		pctx->calltone.pos += ONE_OPUS_FRAME;
	} else {
		pctx->calltone.pos = 0;
	}

	if (pctx->callers && pctx->ringtone.enable) {
		n++;

		if (pctx->ringtone.pos >= pctx->ringtone.pcmlen)
			pctx->ringtone.pos = 0;

		adsp_sum_s32_s16(pcm32, pctx->ringtone.pcm + channels * pctx->ringtone.pos, channels * ONE_OPUS_FRAME);
		pctx->ringtone.pos += ONE_OPUS_FRAME;
	} else {
		pctx->ringtone.pos = 0;
	}

	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (pctx->nodes[i] && pctx->nodes[i]->pcmframes) {
			struct pc_pcmframe *pf;
			double rms2;

			n++;
			pf = pctx->nodes[i]->pcmframes->data;

			/* dBSPL */
			pctx->nodes[i]->sos   += adsp_sum_of_squares(pf->pcm, channels * pf->pcmlen);
			pctx->nodes[i]->sos_N += channels * pf->pcmlen;
			rms2 = (double)(pctx->nodes[i]->sos) / (double)pctx->nodes[i]->sos_N;
			pctx->nodes[i]->dBSPL = 10.0 * log10(1.0 /* to avoid -inf */ + rms2) - 90.3 /* 20*log10(1/32768.0) */;

			/* sum (mix) pcm from different nodes */
			adsp_sum_s32_s16(pcm32, pf->pcm, channels * pf->pcmlen);

			/* remove one opus frame from the head of the queue */
			free(pf);
			pctx->nodes[i]->pcmframes = slist_remove_head(pctx->nodes[i]->pcmframes);
			pctx->nodes[i]->nb_frames--;
		}
	}

	m = 0;
	if (pctx->lb) {
		m++;

		adsp_sum_s32_s16(pcm32, pctx->lb_pcm, channels * ONE_OPUS_FRAME);
	}

	if (n+m) {
#if 1
		peak = adsp_find_peak_s32_2ch(pcm32, channels * ONE_OPUS_FRAME);
		gain = (float)(INT16_MAX) / (float)peak;

		if (gain < 1.0f) {
			adsp_scale_s16_s32(pctx->pcm, pcm32, channels * ONE_OPUS_FRAME, gain);
			if (*pctx->verbose >= 3) {
				snprintf(msgbuf, MBS, "Scale, gain = %.4f", gain);
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
			}
		} else {
			adsp_copy_s16_s32(pctx->pcm, pcm32, channels * ONE_OPUS_FRAME);
		}
#else
		adsp_compress_tanh_s16_s32(pctx->pcm, pcm32, channels * ONE_OPUS_FRAME);
#endif
		pctx->pcmlen = ONE_OPUS_FRAME;
	} else {
		pctx->pcmlen = 0;
	}

	if (pctx->record || pctx->fifo) {
		if (!m)
			adsp_sum_s32_s16(pcm32, pctx->lb_pcm, channels * ONE_OPUS_FRAME);

		peak = adsp_find_peak_s32_2ch(pcm32, channels * ONE_OPUS_FRAME);
		gain = (float)(INT16_MAX) / (float)peak;

		if (gain < 1.0f) {
			adsp_scale_s16_s32(pctx->record_pcm, pcm32, channels * ONE_OPUS_FRAME, gain);
		} else {
			adsp_copy_s16_s32(pctx->record_pcm, pcm32, channels * ONE_OPUS_FRAME);
		}

		/* write data to file */
		if (pctx->record) {
			if (pctx->record == REC_WAVE) {
				wave_write_data(pctx->record_pcm, channels, ONE_OPUS_FRAME, &pctx->record_bytes_written, pctx->record_fp);
			} else {
				oggopus_write_data(pctx->record_pcm, ONE_OPUS_FRAME, pctx->record_enc, &pctx->record_oss,
					               &pctx->record_packetno, 0, pctx->record_fp);
			}
		}

		/* write data to output fifo */
		if (pctx->fifo) {
			/* open output fifo: opening for write-only will fail with ENXIO
			   (no such device or address) unless the other end has already been opened */
			if (pctx->fifooutfd == -1 && pctx->fifoout[0]) {
				pctx->fifooutfd = open(pctx->fifoout, O_WRONLY | O_NONBLOCK);
				if (pctx->fifooutfd != -1 && *pctx->verbose >= 2) {
					snprintf(msgbuf, MBS, "Output fifo opened, fd = %d", pctx->fifooutfd);
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
				}
			}
			if (pctx->fifooutfd != -1) {
				ssize_t nw;

				nw = write(pctx->fifooutfd, pctx->record_pcm, sizeof(pctx->record_pcm[0]) * channels * ONE_OPUS_FRAME);
				if (nw == -1) {
					if (errno == EPIPE) {
						int ret;

						ret = close(pctx->fifooutfd);
						if (ret == 0) {
							pctx->fifooutfd = -1;
							if (*pctx->verbose >= 2)
								msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Output fifo closed");
						}
					}
				}
			}
		}
	}

	return n+m;
}

static void allocate_encrypt_context(struct pc_context *pctx)
{
	switch (pctx->algo) {
	case algo_xtea:
		pctx->cipher_ctx = xcalloc(1, sizeof(struct xtea_ctx));
		break;
	case algo_cast128:
		pctx->cipher_ctx = xcalloc(1, sizeof(struct cast128_ctx));
		break;
	case algo_blowfish:
		pctx->cipher_ctx = xcalloc(1, sizeof(struct blowfish_ctx));
		break;
	case algo_camellia:
		pctx->cipher_ctx = xcalloc(1, sizeof(struct camellia_ctx));
		break;
	case algo_twofish:
		pctx->cipher_ctx = xcalloc(1, sizeof(struct twofish_ctx));
		break;
	}
}

static void init_encrypt_context(struct pc_context *pctx)
{
	switch (pctx->algo) {
	case algo_xtea:
		xtea_init(pctx->cipher_ctx, pctx->psk);
		break;
	case algo_cast128:
		cast128_init(pctx->cipher_ctx, pctx->psk);
		break;
	case algo_blowfish:
		blowfish_init(pctx->cipher_ctx, pctx->psk, pctx->psklen);
		break;
	case algo_camellia:
		camellia_init(pctx->cipher_ctx, pctx->psk, pctx->psklen);
		break;
	case algo_twofish:
		twofish_init(pctx->cipher_ctx, pctx->psk, pctx->psklen);
		break;
	}
}

const char *pc_engine_version_string(void)
{
	static char str[16];

	snprintf(str, 16, "%d.%d.%d", PC_ENGINE_VERSION_MAJOR, PC_ENGINE_VERSION_MINOR, PC_ENGINE_VERSION_SUBMINOR);

	return str;
}

int pc_engine_init(struct pc_context *pctx, const char *nick, uint16_t local_port, int bitrate, int complexity,
                   const char *audiodevice_playback, const char *audiodevice_capture, const char *fifoin,
                   const char *fifoout, int autoaccept_calls, struct pollfd *pfds, unsigned int *nfds, int *verbose)
{
	int ret, error, stdinfd;
	struct sockaddr_in local_addr;

	snprintf(msgbuf, MBS, "parole-conference-engine %s", pc_engine_version_string());
	logstr(msgbuf);

	/* make sure options are in valid range */
	if (bitrate < 6000 || bitrate > 512000) {
		snprintf(msgbuf, MBS, "Invalid bitrate (%d)", bitrate);
		goto engine_setup_fail;
	}
	if (complexity < 0 || complexity > 10) {
		snprintf(msgbuf, MBS, "Invalid complexity (%d)", complexity);
		goto engine_setup_fail;
	}

	/* clear parole-conference context (it'll clear nick, options and array of nodes) */
	memset(pctx, 0, sizeof(*pctx));
	strncpy(pctx->nick, nick, NICKLEN-1);
	pctx->local_port           = local_port;
	pctx->autoaccept_calls     = autoaccept_calls;
	pctx->verbose              = verbose;
	pctx->telemetry            = 1;
	pctx->rtt                  = 1;
	pctx->audiodevice_playback = audiodevice_playback;
	pctx->audiodevice_capture  = audiodevice_capture;
	pctx->micgain_dB           = 0.0f;
	pctx->fifoinfd             = -1;
	pctx->fifooutfd            = -1;
	pctx->bitrate              = bitrate;
	pctx->complexity           = complexity;
	pctx->mode                 = mode_secure;
	pctx->algo                 = algo_xtea;
	pctx->psklen               = 128;
	allocate_encrypt_context(pctx);
	init_encrypt_context(pctx);
	pctx->preferred_pgid       = pgid_2048;

	/* if no nick was specified, choose a random one */
	if (pctx->nick[0] == '\0') {
		int i;
		memcpy(pctx->nick, "guest", 5);
		for (i = 0; i < 3; i++)
			pctx->nick[i+5] = (char)('0' + (random_rand32() % 10));

		snprintf(msgbuf, MBS, "No nick was specified, setting nick to '%s'", pctx->nick);
		msgbook_enqueue(&mb0, MB_TYPE_WARNING, MODULE, msgbuf);
	}

	/* get stdin fd */
	stdinfd = fileno(stdin);
	if (stdinfd == -1) {
		snprintf(msgbuf, MBS, "fileno(): %s", strerror(errno));
		goto engine_setup_fail;
	}
	/* create socket */
	pctx->sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (pctx->sockfd == -1) {
		snprintf(msgbuf, MBS, "socket(): %s", strerror(errno));
		goto engine_setup_fail;
	}
	/* name socket (bind it to local_port) */
	local_addr.sin_family      = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port        = htons(pctx->local_port);
	ret = bind(pctx->sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr));
	if (ret == -1) {
		snprintf(msgbuf, MBS, "bind(): %s", strerror(errno));
		goto engine_setup_fail;
	}

	/* file descriptor for stdin  is at pfds[fd_idx_stdin] */
	*nfds                     = 0;
	fd_idx_stdin              = *nfds;
	pfds[fd_idx_stdin].fd     = stdinfd;
	pfds[fd_idx_stdin].events = POLLIN;
	*nfds                    += 1;

	/* file descriptor for socket is at pfds[fd_idx_udpsocket] */
	fd_idx_udpsocket              = *nfds;
	pfds[fd_idx_udpsocket].fd     = pctx->sockfd;
	pfds[fd_idx_udpsocket].events = POLLIN;
	*nfds                        += 1;

	/* init alsa audio capture */
	fd_idx_audiocapture = *nfds;
	pctx->audiodevice_capture = pctx->audiodevice_capture ? pctx->audiodevice_capture : pctx->audiodevice_playback;
	ret = audio_init(&pctx->ad_capture, pctx->audiodevice_capture, SND_PCM_STREAM_CAPTURE,
	                 samplerate, channels, pfds+*nfds, pctx->verbose);
	if (ret == -1)
		return -1;
	*nfds += pctx->ad_capture.nfds;

	/* init alsa audio playback */
	fd_idx_audioplayback = *nfds;
	ret = audio_init(&pctx->ad_playback, pctx->audiodevice_playback, SND_PCM_STREAM_PLAYBACK,
	                 samplerate, channels, pfds+*nfds, pctx->verbose);
	if (ret == -1)
		return -1;
	/* we won't poll this device */
	/* *nfds += pctx->ad_playback.nfds; */

	/* prepare input fifo */
	if (fifoin) {
		size_t len, maxlen;

		len = strlen(fifoin);
		maxlen = sizeof(pctx->fifoin) - 1;
		if (len > maxlen) {
			snprintf(msgbuf, MBS, "fifoin name too long (max = %zd)", maxlen);
			goto engine_setup_fail;
		}
		strcpy(pctx->fifoin, fifoin);

		pctx->fifoinfd = open(pctx->fifoin, O_RDONLY | O_NONBLOCK);
		if (pctx->fifoinfd == -1) {
			snprintf(msgbuf, MBS, "open(): %s", strerror(errno));
			goto engine_setup_fail;
		}
	}
	/* prepare output fifo */
	if (fifoout) {
		size_t len, maxlen;

		len = strlen(fifoout);
		maxlen = sizeof(pctx->fifoout) - 1;
		if (len > maxlen) {
			snprintf(msgbuf, MBS, "fifoout name too long (max = %zd)", maxlen);
			goto engine_setup_fail;
		}
		strcpy(pctx->fifoout, fifoout);
	}

	/* create encoder state */
	logstr(opus_get_version_string());
	pctx->enc = opus_encoder_create((opus_int32)samplerate, (int)channels, OPUS_APPLICATION_VOIP, &error);
	if (error != OPUS_OK) {
		snprintf(msgbuf, MBS, "opus error: %s", opus_strerror(error));
		goto engine_setup_fail;
	}
#if 0
	/* set maximum bandwidth */
	pctx->bandwidth = OPUS_BANDWIDTH_WIDEBAND;
	error = opus_encoder_ctl(pctx->enc, OPUS_SET_MAX_BANDWIDTH(pctx->bandwidth));
	if (error != OPUS_OK) {
		snprintf(msgbuf, MBS, "opus error: %s", opus_strerror(error));
		goto engine_setup_fail;
	}
#endif
	/* set bitrate */
	error = opus_encoder_ctl(pctx->enc, OPUS_SET_BITRATE(pctx->bitrate));
	if (error != OPUS_OK) {
		snprintf(msgbuf, MBS, "opus error: %s", opus_strerror(error));
		goto engine_setup_fail;
	}
#if 0
	/* force mono */
	error = opus_encoder_ctl(pctx->enc, OPUS_SET_FORCE_CHANNELS(1));
	if (error != OPUS_OK) {
		snprintf(msgbuf, MBS, "opus error: %s", opus_strerror(error));
		goto engine_setup_fail;
	}
#endif
	/* set complexity */
	error = opus_encoder_ctl(pctx->enc, OPUS_SET_COMPLEXITY(pctx->complexity));
	if (error != OPUS_OK) {
		snprintf(msgbuf, MBS, "opus error: %s", opus_strerror(error));
		goto engine_setup_fail;
	}
	/* set signal type */
	error = opus_encoder_ctl(pctx->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
	if (error != OPUS_OK) {
		snprintf(msgbuf, MBS, "opus error: %s", opus_strerror(error));
		goto engine_setup_fail;
	}
	/* set packet loss */
	error = opus_encoder_ctl(pctx->enc, OPUS_SET_PACKET_LOSS_PERC(1));
	if (error != OPUS_OK) {
		snprintf(msgbuf, MBS, "opus error: %s", opus_strerror(error));
		goto engine_setup_fail;
	}

	/* generate tones */
	tones_generate_tone(&pctx->tone, samplerate, channels, ONE_OPUS_FRAME);
	tones_generate_calltone(&pctx->calltone, samplerate, channels, ONE_OPUS_FRAME);
	tones_generate_ringtone(&pctx->ringtone, 3, samplerate, channels, ONE_OPUS_FRAME);

	return 0;

engine_setup_fail:
	msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
	return -1;
}

int pc_engine_start(struct pc_context *pctx)
{
	int ret;

	ret = audio_start(&pctx->ad_capture);

	return ret;
}

void pc_engine_fix_revents(struct pc_context *pctx, struct pollfd *pfds)
{
	audio_poll_descriptors_revents(&pctx->ad_capture);
	pfds[fd_idx_audiocapture].revents = (short)pctx->ad_capture.revents;
}

static void packet_decrypt(struct udp_packet *udp_packet_dec, const struct udp_packet *udp_packet,
                           enum pc_algo algo, const void *cipher_ctx)
{
	const uint8_t *d;
	size_t         l;
	uint32_t       iv32[2];
	uint64_t       iv64[2];
	uint8_t        padding_size;

	d = udp_packet->data + 2;
	l = udp_packet->len - 2;

	/* read initialization vector */
	if (algo >= algo_camellia) {
		iv64[0] = read_be64(d); d+=8; l-=8;
		iv64[1] = read_be64(d); d+=8; l-=8;
	} else {
		iv32[0] = read_be32(d); d+=4; l-=4;
		iv32[1] = read_be32(d); d+=4; l-=4;
	}

	/* copy payload to new packet */
	udp_packet_dec->addr = udp_packet->addr;
	memcpy(udp_packet_dec->data, d, l);
	udp_packet_dec->len = l;

	/* decrypt payload */
	switch (algo) {
	case algo_xtea:
		xtea_decrypt_buffer_cbc(cipher_ctx, udp_packet_dec->data, udp_packet_dec->len, iv32);
		break;
	case algo_cast128:
		cast128_decrypt_buffer_cbc(cipher_ctx, udp_packet_dec->data, udp_packet_dec->len, iv32);
		break;
	case algo_blowfish:
		blowfish_decrypt_buffer_cbc(cipher_ctx, udp_packet_dec->data, udp_packet_dec->len, iv32);
		break;
	case algo_camellia:
		camellia_decrypt_buffer_cbc(cipher_ctx, udp_packet_dec->data, udp_packet_dec->len, iv64);
		break;
	case algo_twofish:
		twofish_decrypt_buffer_cbc(cipher_ctx, udp_packet_dec->data, udp_packet_dec->len, iv64);
		break;
	}
	padding_size = udp_packet_dec->data[udp_packet_dec->len - 1];
	udp_packet_dec->len -= padding_size;
}

int pc_engine_network_ready(struct pc_context *pctx)
{
	struct udp_packet  udp_packet;
	const uint8_t     *d;
	size_t             l;
	uint16_t           packet_header, packet_mode, packet_family, packet_type;
	int                idx;

	/* read udp_packet */
	udp_receive_packet(pctx->sockfd, &udp_packet);
	pctx->bytes_in_per_sec += udp_packet.len;

	if (udp_packet.len < 2 || udp_packet.len >= UDP_PACKET_MAXLEN ||
	    udp_packet.len > UDP_PACKET_AUDIO_MAXLEN + /* FAMILY_ENCRYPTED header */ 18 + /* FAMILY_ENCRYPTED padding */ 16) {
		snprintf(msgbuf, MBS, "Received packet has invalid size (%zd)", udp_packet.len);
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return RES_ERROR;
	}

	d = udp_packet.data;
	l = udp_packet.len;
	packet_header = read_be16(d); d+=2; l-=2;
	packet_mode   = packet_header & UDP_PACKET_MASK_MODE;
	packet_family = packet_header & UDP_PACKET_MASK_FAMILY;
	packet_type   = packet_header & UDP_PACKET_MASK_TYPE;

	/* only packets with the right mode can pass */
	if (packet_mode == UDP_PACKET_MODE_RESERVED || pctx->mode != (packet_mode >> 14)) {
		if (*pctx->verbose >= 2) {
			snprintf(msgbuf, MBS, "Received packet has wrong mode (0x%04X)", packet_mode);
			msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		}
		return RES_ERROR;
	}

	switch (pctx->mode) {
	case mode_clear:
		return process_packet(pctx, &udp_packet);
		break;
	case mode_secure:
		if (packet_family == UDP_PACKET_FAMILY_HANDSHAKE) {
			return process_packet(pctx, &udp_packet);
		} else if (packet_family == UDP_PACKET_FAMILY_ENCRYPTED && packet_type <= UDP_PACKET_TYPE_TWOFISH) {
			struct udp_packet udp_packet_dec;
			size_t blocksize;

			idx = node_get_idx(pctx->nodes, udp_packet.addr);
			if (idx == -1) {
				if (*pctx->verbose >= 2)
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE,
					                "ENCRYPTED packet from unknown node, cannot decrypt (mode_secure)");
				return RES_ERROR;
			}
			if (pctx->nodes[idx]->status != STATUS_OK) {
				if (*pctx->verbose >= 2)
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Cannot decrypt ENCRYPTED packet, missing key (mode_secure)");
				return RES_ERROR;
			}

			blocksize = packet_type >= UDP_PACKET_TYPE_CAMELLIA ? 16 : 8;
			if (l <= blocksize || l % blocksize) {
				if (*pctx->verbose >= 2)
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Invalid ENCRYPTED packet size (mode_secure)");
				return RES_ERROR;
			}

			/* decrypt packet */
			packet_decrypt(&udp_packet_dec, &udp_packet, pctx->nodes[idx]->algo, pctx->nodes[idx]->cipher_ctx);

			if ((read_be16(udp_packet_dec.data) & UDP_PACKET_MASK_MODE) != UDP_PACKET_MODE_SECURE) {
				if (*pctx->verbose >= 2)
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Wrong mode after packet decryption (mode_secure)");
				return RES_ERROR;
			}

			/* process packet */
			return process_packet(pctx, &udp_packet_dec);
		} else {
			if (*pctx->verbose >= 2)
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Invalid FAMILY or TYPE in packet (mode_secure)");
			return RES_ERROR;
		}
		break;
	case mode_psk:
		/* process only packets encrypted with the right algorithm */
		if (packet_family == UDP_PACKET_FAMILY_ENCRYPTED && packet_type == UDP_PACKET_TYPE_XTEA + pctx->algo) {
			struct udp_packet udp_packet_dec;
			size_t blocksize;

			blocksize = packet_type >= UDP_PACKET_TYPE_CAMELLIA ? 16 : 8;
			if (l <= blocksize || l % blocksize) {
				if (*pctx->verbose >= 2)
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Invalid ENCRYPTED packet size (mode_psk)");
				return RES_ERROR;
			}

			/* decrypt packet */
			packet_decrypt(&udp_packet_dec, &udp_packet, pctx->algo, pctx->cipher_ctx);

			if ((read_be16(udp_packet_dec.data) & UDP_PACKET_MASK_MODE) != UDP_PACKET_MODE_PSK) {
				if (*pctx->verbose >= 2)
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Wrong mode after packet decryption (mode_psk)");
				return RES_ERROR;
			}

			/* process packet */
			return process_packet(pctx, &udp_packet_dec);
		} else {
			if (*pctx->verbose >= 2)
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Invalid FAMILY or TYPE in packet (mode_psk)");
			return RES_ERROR;
		}
		break;
	}
	return RES_ERROR;
}

void pc_engine_step(struct pc_context *pctx)
{
	int i;
	struct slist *p;

	/* age callers */
	p = pctx->callers;
	while (p) {
		struct slist *pnext = p->next;
		struct pc_caller *cl = p->data;

		if (cl->timeout <= 0) {
			struct pc_event *ev;

			/* push event */
			ev = event_push(&pctx->events, event_type_incoming_call_lost);
			ev->addr = cl->addr;
			memcpy(ev->nick, cl->nick, NICKLEN);

			free(cl);
			pctx->callers = slist_remove_element(pctx->callers, p);
		} else {
			cl->timeout--;
		}
		p = pnext;
	}

	/* decrement timeout counter, delete node after 6s without receiving packets */
	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (pctx->nodes[i]) {
			if (pctx->nodes[i]->timeout <= 0)
				node_delete(pctx->nodes, i, DELETE_REASON_TIMEOUT, &pctx->tone, &pctx->events);
			else
				pctx->nodes[i]->timeout--;
		}
	}

	/* send call packets periodically */
	if (pctx->call) {
		struct pc_sendrecipe *sr = pctx->call;
		int idx;

		idx = node_get_idx(pctx->nodes, sr->addr);
		if (idx == -1 || sr->packets_sent >= sr->resend_maxnum) {
			struct pc_event *ev;

			if (idx != -1)
				node_delete(pctx->nodes, idx, DELETE_REASON_LEFT, &pctx->tone, &pctx->events);

			/* push event */
			ev = event_push(&pctx->events, event_type_calling_aborted);
			ev->addr = sr->addr;

			free(pctx->call);
			pctx->call = NULL;
		} else {
			/* reset timeout counter */
			pctx->nodes[idx]->timeout = TIMEOUT;

			if (sr->resend_watchdog <= 0) {
				send_udp_packet_enc(pctx, &sr->udp_packet);

				sr->resend_watchdog = sr->resend_interval;
				sr->packets_sent++;
			} else {
				sr->resend_watchdog--;
			}
		}
	}
#if 0
	/* packets to send periodically */
	p = pctx->sendrecipes;
	while (p) {
		struct slist *pnext = p->next;
		struct pc_sendrecipe *sr = p->data;
		int idx;

		idx = node_get_idx(pctx->nodes, sr->addr);
		if (idx == -1 || sr->packets_sent >= sr->resend_maxnum) {
			free(sr);
			pctx->sendrecipes = slist_remove_element(pctx->sendrecipes, p);
		} else {
			/* reset timeout counter */
			pctx->nodes[idx]->timeout = TIMEOUT;

			if (sr->resend_watchdog <= 0) {
				send_udp_packet_enc(pctx, &sr->udp_packet);

				sr->resend_watchdog = sr->resend_interval;
				sr->packets_sent++;
				if (*pctx->verbose >= 2) {
					snprintf(msgbuf, MBS, "Resent packet for %s:%hu",
					         inet_ntoa(sr->udp_packet.addr.sin_addr), ntohs(sr->udp_packet.addr.sin_port));
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
				}
			} else {
				sr->resend_watchdog--;
			}
		}
		p = pnext;
	}
#endif

	/* connect packets or table packets might have gotten lost, so every
	   1s send out call requests to those who don't know about me,
	   eventually using relay to make sure packets get delivered */
	if ((1 + pctx->ic_talk + pctx->ic_mute) % 50 == 0)
		connect_new_nodes(pctx, 0);

	/* send telemetry, every 10s */
	if (pctx->telemetry && (1 + pctx->ic_total) % (10*50) == 0) {
		for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
			if (pctx->nodes[i] && pctx->nodes[i]->status == STATUS_OK) {
				uint32_t pl10k;
				struct udp_packet udp_packet;

				pl10k = (uint32_t)lrintf(10000.0f * pctx->nodes[i]->packet_loss);

				udp_packet.addr = pctx->nodes[i]->addr;
				packet_plinfo(&udp_packet, pctx->mode, pl10k);
				send_udp_packet_enc(pctx, &udp_packet);
			}
		}
	}

	/* send rtt request, every 2s */
	if (pctx->rtt && (1 + pctx->ic_total) % (2*50) == 0) {
		for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
			if (pctx->nodes[i] && pctx->nodes[i]->status == STATUS_OK) {
				struct udp_packet udp_packet;

				udp_packet.addr = pctx->nodes[i]->addr;
				packet_rttreq(&udp_packet, pctx->mode);
				send_udp_packet_enc(pctx, &udp_packet);
			}
		}
	}

	/* update stats */
	if (pctx->ic_total % 50 == 0) {
		pctx->packets_received_g = 0;
		pctx->packets_lost_g     = 0;
		for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
			if (pctx->nodes[i]) {
				pctx->packets_received_g += pctx->nodes[i]->packets_received;
				pctx->packets_lost_g     += pctx->nodes[i]->packets_lost;
			}
		}
		pctx->packet_loss_g = pctx->packets_received_g ?
		                      100.0f * (float)pctx->packets_lost_g /
		                      (float)(pctx->packets_lost_g + pctx->packets_received_g) : 0.0f;
		pctx->bw_upload   = (float)pctx->bytes_out_per_sec / 1024.0f;
		pctx->bw_download = (float)pctx->bytes_in_per_sec  / 1024.0f;
		pctx->bytes_out_per_sec = 0;
		pctx->bytes_in_per_sec  = 0;
	}
}

void pc_engine_audio_ready(struct pc_context *pctx)
{
	snd_pcm_sframes_t ret_frames;

	/* read ad_capture.period_size frames of audio */
	ret_frames = audio_read(&pctx->ad_capture, 1);
	if (ret_frames < 0) {
		int ret;
		/* overrun, let's handle it and try again */
		pctx->overruns++;
		ret = audio_recover(&pctx->ad_capture, (int)ret_frames, 1);
		if (ret == 0) {
			ret = audio_start(&pctx->ad_capture);
			if (ret == -1)
				die("audio_start() failed", 1);
			ret_frames = audio_read(&pctx->ad_capture, 0);
			if (ret_frames < 0)
				die("audio_read() failed", 1);
		} else {
			die("audio_recover() on capture failed", 1);
		}
	}

	/* make sure we have read an entire frame */
	if ((snd_pcm_uframes_t)pctx->ad_capture.frames != pctx->ad_capture.alsabuffersize) {
		snprintf(msgbuf, MBS, "audio_read() only read %ld frames instead of %lu",
		         pctx->ad_capture.frames, pctx->ad_capture.alsabuffersize);
		die(msgbuf, 1);
	}
	pctx->lb_pcmlen = (unsigned int)pctx->ad_capture.frames;

	if (!pctx->micmute) {
		int32_t ipeak;
		float peak_percent;
		double rms2;

		/* copy captured audio to loopback buffer */
		memcpy(pctx->lb_pcm, pctx->ad_capture.alsabuffer,
		       pctx->ad_capture.channels * (size_t)pctx->ad_capture.frames * sizeof(*pctx->ad_capture.alsabuffer));

		/* read from input fifo and mix */
		if (pctx->fifo && pctx->fifoinfd != -1) {
			opus_int16 fifo_pcm[2*ONE_OPUS_FRAME];
			ssize_t nr;

			memset(fifo_pcm, 0, sizeof(fifo_pcm));
			nr = read(pctx->fifoinfd, fifo_pcm, sizeof(fifo_pcm));
#if 0
			if (*pctx->verbose >= 2) {
				snprintf(msgbuf, MBS, "nr = %zd", nr);
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
			}
#endif
			if (nr > 0)
				adsp_sum_and_clip_s16_s16(pctx->lb_pcm, fifo_pcm, channels * pctx->lb_pcmlen);
		}

		/* amplify if necessary */
		if (pctx->micgain_dB != 0.0f)
			adsp_scale_and_clip_s16_s16(pctx->lb_pcm, channels * pctx->lb_pcmlen, powf(10.0f, pctx->micgain_dB/20.0f));

		/* find peak in captured audio */
		ipeak = adsp_find_peak_s16_2ch(pctx->lb_pcm, channels * pctx->lb_pcmlen);
		peak_percent = 100.0f * (float)ipeak / (float)(INT16_MAX+1);
		pctx->peak_percent = (pctx->peak_percent < peak_percent) ? peak_percent : pctx->peak_percent;

		/* dBSPL */
		pctx->sos   += adsp_sum_of_squares(pctx->lb_pcm, channels * pctx->lb_pcmlen);
		pctx->sos_N += channels * pctx->lb_pcmlen;
		rms2 = (double)(pctx->sos) / (double)pctx->sos_N;
		pctx->dBSPL = 10.0 * log10(1.0 /* to avoid -inf */ + rms2) - 90.3 /* 20*log10(1/32768.0) */;
	} else {
		/* insert silence in loopback buffer */
		memset(pctx->lb_pcm, 0, sizeof(pctx->lb_pcm));
	}

	/* if there are no nodes connected, there is nothing to do */
	if (node_get_count(pctx->nodes) == 0) {
		pctx->ic_talk = 0;
		pctx->ic_mute = 0;
	} else {
		struct udp_packet udp_packet;

		if (pctx->micmute) {
			if ((1+pctx->ic_total) % 50 == 0) { /* nop packets only every 1s */
				/* forge udp nop packet */
				packet_nop(&udp_packet, pctx->mode);

				/* send udp packet */
				send_udp_packet_enc_to_all(pctx, &udp_packet);
			}

			/* increment mute frame counter */
			pctx->ic_mute++;
		} else {
			uint8_t    opus_enc_packet[UDP_PACKET_AUDIO_PAYLOAD_LEN];
			opus_int32 opus_enc_packetlen;

			/* encoding */
			opus_enc_packetlen = opus_encode(pctx->enc, pctx->lb_pcm, (int)pctx->lb_pcmlen, opus_enc_packet, sizeof(opus_enc_packet));
			if (opus_enc_packetlen < 0) {
				snprintf(msgbuf, MBS, "opus_encode() failed: %s", opus_strerror(opus_enc_packetlen));
				msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
			} else {
				/* forge udp audio packet */
				packet_audio(&udp_packet, pctx->mode, pctx->ic_talk, opus_enc_packet, (size_t)opus_enc_packetlen);

				/* send udp packet */
				send_udp_packet_enc_to_all(pctx, &udp_packet);
			}

			/* increment talk frame counter */
			pctx->ic_talk++;
		}
	}

	/* mix audio */
	if (mix_audio(pctx)) {
		/* playback decoded data */
		ret_frames = audio_write(&pctx->ad_playback, pctx->pcm, pctx->pcmlen, 1);
		if (ret_frames < 0) {
			int ret;
			/* underrun, let's handle it and try again */
			pctx->underruns++;
			ret = audio_recover(&pctx->ad_playback, (int)ret_frames, 1);
			if (ret == 0) {
				ret_frames = audio_write(&pctx->ad_playback, pctx->pcm, pctx->pcmlen, 0);
				if (ret_frames < 0)
					die("audio_write() failed", 1);
			} else {
				die("audio_recover() on playback failed", 1);
			}
		}
	}

	/* increment total frame counter */
	pctx->ic_total++;
}

void pc_engine_goodbye(struct pc_context *pctx)
{
	struct udp_packet udp_packet;

	packet_bye(&udp_packet, pctx->mode);
	send_udp_packet_enc_to_all(pctx, &udp_packet);
}

void pc_engine_cleanup(struct pc_context *pctx)
{
	int i;

	/* stop recording if necessary */
	pc_engine_cmd_stop_recording(pctx);

	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (pctx->nodes[i])
			node_delete(pctx->nodes, i, DELETE_REASON_LEFT, &pctx->tone, &pctx->events);
	}
	if (pctx->fifoinfd != -1)
		close(pctx->fifoinfd);
	if (pctx->fifooutfd != -1)
		close(pctx->fifooutfd);
	close(pctx->sockfd);

	audio_stop(&pctx->ad_capture);
	audio_close(&pctx->ad_capture);
	audio_stop(&pctx->ad_playback);
	audio_close(&pctx->ad_playback);

	free(pctx->tone.pcm);
	free(pctx->calltone.pcm);
	free(pctx->ringtone.pcm);
	if (pctx->call)
		free(pctx->call);

	/* destroy encoder state */
	opus_encoder_destroy(pctx->enc);

	free(pctx->cipher_ctx);
}

static void update_bitrate_and_bandwidth(struct pc_context *pctx)
{
	int error;

	/* get bitrate */
	error = opus_encoder_ctl(pctx->enc, OPUS_GET_BITRATE(&pctx->bitrate));
	if (error != OPUS_OK)
		pctx->bitrate = 0;

	/* get bandwidth */
	error = opus_encoder_ctl(pctx->enc, OPUS_GET_BANDWIDTH(&pctx->bandwidth));
	if (error != OPUS_OK)
		pctx->bandwidth_hz = 0;
	else
		pctx->bandwidth_hz = convert_opus_bw(pctx->bandwidth);
}

void pc_engine_cmd_print_info(struct pc_context *pctx)
{
	unsigned int i;
	snd_pcm_sframes_t ret_frames;

	update_bitrate_and_bandwidth(pctx);

	/* read available frames */
	ret_frames = audio_avail(&pctx->ad_capture, 1);
	if (ret_frames < 0)
		pctx->ad_capture.avail = (snd_pcm_sframes_t)pctx->ad_capture.buffer_size;
	ret_frames = audio_avail(&pctx->ad_playback, 1);
	if (ret_frames < 0) {
		pctx->ad_playback.avail = 0;
		pctx->underruns++;
		audio_recover(&pctx->ad_playback, (int)ret_frames, 1);
	}

	snprintf(msgbuf, MBS,
"info:\n"
"  capture:   rb[%3.0f%%]   overrun[%2d]  gain[%+.1fdB]  mute[%s]\n"
"  playback:  rb[%3.0f%%]  underrun[%2d]  loopback[%s]\n"
"  opus:      bitrate[%5d bit/s]  bw[%d Hz]  cmplx[%2d]\n"
"  node:      mode[%s]  algo[%s]  psklen[%zd bit]\n"
"  options:   verbose[%d]  fifo[%s]  telemetry[%s]  rtt[%s]\n"
"  psk:       %08x%08x%08x%08x\n"
"             %08x%08x%08x%08x\n"
"             %08x%08x%08x%08x\n"
"  nodes: %u\n"
"    -:%15s:%-5hu %12s",
	100.0f * (float)pctx->ad_capture.avail/(float)pctx->ad_capture.buffer_size,
	pctx->overruns, pctx->micgain_dB, pctx->micmute ? " on" : "off",
	100.0f * (float)pctx->ad_playback.avail/(float)pctx->ad_playback.buffer_size,
	pctx->underruns, pctx->lb ? " on" : "off",
	pctx->bitrate, pctx->bandwidth_hz, pctx->complexity,
	pctx->mode == mode_clear ? "clear" : (pctx->mode == mode_secure ? "secure" : "psk"),
	pc_algo_name[pctx->algo], pctx->psklen,
	*pctx->verbose, pctx->fifo ? " on" : "off", pctx->telemetry ? " on" : "off", pctx->rtt ? " on" : "off",
	read_be32(pctx->psk),    read_be32(pctx->psk+4),  read_be32(pctx->psk+8),  read_be32(pctx->psk+12),
	read_be32(pctx->psk+16), read_be32(pctx->psk+20), read_be32(pctx->psk+24), read_be32(pctx->psk+28),
	read_be32(pctx->psk+32), read_be32(pctx->psk+36), read_be32(pctx->psk+40), read_be32(pctx->psk+44),
	node_get_count(pctx->nodes),
	pctx->external_ip[0] ? pctx->external_ip : "localhost", pctx->local_port, pctx->nick);

	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		size_t l;
		if (pctx->nodes[i]) {
			l = strlen(msgbuf);
			snprintf(msgbuf+l, MBS-l, "\n    %u:%15s:%-5hu %12s  pl[l%.2f%% t%.2f%%]  rtt[%3.0fms]  pcm[%3ums]  %+.0fdB%s",
			         i, inet_ntoa(pctx->nodes[i]->addr.sin_addr),
			         ntohs(pctx->nodes[i]->addr.sin_port), pctx->nodes[i]->nick,
			         pctx->nodes[i]->packet_loss, (float)pctx->nodes[i]->tm_pl10k / 10000.0f,
			         pctx->nodes[i]->rtt_us * 0.001,
			         20 * pctx->nodes[i]->nb_frames,
			         (float)pctx->nodes[i]->gain_Q8_dB / 256.0f,
			         pctx->nodes[i]->nb_frames ? "" : "  MUTE");
		}
	}
	msgbook_enqueue(&mb0, MB_TYPE_INFO, MODULE, msgbuf);
}

void pc_engine_cmd_toggle_mute(struct pc_context *pctx)
{
	pctx->micmute = (pctx->micmute == 0) ? 1 : 0;
	event_push(&pctx->events, event_type_mute);
}

void pc_engine_cmd_toggle_loopback(struct pc_context *pctx)
{
	pctx->lb = (pctx->lb == 0) ? 1 : 0;
	event_push(&pctx->events, event_type_loopback);
}

void pc_engine_cmd_toggle_tones(struct pc_context *pctx)
{
	pctx->tone.enable = (pctx->tone.enable == 0) ? 1 : 0;
	event_push(&pctx->events, event_type_tones);
}

void pc_engine_cmd_toggle_ringtone(struct pc_context *pctx)
{
	pctx->ringtone.enable = (pctx->ringtone.enable == 0) ? 1 : 0;
	event_push(&pctx->events, event_type_ringtone);
}

void pc_engine_cmd_toggle_autoaccept_calls(struct pc_context *pctx)
{
	pctx->autoaccept_calls = (pctx->autoaccept_calls == 0) ? 1 : 0;
	event_push(&pctx->events, event_type_autoaccept_calls);
}

void pc_engine_cmd_toggle_fifo(struct pc_context *pctx)
{
	pctx->fifo = (pctx->fifo == 0) ? 1 : 0;
	event_push(&pctx->events, event_type_fifo);
}

void pc_engine_cmd_stop_recording(struct pc_context *pctx)
{
	if (pctx->record == REC_WAVE) {
		wave_stop_recording(pctx->record_bytes_written, pctx->record_fp);
		pctx->record = 0;
		event_push(&pctx->events, event_type_recording);
	} else if (pctx->record == REC_OPUS) {
		memset(pctx->record_pcm, 0, sizeof(pctx->record_pcm));
		oggopus_write_data(pctx->record_pcm, ONE_OPUS_FRAME, pctx->record_enc, &pctx->record_oss,
		                   &pctx->record_packetno, 1, pctx->record_fp);
		oggopus_stop_recording(&pctx->record_enc, &pctx->record_oss, pctx->record_fp);
		pctx->record = 0;
		event_push(&pctx->events, event_type_recording);
	}
}

int pc_engine_cmd_toggle_recording(struct pc_context *pctx, int rec_format)
{
	if (rec_format != REC_WAVE && rec_format != REC_OPUS)
		rec_format = REC_OPUS;

	if (pctx->record == 0) {
		time_t now;
		struct tm *t;

		now = time(NULL);
		t = localtime(&now);

		if (t)
			snprintf(pctx->record_filename, 64, "rec_%04d%02d%02d_%02d%02d%02d",
			         t->tm_year+1900, t->tm_mon+1, t->tm_mday,
			         t->tm_hour, t->tm_min, t->tm_sec);
		else
			snprintf(pctx->record_filename, 64, "rec_%u", (unsigned int)now);

		if (rec_format == REC_WAVE) {
			strcat(pctx->record_filename, ".wav");
			pctx->record_fp = wave_start_recording(pctx->record_filename, samplerate, channels);
		} else {
			strcat(pctx->record_filename, ".opus");
			pctx->record_fp = oggopus_start_recording(pctx->record_filename, samplerate, channels,
			                                          &pctx->record_enc, &pctx->record_oss);
		}

		if (pctx->record_fp) {
			pctx->record               = rec_format;
			pctx->record_bytes_written = 0;
			pctx->record_packetno      = 2;
			event_push(&pctx->events, event_type_recording);
			return 0;
		} else {
			return -1;
		}
	} else {
		pc_engine_cmd_stop_recording(pctx);
		return 0;
	}
}

int pc_engine_cmd_set_micgain(struct pc_context *pctx, float gain_dB)
{
	if (-40.0f <= gain_dB && gain_dB <= 40.0f) {
		pctx->micgain_dB = gain_dB;
		event_push(&pctx->events, event_type_micgain);
		return 0;
	} else {
		return -1;
	}
}

int pc_engine_cmd_set_bitrate(struct pc_context *pctx, int bitrate)
{
	if (6000 <= bitrate && bitrate <= 512000) {
		opus_encoder_ctl(pctx->enc, OPUS_SET_BITRATE(bitrate));
		update_bitrate_and_bandwidth(pctx);
		event_push(&pctx->events, event_type_bitrate);
		return 0;
	} else {
		return -1;
	}
}

int pc_engine_cmd_set_mode(struct pc_context *pctx, int mode)
{
	if (mode == mode_clear || mode == mode_secure || mode == mode_psk) {
		pctx->mode = mode;
		event_push(&pctx->events, event_type_mode);
		return 0;
	} else {
		return -1;
	}
}

int pc_engine_cmd_set_algo(struct pc_context *pctx, int algo)
{
	if (algo == algo_xtea || algo == algo_cast128 || algo == algo_blowfish ||
	    algo == algo_camellia || algo == algo_twofish) {
		free(pctx->cipher_ctx);
		pctx->algo = algo;
		allocate_encrypt_context(pctx);
		init_encrypt_context(pctx);
		event_push(&pctx->events, event_type_setalgo);
		return 0;
	} else {
		return -1;
	}
}

static uint8_t hex2num(uint8_t c)
{
	if ('0' <= c && c <= '9')
		return (uint8_t)(c - '0');
	else if ('a' <= c && c <= 'f')
		return (uint8_t)(c - 'a' + 10);
	else if ('A' <= c && c <= 'F')
		return (uint8_t)(c - 'A' + 10);
	else
		return 0;
}

void pc_engine_cmd_set_psk(struct pc_context *pctx, const unsigned char *hexkey, size_t len)
{
	size_t i;

	/* convert key from hex and store it to key[] array */
	memset(pctx->psk, 0, sizeof(pctx->psk));
	len = len > 96 ? 96 : len;
	len = len - (len % 2);
	for (i = 0; i < len; i++)
		pctx->psk[i/2] |= (uint8_t)(hex2num(hexkey[i]) << 4*(1 - i%2));

	pctx->psklen = (4*len) < 128 ? 128 : (4*len);

	init_encrypt_context(pctx);

	event_push(&pctx->events, event_type_setpsk);
}

int pc_engine_cmd_set_nodegain(struct pc_context *pctx, int idx, float gain_dB)
{
#ifdef OPUS_SET_GAIN
	if (0 <= idx && idx < MAX_NUMBER_OF_NODES && pctx->nodes[idx] &&
	    -40.0f <= gain_dB && gain_dB <= 40.0f) {
		struct pc_event *ev;

		pctx->nodes[idx]->gain_Q8_dB = (opus_int32)lrintf(gain_dB * 256.0f);
		opus_decoder_ctl(pctx->nodes[idx]->dec, OPUS_SET_GAIN(pctx->nodes[idx]->gain_Q8_dB));

		ev = event_push(&pctx->events, event_type_nodegain);
		ev->addr = pctx->nodes[idx]->addr;
		memcpy(ev->nick, pctx->nodes[idx]->nick, NICKLEN);
		ev->f = gain_dB;

		return 0;
	} else {
		return -1;
	}
#else
	(void)pctx; (void)idx; (void)gain_dB; /* avoids warnings */
	msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Your version of libopus does not support OPUS_SET_GAIN");
	return -1;
#endif
}

int pc_engine_cmd_kill_node(struct pc_context *pctx, int idx)
{
	if (0 <= idx && idx < MAX_NUMBER_OF_NODES && pctx->nodes[idx]) {
		node_delete(pctx->nodes, idx, DELETE_REASON_LEFT, &pctx->tone, &pctx->events);
		return 0;
	}
	return -1;
}

int pc_engine_cmd_call_node(struct pc_context *pctx, const char *host, uint16_t port)
{
	struct udp_packet udp_packet;
	struct sockaddr_in addr;
	struct pc_event *ev;
	struct pc_sendrecipe *sr;
	int ret, idx;

	if (pctx->call) {
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "We're already calling a host");
		return -1;
	}

	ret = resolve_address(&addr, host, port, pctx->verbose);
	if (ret == -1)
		return -1;

	idx = node_get_idx(pctx->nodes, addr);
	if (idx == -1) {
		idx = node_add(pctx->nodes, addr, NULL, pctx->preferred_pgid, pctx->algo, &pctx->tone, &pctx->events);
		if (idx == -1)
			return -1;
		pctx->nodes[idx]->status = STATUS_CALLING;
	} else {
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "We're already connected to this host");
		return -1;
	}

	udp_packet.addr = addr;
	packet_call(&udp_packet, pctx->mode, pctx->nick, pctx->nodes[idx]->pgid, pctx->nodes[idx]->algo,
	            pctx->nodes[idx]->dhm.pklen, pctx->nodes[idx]->dhm.pk);

	/* insert packet in call sendrecipe */
	sr = xcalloc(1, sizeof(*sr));
	sr->addr            = addr;
	sr->udp_packet      = udp_packet;
	sr->resend_interval = 50; /* every second */
	sr->resend_maxnum   = 60; /* 60 times */
	sr->resend_watchdog = 0;  /* send as soon as possible */
	sr->packets_sent    = 0;
	pctx->call          = sr;

	/* push event */
	ev = event_push(&pctx->events, event_type_calling_in_progress);
	ev->addr = addr;

	return 0;
}

void pc_engine_cmd_abort_calling(struct pc_context *pctx)
{
	if (pctx->call) {
		struct pc_sendrecipe *sr = pctx->call;
		int idx;
		struct pc_event *ev;

		idx = node_get_idx(pctx->nodes, sr->addr);
		if (idx != -1)
			node_delete(pctx->nodes, idx, DELETE_REASON_LEFT, &pctx->tone, &pctx->events);

		/* push event */
		ev = event_push(&pctx->events, event_type_calling_aborted);
		ev->addr = sr->addr;

		free(pctx->call);
		pctx->call = NULL;
	}
}

void pc_engine_cmd_hangup(struct pc_context *pctx)
{
	int i;
	struct udp_packet udp_packet;

	packet_bye(&udp_packet, pctx->mode);
	send_udp_packet_enc_to_all(pctx, &udp_packet);

	for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
		if (pctx->nodes[i])
			node_delete(pctx->nodes, i, DELETE_REASON_LEFT, &pctx->tone, &pctx->events);
	}

	event_push(&pctx->events, event_type_call_hangup);
}

void pc_engine_cmd_send_chat(struct pc_context *pctx, const char *buf, size_t len)
{
	struct udp_packet udp_packet;
	struct pc_event *ev;

	/* push event */
	ev = event_push(&pctx->events, event_type_chat);
	/* ev->addr = ; */
	memcpy(ev->nick, pctx->nick, NICKLEN);
	ev->data = xmalloc(len);
	memcpy(ev->data, buf, len);

	packet_chat(&udp_packet, pctx->mode, buf, len);
	send_udp_packet_enc_to_all(pctx, &udp_packet);
}

void pc_engine_cmd_accept_call(struct pc_context *pctx)
{
	if (pctx->callers) {
		struct pc_caller *cl;
		int idx;
		struct pc_event *ev;
		struct udp_packet udp_packet_response;

		cl = pctx->callers->data;

		/* push event */
		ev = event_push(&pctx->events, event_type_chose_accepted);
		ev->addr = cl->addr;
		memcpy(ev->nick, cl->nick, NICKLEN);

		idx = node_add(pctx->nodes, cl->addr, cl->nick, cl->pgid, cl->algo, &pctx->tone, &pctx->events);
		if (idx == -1) {
			/* send refuse */
			udp_packet_response.addr = cl->addr;
			packet_refuse(&udp_packet_response, pctx->mode, REFUSE_REASON_FULL);
			send_udp_packet_enc(pctx, &udp_packet_response);
			return;
		}
		/* setup key */
		node_setup_cipher_and_key(pctx->nodes[idx], cl->pk, cl->pklen);
		pctx->nodes[idx]->status = STATUS_OK;

		/* send table */
		udp_packet_response.addr = cl->addr;
		packet_table(&udp_packet_response, pctx->mode, pctx->nodes[idx]->dhm.pklen,
		             pctx->nodes[idx]->dhm.pk, pctx->nick, pctx->nodes, idx);
		send_udp_packet_enc(pctx, &udp_packet_response);

		free(cl);
		pctx->callers = slist_remove_head(pctx->callers);
	}
}

void pc_engine_cmd_refuse_call(struct pc_context *pctx)
{
	if (pctx->callers) {
		struct pc_caller *cl;
		struct pc_event *ev;
		struct udp_packet udp_packet_response;

		cl = pctx->callers->data;

		/* push event */
		ev = event_push(&pctx->events, event_type_chose_refused);
		ev->addr = cl->addr;
		memcpy(ev->nick, cl->nick, NICKLEN);

		/* send refuse */
		udp_packet_response.addr = cl->addr;
		packet_refuse(&udp_packet_response, pctx->mode, REFUSE_REASON_USER);
		send_udp_packet_enc(pctx, &udp_packet_response);

		free(cl);
		pctx->callers = slist_remove_head(pctx->callers);
	}
}

int pc_engine_cmd_set_verbose(struct pc_context *pctx, int verbose)
{
	if (0 <= verbose && verbose <= 3) {
		*pctx->verbose = verbose;
		event_push(&pctx->events, event_type_verbose);
		return 0;
	} else {
		return -1;
	}
}

#undef MODULE
