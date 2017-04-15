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

/* XTEA Encryption Algorithm */

#include "xtea.h"
#include "rw.h"

#ifdef SMALL
static void xtea_encipher(const struct xtea_ctx *ctx, uint32_t v[2])
{
	uint32_t i, v0, v1, sum = 0, delta = 0x9E3779B9;

	v0 = v[0];
	v1 = v[1];

	for (i = 0; i < 32; i++) {
		v0  += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ctx->key[sum & 3]);
		sum += delta;
		v1  += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ctx->key[(sum>>11) & 3]);
	}

	v[0] = v0;
	v[1] = v1;
}

static void xtea_decipher(const struct xtea_ctx *ctx, uint32_t v[2])
{
	uint32_t i, v0, v1, delta = 0x9E3779B9, sum = delta*32;

	v0 = v[0];
	v1 = v[1];

	for (i = 0; i < 32; i++) {
		v1  -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ctx->key[(sum>>11) & 3]);
		sum -= delta;
		v0  -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ctx->key[sum & 3]);
	}

	v[0] = v0;
	v[1] = v1;
}
#else

#define RF02(i)                                                \
do {                                                           \
	v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (ctx->subkey[i]);   \
	v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (ctx->subkey[i+1]); \
} while (0)
#define RF04(i) RF02(i); RF02(i+2)
#define RF08(i) RF04(i); RF04(i+4)
#define RF16(i) RF08(i); RF08(i+8)
#define RF32(i) RF16(i); RF16(i+16)

static void xtea_encipher(const struct xtea_ctx *ctx, uint32_t v[2])
{
	uint32_t v0, v1;

	v0 = v[0];
	v1 = v[1];

	RF32(0);
	RF32(32);

	v[0] = v0;
	v[1] = v1;
}

#define RR02(i)                                                \
do {                                                           \
	v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (ctx->subkey[i]);   \
	v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (ctx->subkey[i-1]); \
} while (0)
#define RR04(i) RR02(i); RR02(i-2)
#define RR08(i) RR04(i); RR04(i-4)
#define RR16(i) RR08(i); RR08(i-8)
#define RR32(i) RR16(i); RR16(i-16)

static void xtea_decipher(const struct xtea_ctx *ctx, uint32_t v[2])
{
	uint32_t v0, v1;

	v0 = v[0];
	v1 = v[1];

	RR32(63);
	RR32(31);

	v[0] = v0;
	v[1] = v1;
}
#endif

void xtea_init(struct xtea_ctx *ctx, const uint8_t key[16])
{
	size_t i;
#ifndef SMALL
	uint32_t sum = 0, delta = 0x9E3779B9;
#endif

	for (i = 0; i < 4; i++)
		ctx->key[i] = read_be32(key + 4*i);

#ifndef SMALL
	for (i = 0; i < 64; i += 2) {
		ctx->subkey[i]   = (sum + ctx->key[sum & 3]);
		sum += delta;
		ctx->subkey[i+1] = (sum + ctx->key[(sum>>11) & 3]);
	}
#endif
}

void xtea_encrypt_buffer_ecb(const struct xtea_ctx *ctx, uint8_t *buf, size_t len)
{
	size_t i;
	uint32_t v[2];

	for (i = 0; i + 7 < len; i += 8) {
		v[0] = read_be32(buf + i);
		v[1] = read_be32(buf + i + 4);
		xtea_encipher(ctx, v);
		write_be32(buf + i,     v[0]);
		write_be32(buf + i + 4, v[1]);
	}
}

void xtea_decrypt_buffer_ecb(const struct xtea_ctx *ctx, uint8_t *buf, size_t len)
{
	size_t i;
	uint32_t v[2];

	for (i = 0; i + 7 < len; i += 8) {
		v[0] = read_be32(buf + i);
		v[1] = read_be32(buf + i + 4);
		xtea_decipher(ctx, v);
		write_be32(buf + i,     v[0]);
		write_be32(buf + i + 4, v[1]);
	}
}

void xtea_encrypt_buffer_cbc(const struct xtea_ctx *ctx, uint8_t *buf, size_t len, const uint32_t iv[2])
{
	size_t i;
	uint32_t v[2], iiv[2];

	iiv[0] = iv[0];
	iiv[1] = iv[1];
	for (i = 0; i + 7 < len; i += 8) {
		v[0] = read_be32(buf + i)     ^ iiv[0];
		v[1] = read_be32(buf + i + 4) ^ iiv[1];
		xtea_encipher(ctx, v);
		write_be32(buf + i,     v[0]);
		write_be32(buf + i + 4, v[1]);
		iiv[0] = v[0];
		iiv[1] = v[1];
	}
}

void xtea_decrypt_buffer_cbc(const struct xtea_ctx *ctx, uint8_t *buf, size_t len, const uint32_t iv[2])
{
	size_t i;
	uint32_t v[2], iiv[2], ct[2];

	iiv[0] = iv[0];
	iiv[1] = iv[1];
	for (i = 0; i + 7 < len; i += 8) {
		ct[0] = v[0] = read_be32(buf + i);
		ct[1] = v[1] = read_be32(buf + i + 4);
		xtea_decipher(ctx, v);
		write_be32(buf + i,     v[0] ^ iiv[0]);
		write_be32(buf + i + 4, v[1] ^ iiv[1]);
		iiv[0] = ct[0];
		iiv[1] = ct[1];
	}
}

void xtea_encrypt_buffer_ctr(const struct xtea_ctx *ctx, uint8_t *buf, size_t len, const uint32_t iv[2])
{
	size_t i;
	uint32_t v[2], counter[2], ks[2];

	counter[0] = 0;
	counter[1] = 0;

	for (i = 0; i + 7 < len; i += 8) {
		ks[0] = iv[0] ^ counter[0];
		ks[1] = iv[1] ^ counter[1];
		xtea_encipher(ctx, ks);
		v[0] = read_be32(buf + i)     ^ ks[0];
		v[1] = read_be32(buf + i + 4) ^ ks[1];
		write_be32(buf + i,     v[0]);
		write_be32(buf + i + 4, v[1]);

		if (counter[1] == UINT32_MAX)
			counter[0]++;
		counter[1]++;
	}
}

#ifdef SELFTEST
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#define BUFDIM (10*1024*1024)
#define RUNS   3

int main(int argc, char *argv[])
{
	struct xtea_ctx ctx;
	const uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A};
	const uint8_t   pt[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
	const uint8_t   ct[8] = {0xFC, 0x26, 0xD7, 0xC7, 0xEB, 0xC9, 0x77, 0xCF};
	uint8_t        buf[8];
	int cmp_enc, cmp_dec;

	fprintf(stderr, "XTEA selftest\n");
	memcpy(buf, pt, sizeof(pt));
	xtea_init(&ctx, key);
	fprintf(stderr, "128-bit key         = %08X%08X%08X%08X\n", read_be32(key), read_be32(key+4), read_be32(key+8), read_be32(key+12));
	fprintf(stderr, "        plaintext   = %08X%08X\n", read_be32(buf), read_be32(buf+4));
	xtea_encrypt_buffer_ecb(&ctx, buf, 8);
	fprintf(stderr, "        ciphertext  = %08X%08X\n", read_be32(buf), read_be32(buf+4));
	cmp_enc = memcmp(buf, ct, 8);
	xtea_decrypt_buffer_ecb(&ctx, buf, 8);
	fprintf(stderr, "        plaintext   = %08X%08X\n", read_be32(buf), read_be32(buf+4));
	cmp_dec = memcmp(buf, pt, 8);

	if (cmp_enc || cmp_dec) {
		fprintf(stderr, "ERROR\n");
		return 1;
	}
	fprintf(stderr, "OK\n");

	if (argc > 1 && argv[1]) {
		size_t i;
		uint8_t *buf = calloc(1, BUFDIM);
		struct timeval t0, t1;
		double interval;

#define PRINT_INTERVAL \
do { \
	interval = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_usec - t0.tv_usec) / 1000000.0; \
	fprintf(stderr, "  run = %zd, time = %.3fs, speed = %.2f Mb/s\n", \
	        i, interval, (double)BUFDIM / (interval * 1024.0 * 1024.0)); \
} while (0)

		if (buf) {
			fprintf(stderr, "encrypt:\n");
			for (i = 0; i < RUNS; i++) {
				gettimeofday(&t0,  NULL);
				xtea_encrypt_buffer_ecb(&ctx, buf, BUFDIM);
				gettimeofday(&t1,  NULL);
				PRINT_INTERVAL;
			}
			fprintf(stderr, "decrypt:\n");
			for (i = 0; i < RUNS; i++) {
				gettimeofday(&t0,  NULL);
				xtea_decrypt_buffer_ecb(&ctx, buf, BUFDIM);
				gettimeofday(&t1,  NULL);
				PRINT_INTERVAL;
			}
			free(buf);
		}
	}

	return 0;
}
#endif
