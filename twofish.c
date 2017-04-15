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

/* Twofish Encryption Algorithm
 *
 * https://www.schneier.com/twofish.html
 * https://www.schneier.com/paper-twofish-paper.pdf
 */

#include <string.h>
#include "twofish.h"
#include "rw.h"

#ifdef DEBUG
#include <stdio.h>
#endif

static const uint8_t ror_4_1[16] = {
	0x0, 0x8, 0x1, 0x9, 0x2, 0xa, 0x3, 0xb, 0x4, 0xc, 0x5, 0xd, 0x6, 0xe, 0x7, 0xf
};

static const uint8_t t_q0[4][16] = {
	{0x8, 0x1, 0x7, 0xd, 0x6, 0xf, 0x3, 0x2, 0x0, 0xb, 0x5, 0x9, 0xe, 0xc, 0xa, 0x4},
	{0xe, 0xc, 0xb, 0x8, 0x1, 0x2, 0x3, 0x5, 0xf, 0x4, 0xa, 0x6, 0x7, 0x0, 0x9, 0xd},
	{0xb, 0xa, 0x5, 0xe, 0x6, 0xd, 0x9, 0x0, 0xc, 0x8, 0xf, 0x3, 0x2, 0x4, 0x7, 0x1},
	{0xd, 0x7, 0xf, 0x4, 0x1, 0x2, 0x6, 0xe, 0x9, 0xb, 0x3, 0x0, 0x8, 0x5, 0xc, 0xa}
};

static const uint8_t t_q1[4][16] = {
	{0x2, 0x8, 0xb, 0xd, 0xf, 0x7, 0x6, 0xe, 0x3, 0x1, 0x9, 0x4, 0x0, 0xa, 0xc, 0x5},
	{0x1, 0xe, 0x2, 0xb, 0x4, 0xc, 0x3, 0x7, 0x6, 0xd, 0xa, 0x5, 0xf, 0x9, 0x0, 0x8},
	{0x4, 0xc, 0x7, 0x5, 0x1, 0x6, 0x9, 0xa, 0x0, 0xe, 0xd, 0x8, 0x2, 0xb, 0x3, 0xf},
	{0xb, 0x9, 0x5, 0x1, 0xc, 0x3, 0xd, 0xe, 0x6, 0x4, 0x7, 0xf, 0x2, 0x0, 0x8, 0xa}
};

static const uint8_t MDS[4][4] = {
	{0x01, 0xef, 0x5b, 0x5b},
	{0x5b, 0xef, 0xef, 0x01},
	{0xef, 0x5b, 0x01, 0xef},
	{0xef, 0x01, 0xef, 0x5b}
};

static const uint8_t RS[4][8] = {
	{0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e},
	{0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5},
	{0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19},
	{0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03}
};

/* circular left shift (left rotation) */
#define LR32(x, c) ((x) << (c) | (x) >> (32 - (c)))
/* circular right shift (right rotation) */
#define RR32(x, c) ((x) >> (c) | (x) << (32 - (c)))

#define PERM_Q(T) \
	uint8_t a[5], b[5];\
\
	a[0] = x >> 4;\
	b[0] = x & 0x0f;\
\
	a[1] = a[0] ^ b[0];\
	b[1] = (uint8_t)(a[0] ^ ror_4_1[b[0]] ^ ((a[0] << 3) & 0x0f));\
\
	a[2] = T[0][a[1]];\
	b[2] = T[1][b[1]];\
\
	a[3] = a[2] ^ b[2];\
	b[3] = (uint8_t)(a[2] ^ ror_4_1[b[2]] ^ ((a[2] << 3) & 0x0f));\
\
	a[4] = T[2][a[3]];\
	b[4] = T[3][b[3]];\
\
	return (uint8_t)(16 * b[4] + a[4])


static uint8_t perm_q0(uint8_t x)
{
	PERM_Q(t_q0);
}

static uint8_t perm_q1(uint8_t x)
{
	PERM_Q(t_q1);
}

static uint8_t gfmul(uint8_t v, uint8_t a, uint8_t b)
{
	uint8_t i, prod, carry;

	prod = 0;
	for (i = 0; i < 8; i++) {
		if (b & 1)
			prod = prod ^ a;
		b = b >> 1;
		carry = a & 0x80;
		a = (uint8_t)(a << 1);
		if (carry)
			a = a ^ v;
	}

	return prod;
}

static void mult_by_mds(uint8_t z[4], const uint8_t y[4], uint16_t primitive_polynomial)
{
	uint8_t v;

	v = (uint8_t)(primitive_polynomial & 0xff);

	z[0] = gfmul(v, MDS[0][0], y[0]) ^ gfmul(v, MDS[0][1], y[1]) ^ gfmul(v, MDS[0][2], y[2]) ^ gfmul(v, MDS[0][3], y[3]);
	z[1] = gfmul(v, MDS[1][0], y[0]) ^ gfmul(v, MDS[1][1], y[1]) ^ gfmul(v, MDS[1][2], y[2]) ^ gfmul(v, MDS[1][3], y[3]);
	z[2] = gfmul(v, MDS[2][0], y[0]) ^ gfmul(v, MDS[2][1], y[1]) ^ gfmul(v, MDS[2][2], y[2]) ^ gfmul(v, MDS[2][3], y[3]);
	z[3] = gfmul(v, MDS[3][0], y[0]) ^ gfmul(v, MDS[3][1], y[1]) ^ gfmul(v, MDS[3][2], y[2]) ^ gfmul(v, MDS[3][3], y[3]);
}

static void mult_by_rs(uint8_t s[4], const uint8_t m[8], uint16_t primitive_polynomial)
{
	size_t i;
	uint8_t v;

	v = (uint8_t)(primitive_polynomial & 0xff);

	for (i = 0; i < 4; i++) {
		s[i] = gfmul(v, RS[i][0], m[0]) ^ gfmul(v, RS[i][1], m[1]) ^ gfmul(v, RS[i][2], m[2]) ^ gfmul(v, RS[i][3], m[3]) ^
		       gfmul(v, RS[i][4], m[4]) ^ gfmul(v, RS[i][5], m[5]) ^ gfmul(v, RS[i][6], m[6]) ^ gfmul(v, RS[i][7], m[7]);
	}
}

#define MAXK 4

static void func_h0(uint8_t y[4], uint32_t X, const uint32_t L[], size_t k)
{
	size_t i;
	uint8_t x[4], l[MAXK][4], w[MAXK+1][4];

	/* split word into bytes */
	x[0] = (uint8_t)(X      );
	x[1] = (uint8_t)(X >>  8);
	x[2] = (uint8_t)(X >> 16);
	x[3] = (uint8_t)(X >> 24);
	for (i = 0; i < k; i++) {
		l[i][0] = (uint8_t)(L[i]      );
		l[i][1] = (uint8_t)(L[i] >>  8);
		l[i][2] = (uint8_t)(L[i] >> 16);
		l[i][3] = (uint8_t)(L[i] >> 24);
	}

	/* w_k,j = x_j  for j = 0,...,3 */
	memset(w, 0, sizeof(w));
	w[k][0] = x[0];
	w[k][1] = x[1];
	w[k][2] = x[2];
	w[k][3] = x[3];

	/* k stages */
	if (k == 4) {
		w[3][0] = perm_q1(w[4][0]) ^ l[3][0];
		w[3][1] = perm_q0(w[4][1]) ^ l[3][1];
		w[3][2] = perm_q0(w[4][2]) ^ l[3][2];
		w[3][3] = perm_q1(w[4][3]) ^ l[3][3];
	}

	if (k >= 3) {
		w[2][0] = perm_q1(w[3][0]) ^ l[2][0];
		w[2][1] = perm_q1(w[3][1]) ^ l[2][1];
		w[2][2] = perm_q0(w[3][2]) ^ l[2][2];
		w[2][3] = perm_q0(w[3][3]) ^ l[2][3];
	}

	w[1][0] = perm_q0(w[2][0]) ^ l[1][0];
	w[1][1] = perm_q1(w[2][1]) ^ l[1][1];
	w[1][2] = perm_q0(w[2][2]) ^ l[1][2];
	w[1][3] = perm_q1(w[2][3]) ^ l[1][3];

	w[0][0] = perm_q0(w[1][0]) ^ l[0][0];
	w[0][1] = perm_q0(w[1][1]) ^ l[0][1];
	w[0][2] = perm_q1(w[1][2]) ^ l[0][2];
	w[0][3] = perm_q1(w[1][3]) ^ l[0][3];

	/* pass through s-boxes again */
	y[0] = perm_q1(w[0][0]);
	y[1] = perm_q0(w[0][1]);
	y[2] = perm_q1(w[0][2]);
	y[3] = perm_q0(w[0][3]);
}

static uint32_t func_h(uint32_t X, const uint32_t L[], size_t k)
{
	uint8_t y[4], z[4];

	func_h0(y, X, L, k);

	mult_by_mds(z, y, 0x169);

	return read_le32(z);
}

static uint32_t func_g(const struct twofish_ctx *ctx, uint32_t X)
{
#if 0
	uint8_t x[4], y[4], z[4];

	write_le32(x, X);

	y[0] = ctx->S0[x[0]];
	y[1] = ctx->S1[x[1]];
	y[2] = ctx->S2[x[2]];
	y[3] = ctx->S3[x[3]];

	mult_by_mds(z, y, 0x169); /* v(x) = x^8 + x^6 + x^5 + x^3 + 1 = {1 0110 1001} = 0x169 */

	return read_le32(z);
#else
	uint8_t x[4];
	uint32_t z;

	x[0] = (uint8_t)(X      );
	x[1] = (uint8_t)(X >>  8);
	x[2] = (uint8_t)(X >> 16);
	x[3] = (uint8_t)(X >> 24);

	z = ctx->SF0[x[0]] ^ ctx->SF1[x[1]] ^ ctx->SF2[x[2]] ^ ctx->SF3[x[3]];

	return z;
#endif
}

static void func_f(const struct twofish_ctx *ctx, uint32_t *F0, uint32_t *F1, uint32_t R0, uint32_t R1, uint32_t r)
{
	uint32_t T0, T1;

	T0 = func_g(ctx, R0);
	T1 = func_g(ctx, LR32(R1, 8));

#ifdef DEBUG
	printf("                                        %08X %08X\n", T0, T1);
#endif

	*F0 = T0 +   T1 + ctx->K[2*r+8];
	*F1 = T0 + 2*T1 + ctx->K[2*r+9];
}

static void twofish_encipher(const struct twofish_ctx *ctx, uint32_t *P0, uint32_t *P1, uint32_t *P2, uint32_t *P3)
{
	uint32_t r, R0, R1, R2, R3, F0, F1;

#ifdef DEBUG
	printf("R[-1]:  %08X  %08X  %08X  %08X\n", *P0, *P1, *P2, *P3);
#endif

	/* input whitening */
	R0 = *P0 ^ ctx->K[0];
	R1 = *P1 ^ ctx->K[1];
	R2 = *P2 ^ ctx->K[2];
	R3 = *P3 ^ ctx->K[3];

#ifdef DEBUG
	printf("R[ 0]:  %08X  %08X  %08X  %08X\n", R0, R1, R2, R3);
#endif

	/* 16 rounds */
	for (r = 0; r < 16; r++) {
		uint32_t tmpR0, tmpR1;

		tmpR0 = R0;
		tmpR1 = R1;

		func_f(ctx, &F0, &F1, R0, R1, r);

		R0 = RR32(R2 ^ F0, 1);
		R1 = LR32(R3, 1) ^ F1;
		R2 = tmpR0;
		R3 = tmpR1;

#ifdef DEBUG
		printf("R[%2d]:  %08X  %08X  %08X  %08X\n", r+1, R2, R3, R0, R1);
#endif
	}

	/* output whitening */
	R0 ^= ctx->K[6];
	R1 ^= ctx->K[7];
	R2 ^= ctx->K[4];
	R3 ^= ctx->K[5];

#ifdef DEBUG
	printf("R[17]:  %08X  %08X  %08X  %08X\n", R2, R3, R0, R1);
#endif

	/* undo last swap and store */
	*P0 = R2;
	*P1 = R3;
	*P2 = R0;
	*P3 = R1;
}

static void twofish_decipher(const struct twofish_ctx *ctx, uint32_t *P0, uint32_t *P1, uint32_t *P2, uint32_t *P3)
{
	uint32_t r;
	uint32_t R0, R1, R2, R3, F0, F1;

	R0 = *P0 ^ ctx->K[4];
	R1 = *P1 ^ ctx->K[5];
	R2 = *P2 ^ ctx->K[6];
	R3 = *P3 ^ ctx->K[7];

	for (r = 15; r <= 15 ; r--) {
		uint32_t tmpR0, tmpR1;

		tmpR0 = R0;
		tmpR1 = R1;

		func_f(ctx, &F0, &F1, R0, R1, r);

		R0 = LR32(R2, 1) ^ F0;
		R1 = RR32(R3 ^ F1, 1);
		R2 = tmpR0;
		R3 = tmpR1;
	}

	R0 ^= ctx->K[2];
	R1 ^= ctx->K[3];
	R2 ^= ctx->K[0];
	R3 ^= ctx->K[1];

	*P0 = R2;
	*P1 = R3;
	*P2 = R0;
	*P3 = R1;
}

void twofish_init(struct twofish_ctx *ctx, const uint8_t key[], size_t keylen)
{
	size_t k, i;
	const uint32_t rho = (1 << 24) + (1 << 16) + (1 << 8) + 1;
	uint32_t Meven[MAXK], Modd[MAXK], S[MAXK], u32;

	memset(ctx->key, 0, sizeof(ctx->key));

	ctx->keylen = keylen - (keylen % 8);
	ctx->keylen = ctx->keylen >= 256 ? 256 : ctx->keylen;
	memcpy(ctx->key, key, ctx->keylen / 8);
	if (ctx->keylen <= 128)
		ctx->keylen = 128;
	else if (ctx->keylen <= 192)
		ctx->keylen = 192;
	else if (ctx->keylen <= 256)
		ctx->keylen = 256;

	k = ctx->keylen / 64;

	/* compute Meven and Modd vectors of length k */
	for (i = 0; i < 2*k; i++) {
		uint32_t M;

		M = read_le32(ctx->key+4*i);
		if (i & 1)
			Modd[i >> 1]  = M;
		else
			Meven[i >> 1] = M;
	}

	/* compute S vector of length k */
	for (i = 0; i < k; i++) {
		uint8_t m[8], s[4];

		memcpy(m, ctx->key+8*i, 8);
		mult_by_rs(s, m, 0x14d); /* w(x) = x^8 + x^6 + x^3 + x^2 + 1 = {1 0100 1101} = 0x14d */
		S[k-1-i] = read_le32(s);
	}

	/* compute S-boxes */
	for (u32 = 0; u32 < 256; u32++) {
		uint8_t y[4], z[4];

		func_h0(y, u32*rho, S, k);
#if 0
		ctx->S0[u32] = y[0];
		ctx->S1[u32] = y[1];
		ctx->S2[u32] = y[2];
		ctx->S3[u32] = y[3];
#else
		z[0] = gfmul(0x69, MDS[0][0], y[0]);
		z[1] = gfmul(0x69, MDS[1][0], y[0]);
		z[2] = gfmul(0x69, MDS[2][0], y[0]);
		z[3] = gfmul(0x69, MDS[3][0], y[0]);
		ctx->SF0[u32] = read_le32(z);

		z[0] = gfmul(0x69, MDS[0][1], y[1]);
		z[1] = gfmul(0x69, MDS[1][1], y[1]);
		z[2] = gfmul(0x69, MDS[2][1], y[1]);
		z[3] = gfmul(0x69, MDS[3][1], y[1]);
		ctx->SF1[u32] = read_le32(z);

		z[0] = gfmul(0x69, MDS[0][2], y[2]);
		z[1] = gfmul(0x69, MDS[1][2], y[2]);
		z[2] = gfmul(0x69, MDS[2][2], y[2]);
		z[3] = gfmul(0x69, MDS[3][2], y[2]);
		ctx->SF2[u32] = read_le32(z);

		z[0] = gfmul(0x69, MDS[0][3], y[3]);
		z[1] = gfmul(0x69, MDS[1][3], y[3]);
		z[2] = gfmul(0x69, MDS[2][3], y[3]);
		z[3] = gfmul(0x69, MDS[3][3], y[3]);
		ctx->SF3[u32] = read_le32(z);
#endif
	}

	/* compute key words K[] */
	for (u32 = 0; u32 < 20; u32++) {
		uint32_t A, B, t;

		A = func_h((2*u32  )*rho, Meven, k);
		t = func_h((2*u32+1)*rho, Modd,  k);
		B = LR32(t, 8);
		ctx->K[2*u32  ] = A + B;
		t = A + 2*B;
		ctx->K[2*u32+1] = LR32(t, 9);

#ifdef DEBUG
		printf("%08X  %08X\n", ctx->K[2*u32], ctx->K[2*u32+1]);
#endif
	}
}

void twofish_encrypt_buffer_ecb(const struct twofish_ctx *ctx, uint8_t *buf, size_t len)
{
	size_t i;
	uint32_t p0, p1, p2, p3;

	for (i = 0; i + 15 < len; i += 16) {
		p0 = read_le32(buf + i);
		p1 = read_le32(buf + i + 4);
		p2 = read_le32(buf + i + 8);
		p3 = read_le32(buf + i + 12);
		twofish_encipher(ctx, &p0, &p1, &p2, &p3);
		write_le32(buf + i,      p0);
		write_le32(buf + i + 4,  p1);
		write_le32(buf + i + 8,  p2);
		write_le32(buf + i + 12, p3);
	}
}

void twofish_decrypt_buffer_ecb(const struct twofish_ctx *ctx, uint8_t *buf, size_t len)
{
	size_t i;
	uint32_t p0, p1, p2, p3;

	for (i = 0; i + 15 < len; i += 16) {
		p0 = read_le32(buf + i);
		p1 = read_le32(buf + i + 4);
		p2 = read_le32(buf + i + 8);
		p3 = read_le32(buf + i + 12);
		twofish_decipher(ctx, &p0, &p1, &p2, &p3);
		write_le32(buf + i,      p0);
		write_le32(buf + i + 4,  p1);
		write_le32(buf + i + 8,  p2);
		write_le32(buf + i + 12, p3);
	}
}

void twofish_encrypt_buffer_cbc(const struct twofish_ctx *ctx, uint8_t *buf, size_t len, const uint64_t iv[2])
{
	size_t i;
	uint32_t p0, p1, p2, p3, iiv[4];

	iiv[0] = (uint32_t)(iv[0] >> 32) & 0xffffffff;
	iiv[1] = (uint32_t)(iv[0]      ) & 0xffffffff;
	iiv[2] = (uint32_t)(iv[1] >> 32) & 0xffffffff;
	iiv[3] = (uint32_t)(iv[1]      ) & 0xffffffff;
	for (i = 0; i + 15 < len; i += 16) {
		p0 = read_le32(buf + i)      ^ iiv[0];
		p1 = read_le32(buf + i + 4)  ^ iiv[1];
		p2 = read_le32(buf + i + 8)  ^ iiv[2];
		p3 = read_le32(buf + i + 12) ^ iiv[3];
		twofish_encipher(ctx, &p0, &p1, &p2, &p3);
		write_le32(buf + i,      p0);
		write_le32(buf + i + 4,  p1);
		write_le32(buf + i + 8,  p2);
		write_le32(buf + i + 12, p3);
		iiv[0] = p0;
		iiv[1] = p1;
		iiv[2] = p2;
		iiv[3] = p3;
	}
}

void twofish_decrypt_buffer_cbc(const struct twofish_ctx *ctx, uint8_t *buf, size_t len, const uint64_t iv[2])
{
	size_t i;
	uint32_t p0, p1, p2, p3, iiv[4], ct[4];

	iiv[0] = (uint32_t)(iv[0] >> 32) & 0xffffffff;
	iiv[1] = (uint32_t)(iv[0]      ) & 0xffffffff;
	iiv[2] = (uint32_t)(iv[1] >> 32) & 0xffffffff;
	iiv[3] = (uint32_t)(iv[1]      ) & 0xffffffff;
	for (i = 0; i + 15 < len; i += 16) {
		ct[0] = p0 = read_le32(buf + i);
		ct[1] = p1 = read_le32(buf + i + 4);
		ct[2] = p2 = read_le32(buf + i + 8);
		ct[3] = p3 = read_le32(buf + i + 12);
		twofish_decipher(ctx, &p0, &p1, &p2, &p3);
		write_le32(buf + i,      p0 ^ iiv[0]);
		write_le32(buf + i + 4,  p1 ^ iiv[1]);
		write_le32(buf + i + 8,  p2 ^ iiv[2]);
		write_le32(buf + i + 12, p3 ^ iiv[3]);
		iiv[0] = ct[0];
		iiv[1] = ct[1];
		iiv[2] = ct[2];
		iiv[3] = ct[3];
	}
}

#ifdef SELFTEST
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define BUFDIM (10*1024*1024)
#define RUNS   3

int main(int argc, char *argv[])
{
	struct twofish_ctx ctx;
	const uint8_t key128[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	const uint8_t key192[24] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	                            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
	const uint8_t key256[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	                            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	const uint8_t     pt[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	const uint8_t  ct128[16] = {0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A};
	const uint8_t  ct192[16] = {0xCF, 0xD1, 0xD2, 0xE5, 0xA9, 0xBE, 0x9C, 0xDF, 0x50, 0x1F, 0x13, 0xB8, 0x92, 0xBD, 0x22, 0x48};
	const uint8_t  ct256[16] = {0x37, 0x52, 0x7B, 0xE0, 0x05, 0x23, 0x34, 0xB8, 0x9F, 0x0C, 0xFC, 0xCA, 0xE8, 0x7C, 0xFA, 0x20};
	uint8_t       buf[16];
	int cmp_enc, cmp_dec;

	fprintf(stderr, "Twofish-128 selftest\n");
	memcpy(buf, pt, sizeof(pt));
	twofish_init(&ctx, key128, 128);
	fprintf(stderr, "128-bit key         = %08X%08X%08X%08X\n", read_be32(key128), read_be32(key128+4), read_be32(key128+8), read_be32(key128+12));
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	twofish_encrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        ciphertext  = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_enc = memcmp(buf, ct128, 16);
	twofish_decrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_dec = memcmp(buf, pt, 16);

	if (cmp_enc || cmp_dec) {
		fprintf(stderr, "ERROR\n");
		return 1;
	}
	fprintf(stderr, "OK\n");

	fprintf(stderr, "Twofish-192 selftest\n");
	memcpy(buf, pt, sizeof(pt));
	twofish_init(&ctx, key192, 192);
	fprintf(stderr, "192-bit key         = %08X%08X%08X%08X%08X%08X\n", read_be32(key192), read_be32(key192+4), read_be32(key192+8), read_be32(key192+12), read_be32(key192+16), read_be32(key192+20));
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	twofish_encrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        ciphertext  = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_enc = memcmp(buf, ct192, 16);
	twofish_decrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_dec = memcmp(buf, pt, 16);

	if (cmp_enc || cmp_dec) {
		fprintf(stderr, "ERROR\n");
		return 1;
	}
	fprintf(stderr, "OK\n");

	fprintf(stderr, "Twofish-256 selftest\n");
	memcpy(buf, pt, sizeof(pt));
	twofish_init(&ctx, key256, 256);
	fprintf(stderr, "256-bit key         = %08X%08X%08X%08X%08X%08X%08X%08X\n", read_be32(key256), read_be32(key256+4), read_be32(key256+8), read_be32(key256+12), read_be32(key256+16), read_be32(key256+20), read_be32(key256+24), read_be32(key256+28));
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	twofish_encrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        ciphertext  = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_enc = memcmp(buf, ct256, 16);
	twofish_decrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_dec = memcmp(buf, pt, 16);

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
			twofish_init(&ctx, key128, 128);
			fprintf(stderr, "encrypt:\n");
			for (i = 0; i < RUNS; i++) {
				gettimeofday(&t0,  NULL);
				twofish_encrypt_buffer_ecb(&ctx, buf, BUFDIM);
				gettimeofday(&t1,  NULL);
				PRINT_INTERVAL;
			}
			fprintf(stderr, "decrypt:\n");
			for (i = 0; i < RUNS; i++) {
				gettimeofday(&t0,  NULL);
				twofish_decrypt_buffer_ecb(&ctx, buf, BUFDIM);
				gettimeofday(&t1,  NULL);
				PRINT_INTERVAL;
			}
			free(buf);
		}
	}

	return 0;
}

#endif
