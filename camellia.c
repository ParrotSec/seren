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

/* Camellia Encryption Algorithm, RFC3713 */

#include <string.h>
#include "camellia.h"
#include "rw.h"

#ifdef DEBUG
#include <stdio.h>
#endif

static const uint8_t SBOX1[256] = {
112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
 35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
 20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
 16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
 82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
 64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
};

static const uint8_t SBOX2[256] = {
224,   5,  88, 217, 103,  78, 129, 203, 201,  11, 174, 106, 213,  24,  93, 130,
 70, 223, 214,  39, 138,  50,  75,  66, 219,  28, 158, 156,  58, 202,  37, 123,
 13, 113,  95,  31, 248, 215,  62, 157, 124,  96, 185, 190, 188, 139,  22,  52,
 77, 195, 114, 149, 171, 142, 186, 122, 179,   2, 180, 173, 162, 172, 216, 154,
 23,  26,  53, 204, 247, 153,  97,  90, 232,  36,  86,  64, 225,  99,   9,  51,
191, 152, 151, 133, 104, 252, 236,  10, 218, 111,  83,  98, 163,  46,   8, 175,
 40, 176, 116, 194, 189,  54,  34,  56, 100,  30,  57,  44, 166,  48, 229,  68,
253, 136, 159, 101, 135, 107, 244,  35,  72,  16, 209,  81, 192, 249, 210, 160,
 85, 161,  65, 250,  67,  19, 196,  47, 168, 182,  60,  43, 193, 255, 200, 165,
 32, 137,   0, 144,  71, 239, 234, 183,  21,   6, 205, 181,  18, 126, 187,  41,
 15, 184,   7,   4, 155, 148,  33, 102, 230, 206, 237, 231,  59, 254, 127, 197,
164,  55, 177,  76, 145, 110, 141, 118,   3,  45, 222, 150,  38, 125, 198,  92,
211, 242,  79,  25,  63, 220, 121,  29,  82, 235, 243, 109,  94, 251, 105, 178,
240,  49,  12, 212, 207, 140, 226, 117, 169,  74,  87, 132,  17,  69,  27, 245,
228,  14, 115, 170, 241, 221,  89,  20, 108, 146,  84, 208, 120, 112, 227,  73,
128,  80, 167, 246, 119, 147, 134, 131,  42, 199,  91, 233, 238, 143,   1,  61
};

static const uint8_t SBOX3[256] = {
 56,  65,  22, 118, 217, 147,  96, 242, 114, 194, 171, 154, 117,   6,  87, 160,
145, 247, 181, 201, 162, 140, 210, 144, 246,   7, 167,  39, 142, 178,  73, 222,
 67,  92, 215, 199,  62, 245, 143, 103,  31,  24, 110, 175,  47, 226, 133,  13,
 83, 240, 156, 101, 234, 163, 174, 158, 236, 128,  45, 107, 168,  43,  54, 166,
197, 134,  77,  51, 253, 102,  88, 150,  58,   9, 149,  16, 120, 216,  66, 204,
239,  38, 229,  97,  26,  63,  59, 130, 182, 219, 212, 152, 232, 139,   2, 235,
 10,  44,  29, 176, 111, 141, 136,  14,  25, 135,  78,  11, 169,  12, 121,  17,
127,  34, 231,  89, 225, 218,  61, 200,  18,   4, 116,  84,  48, 126, 180,  40,
 85, 104,  80, 190, 208, 196,  49, 203,  42, 173,  15, 202, 112, 255,  50, 105,
  8,  98,   0,  36, 209, 251, 186, 237,  69, 129, 115, 109, 132, 159, 238,  74,
195,  46, 193,   1, 230,  37,  72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
 41, 205, 108,  19, 100, 155,  99, 157, 192,  75, 183, 165, 137,  95, 177,  23,
244, 188, 211,  70, 207,  55,  94,  71, 148, 250, 252,  91, 151, 254,  90, 172,
 60,  76,   3,  53, 243,  35, 184,  93, 106, 146, 213,  33,  68,  81, 198, 125,
 57, 131, 220, 170, 124, 119,  86,   5,  27, 164,  21,  52,  30,  28, 248,  82,
 32,  20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227,  64,  79
};

static const uint8_t SBOX4[256] = {
112,  44, 179, 192, 228,  87, 234, 174,  35, 107,  69, 165, 237,  79,  29, 146,
134, 175, 124,  31,  62, 220,  94,  11, 166,  57, 213,  93, 217,  90,  81, 108,
139, 154, 251, 176, 116,  43, 240, 132, 223, 203,  52, 118, 109, 169, 209,   4,
 20,  58, 222,  17,  50, 156,  83, 242, 254, 207, 195, 122,  36, 232,  96, 105,
170, 160, 161,  98,  84,  30, 224, 100,  16,   0, 163, 117, 138, 230,   9, 221,
135, 131, 205, 144, 115, 246, 157, 191,  82, 216, 200, 198, 129, 111,  19,  99,
233, 167, 159, 188,  41, 249,  47, 180, 120,   6, 231, 113, 212, 171, 136, 141,
114, 185, 248, 172,  54,  42,  60, 241,  64, 211, 187,  67,  21, 173, 119, 128,
130, 236,  39, 229, 133,  53,  12,  65, 239, 147,  25,  33,  14,  78, 101, 189,
184, 143, 235, 206,  48,  95, 197,  26, 225, 202,  71,  61,   1, 214,  86,  77,
 13, 102, 204,  45,  18,  32, 177, 153,  76, 194, 126,   5, 183,  49,  23, 215,
 88,  97,  27,  28,  15,  22,  24,  34,  68, 178, 181, 145,   8, 168, 252,  80,
208, 125, 137, 151,  91, 149, 255, 210, 196,  72, 247, 219,   3, 218,  63, 148,
 92,   2,  74,  51, 103, 243, 127, 226, 155,  38,  55,  59, 150,  75, 190,  46,
121, 140, 110, 142, 245, 182, 253,  89, 152, 106,  70, 186,  37,  66, 162, 250,
  7,  85, 238,  10,  73, 104,  56, 164,  40, 123, 201, 193, 227, 244, 199, 158
};

static const uint64_t Sigma1 = 0xA09E667F3BCC908BULL;
static const uint64_t Sigma2 = 0xB67AE8584CAA73B2ULL;
static const uint64_t Sigma3 = 0xC6EF372FE94F82BEULL;
static const uint64_t Sigma4 = 0x54FF53A5F1D36F1CULL;
static const uint64_t Sigma5 = 0x10E527FADE682D1DULL;
static const uint64_t Sigma6 = 0xB05688C2B3E6C1FDULL;

#define MASK8  (0x000000FFULL)
#define MASK32 (0xFFFFFFFFULL)
/* circular left shift (left rotation) */
#define LR32(x, c) ((x) << (c) | (x) >> (32 - (c)))
/* circular right shift (right rotation) */
#define RR32(x, c) ((x) >> (c) | (x) << (32 - (c)))

#ifdef SMALL
#define OPTIMIZE 2

static uint64_t F(uint64_t F_IN, uint64_t KE)
{
	uint64_t x, F_OUT;
	uint8_t t1, t2, t3, t4, t5, t6, t7, t8;
#if OPTIMIZE == 0
	uint8_t y1, y2, y3, y4, y5, y6, y7, y8;
#else
	uint32_t zl, zr;
#endif

	x  = F_IN ^ KE;
	t1 = (uint8_t)((x >> 56) & MASK8);
	t2 = (uint8_t)((x >> 48) & MASK8);
	t3 = (uint8_t)((x >> 40) & MASK8);
	t4 = (uint8_t)((x >> 32) & MASK8);
	t5 = (uint8_t)((x >> 24) & MASK8);
	t6 = (uint8_t)((x >> 16) & MASK8);
	t7 = (uint8_t)((x >>  8) & MASK8);
	t8 = (uint8_t)((x      ) & MASK8);
	t1 = SBOX1[t1];
	t2 = SBOX2[t2];
	t3 = SBOX3[t3];
	t4 = SBOX4[t4];
	t5 = SBOX2[t5];
	t6 = SBOX3[t6];
	t7 = SBOX4[t7];
	t8 = SBOX1[t8];
#if OPTIMIZE == 0
	y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
	y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
	y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
	y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
	y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
	y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
	y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
	y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

	F_OUT = ((uint64_t)y1 << 56) | ((uint64_t)y2 << 48) | ((uint64_t)y3 << 40) | ((uint64_t)y4 << 32) |
	        ((uint64_t)y5 << 24) | ((uint64_t)y6 << 16) | ((uint64_t)y7 <<  8) | (uint64_t)y8;
#elif OPTIMIZE == 1
	zl = ((uint32_t)t1 << 24) | ((uint32_t)t2 << 16) | ((uint32_t)t3 << 8) | (uint32_t)t4;
	zr = ((uint32_t)t5 << 24) | ((uint32_t)t6 << 16) | ((uint32_t)t7 << 8) | (uint32_t)t8;
	zl = zl ^ LR32(zr, 8);
	zr = zr ^ LR32(zl, 16);
	zl = zl ^ RR32(zr, 8);
	zr = zr ^ RR32(zl, 8);

	F_OUT = ((uint64_t)zr << 32) | (uint64_t)zl;
#elif OPTIMIZE == 2
	zl = ((uint32_t)t1 << 24) | ((uint32_t)t2 << 16) | ((uint32_t)t3 << 8) | (uint32_t)t4;
	zr = ((uint32_t)t5 << 24) | ((uint32_t)t6 << 16) | ((uint32_t)t7 << 8) | (uint32_t)t8;

	zr = LR32(zr, 8);

	zl = zl ^ zr;
	zr = LR32(zr, 8);

	zr = zr ^ zl;
	zl = RR32(zl, 8);

	zl = zl ^ zr;
	zr = LR32(zr, 16);

	zr = zr ^ zl;
	zl = LR32(zl, 8);

	F_OUT = ((uint64_t)zr << 32) | (uint64_t)zl;
#endif

#ifdef DEBUG
	printf("Ffunc X=%016lx K=%016lx Y=%016lx\n", F_IN, KE, F_OUT);
#endif

	return F_OUT;
}

#else /* ! defined(SMALL) */

static uint64_t SP1[256];
static uint64_t SP2[256];
static uint64_t SP3[256];
static uint64_t SP4[256];
static uint64_t SP5[256];
static uint64_t SP6[256];
static uint64_t SP7[256];
static uint64_t SP8[256];

#define M64(a,b,c,d,e,f,g,h) \
	((uint64_t)a << 56) | ((uint64_t)b << 48) | ((uint64_t)c << 40) | ((uint64_t)d << 32) | \
	((uint64_t)e << 24) | ((uint64_t)f << 16) | ((uint64_t)g <<  8) | (uint64_t)h

static void fill_SP(void)
{
	size_t i;

	for (i = 0; i < 256; i++) {
		uint8_t  x;

		x = SBOX1[i];
		SP1[i] = M64(x,x,x,0,x,0,0,x);

		x = SBOX2[i];
		SP2[i] = M64(0,x,x,x,x,x,0,0);

		x = SBOX3[i];
		SP3[i] = M64(x,0,x,x,0,x,x,0);

		x = SBOX4[i];
		SP4[i] = M64(x,x,0,x,0,0,x,x);

		x = SBOX2[i];
		SP5[i] = M64(0,x,x,x,0,x,x,x);

		x = SBOX3[i];
		SP6[i] = M64(x,0,x,x,x,0,x,x);

		x = SBOX4[i];
		SP7[i] = M64(x,x,0,x,x,x,0,x);

		x = SBOX1[i];
		SP8[i] = M64(x,x,x,0,x,x,x,0);
	}
}

static uint64_t F(uint64_t F_IN, uint64_t KE)
{
	uint64_t x, F_OUT;
	uint8_t  t1, t2, t3, t4, t5, t6, t7, t8;

	x  = F_IN ^ KE;
	t1 = (uint8_t)((x >> 56) & MASK8);
	t2 = (uint8_t)((x >> 48) & MASK8);
	t3 = (uint8_t)((x >> 40) & MASK8);
	t4 = (uint8_t)((x >> 32) & MASK8);
	t5 = (uint8_t)((x >> 24) & MASK8);
	t6 = (uint8_t)((x >> 16) & MASK8);
	t7 = (uint8_t)((x >>  8) & MASK8);
	t8 = (uint8_t)((x      ) & MASK8);

	F_OUT = SP1[t1] ^ SP2[t2] ^ SP3[t3] ^ SP4[t4] ^ SP5[t5] ^ SP6[t6] ^ SP7[t7] ^ SP8[t8];

#ifdef DEBUG
	printf("Ffunc X=%016lx K=%016lx Y=%016lx\n", F_IN, KE, F_OUT);
#endif

	return F_OUT;
}
#endif

static uint64_t FL(uint64_t FL_IN, uint64_t KE)
{
	uint64_t FL_OUT;
	uint32_t x1, x2;
	uint32_t k1, k2;

	x1 = (uint32_t)((FL_IN >> 32) & MASK32);
	x2 = (uint32_t)((FL_IN      ) & MASK32);
	k1 = (uint32_t)((KE    >> 32) & MASK32);
	k2 = (uint32_t)((KE         ) & MASK32);
	x2 = x2 ^ LR32(x1 & k1, 1);
	x1 = x1 ^ (x2 | k2);

	FL_OUT = ((uint64_t)x1 << 32) | (uint64_t)x2;

#ifdef DEBUG
	printf("FL    X=%016lx K=%016lx Y=%016lx\n", FL_IN, KE, FL_OUT);
#endif

	return FL_OUT;
}

static uint64_t FLINV(uint64_t FLINV_IN, uint64_t KE)
{
	uint64_t FLINV_OUT;
	uint32_t y1, y2;
	uint32_t k1, k2;

	y1 = (uint32_t)((FLINV_IN >> 32) & MASK32);
	y2 = (uint32_t)((FLINV_IN      ) & MASK32);
	k1 = (uint32_t)((KE       >> 32) & MASK32);
	k2 = (uint32_t)((KE            ) & MASK32);
	y1 = y1 ^ (y2 | k2);
	y2 = y2 ^ LR32(y1 & k1, 1);

	FLINV_OUT = ((uint64_t)y1 << 32) | (uint64_t)y2;

#ifdef DEBUG
	printf("FLINV X=%016lx K=%016lx Y=%016lx\n", FLINV_IN, KE, FLINV_OUT);
#endif

	return FLINV_OUT;
}

static void camellia_encipher(const struct camellia_ctx *ctx, uint64_t *dl, uint64_t *dr)
{
	uint64_t D1, D2;

	D1 = *dl;
	D2 = *dr;

	D1 = D1 ^ ctx->kw1;           /* Prewhitening */
	D2 = D2 ^ ctx->kw2;
	D2 = D2 ^ F(D1, ctx->k1);     /* Round 01 */
	D1 = D1 ^ F(D2, ctx->k2);     /* Round 02 */
	D2 = D2 ^ F(D1, ctx->k3);     /* Round 03 */
	D1 = D1 ^ F(D2, ctx->k4);     /* Round 04 */
	D2 = D2 ^ F(D1, ctx->k5);     /* Round 05 */
	D1 = D1 ^ F(D2, ctx->k6);     /* Round 06 */
	D1 = FL   (D1, ctx->ke1);     /* FL       */
	D2 = FLINV(D2, ctx->ke2);     /* FLINV    */
	D2 = D2 ^ F(D1, ctx->k7);     /* Round 07 */
	D1 = D1 ^ F(D2, ctx->k8);     /* Round 08 */
	D2 = D2 ^ F(D1, ctx->k9);     /* Round 09 */
	D1 = D1 ^ F(D2, ctx->k10);    /* Round 10 */
	D2 = D2 ^ F(D1, ctx->k11);    /* Round 11 */
	D1 = D1 ^ F(D2, ctx->k12);    /* Round 12 */
	D1 = FL   (D1, ctx->ke3);     /* FL       */
	D2 = FLINV(D2, ctx->ke4);     /* FLINV    */
	D2 = D2 ^ F(D1, ctx->k13);    /* Round 13 */
	D1 = D1 ^ F(D2, ctx->k14);    /* Round 14 */
	D2 = D2 ^ F(D1, ctx->k15);    /* Round 15 */
	D1 = D1 ^ F(D2, ctx->k16);    /* Round 16 */
	D2 = D2 ^ F(D1, ctx->k17);    /* Round 17 */
	D1 = D1 ^ F(D2, ctx->k18);    /* Round 18 */
	if (ctx->keylen > 128) {
	D1 = FL   (D1, ctx->ke5);     /* FL       */
	D2 = FLINV(D2, ctx->ke6);     /* FLINV    */
	D2 = D2 ^ F(D1, ctx->k19);    /* Round 19 */
	D1 = D1 ^ F(D2, ctx->k20);    /* Round 20 */
	D2 = D2 ^ F(D1, ctx->k21);    /* Round 21 */
	D1 = D1 ^ F(D2, ctx->k22);    /* Round 22 */
	D2 = D2 ^ F(D1, ctx->k23);    /* Round 23 */
	D1 = D1 ^ F(D2, ctx->k24);    /* Round 24 */
	}
	D2 = D2 ^ ctx->kw3;           /* Postwhitening */
	D1 = D1 ^ ctx->kw4;

	*dl = D2;
	*dr = D1;
}

static void camellia_decipher(const struct camellia_ctx *ctx, uint64_t *dl, uint64_t *dr)
{
	uint64_t D1, D2;

	D1 = *dl;
	D2 = *dr;

	D1 = D1 ^ ctx->kw3;           /* Prewhitening */
	D2 = D2 ^ ctx->kw4;
	if (ctx->keylen > 128) {
	D2 = D2 ^ F(D1, ctx->k24);    /* Round 24 */
	D1 = D1 ^ F(D2, ctx->k23);    /* Round 23 */
	D2 = D2 ^ F(D1, ctx->k22);    /* Round 22 */
	D1 = D1 ^ F(D2, ctx->k21);    /* Round 21 */
	D2 = D2 ^ F(D1, ctx->k20);    /* Round 20 */
	D1 = D1 ^ F(D2, ctx->k19);    /* Round 19 */
	D1 = FL   (D1, ctx->ke6);     /* FL       */
	D2 = FLINV(D2, ctx->ke5);     /* FLINV    */
	}
	D2 = D2 ^ F(D1, ctx->k18);    /* Round 18 */
	D1 = D1 ^ F(D2, ctx->k17);    /* Round 17 */
	D2 = D2 ^ F(D1, ctx->k16);    /* Round 16 */
	D1 = D1 ^ F(D2, ctx->k15);    /* Round 15 */
	D2 = D2 ^ F(D1, ctx->k14);    /* Round 14 */
	D1 = D1 ^ F(D2, ctx->k13);    /* Round 13 */
	D1 = FL   (D1, ctx->ke4);     /* FL       */
	D2 = FLINV(D2, ctx->ke3);     /* FLINV    */
	D2 = D2 ^ F(D1, ctx->k12);    /* Round 12 */
	D1 = D1 ^ F(D2, ctx->k11);    /* Round 11 */
	D2 = D2 ^ F(D1, ctx->k10);    /* Round 10 */
	D1 = D1 ^ F(D2, ctx->k9);     /* Round 09 */
	D2 = D2 ^ F(D1, ctx->k8);     /* Round 08 */
	D1 = D1 ^ F(D2, ctx->k7);     /* Round 07 */
	D1 = FL   (D1, ctx->ke2);     /* FL       */
	D2 = FLINV(D2, ctx->ke1);     /* FLINV    */
	D2 = D2 ^ F(D1, ctx->k6);     /* Round 06 */
	D1 = D1 ^ F(D2, ctx->k5);     /* Round 05 */
	D2 = D2 ^ F(D1, ctx->k4);     /* Round 04 */
	D1 = D1 ^ F(D2, ctx->k3);     /* Round 03 */
	D2 = D2 ^ F(D1, ctx->k2);     /* Round 02 */
	D1 = D1 ^ F(D2, ctx->k1);     /* Round 01 */
	D2 = D2 ^ ctx->kw1;           /* Postwhitening */
	D1 = D1 ^ ctx->kw2;

	*dl = D2;
	*dr = D1;
}

struct u128 {
	uint64_t l;
	uint64_t r;
};

/* 128-bit left rotate */
static void u128_lr(struct u128 *d, const struct u128 s, int c)
{
	if (c <= 0) {
		*d = s;
	} else if (c < 64) {
		*d = s;

		d->l = (d->l << c) | (s.r >> (64-c));
		d->r = (d->r << c) | (s.l >> (64-c));
	} else if (c == 64){
		d->l = s.r;
		d->r = s.l;
	} else {
		c = c - 64;

		d->l = s.r;
		d->r = s.l;

		d->l = (d->l << c) | (s.l >> (64-c));
		d->r = (d->r << c) | (s.r >> (64-c));
	}
}

void camellia_init(struct camellia_ctx *ctx, const uint8_t key[], size_t keylen)
{
	struct u128 KL, KR;
	struct u128 KA, KB;
	struct u128 t;
	uint64_t D1, D2;

	memset(ctx->key, 0, sizeof(ctx->key));

	ctx->keylen = keylen - (keylen % 8);
	if (ctx->keylen >= 256)
		ctx->keylen = 256;
	else if (ctx->keylen >= 192)
		ctx->keylen = 192;
	else if (ctx->keylen >= 128)
		ctx->keylen = 128;
	memcpy(ctx->key, key, ctx->keylen / 8);
	ctx->keylen = ctx->keylen <= 128 ? 128 : ctx->keylen;

	switch (ctx->keylen) {
	default:
	case 128:
		KL.l = read_be64(ctx->key);
		KL.r = read_be64(ctx->key+8);
		KR.l = 0;
		KR.r = 0;
		break;
	case 192:
		KL.l = read_be64(ctx->key);
		KL.r = read_be64(ctx->key+8);
		KR.l = read_be64(ctx->key+16);
		KR.r = ~KR.l;
		break;
	case 256:
		KL.l = read_be64(ctx->key);
		KL.r = read_be64(ctx->key+8);
		KR.l = read_be64(ctx->key+16);
		KR.r = read_be64(ctx->key+24);
		break;
	}

#ifndef SMALL
	fill_SP();
#endif

	D1 = KL.l ^ KR.l;
	D2 = KL.r ^ KR.r;
	D2 = D2 ^ F(D1, Sigma1);
	D1 = D1 ^ F(D2, Sigma2);
	D1 = D1 ^ KL.l;
	D2 = D2 ^ KL.r;
	D2 = D2 ^ F(D1, Sigma3);
	D1 = D1 ^ F(D2, Sigma4);
	KA.l = D1;
	KA.r = D2;
	D1 = KA.l ^ KR.l;
	D2 = KA.r ^ KR.r;
	D2 = D2 ^ F(D1, Sigma5);
	D1 = D1 ^ F(D2, Sigma6);
	KB.l = D1;
	KB.r = D2;

	if (ctx->keylen == 128) {
		ctx->kw1 = KL.l;
		ctx->kw2 = KL.r;
		ctx->k1  = KA.l;
		ctx->k2  = KA.r;
		u128_lr(&t, KL, 15);
		ctx->k3  = t.l;
		ctx->k4  = t.r;
		u128_lr(&t, KA, 15);
		ctx->k5  = t.l;
		ctx->k6  = t.r;
		u128_lr(&t, KA, 30);
		ctx->ke1 = t.l;
		ctx->ke2 = t.r;
		u128_lr(&t, KL, 45);
		ctx->k7  = t.l;
		ctx->k8  = t.r;
		u128_lr(&t, KA, 45);
		ctx->k9  = t.l;
		u128_lr(&t, KL, 60);
		ctx->k10 = t.r;
		u128_lr(&t, KA, 60);
		ctx->k11 = t.l;
		ctx->k12 = t.r;
		u128_lr(&t, KL, 77);
		ctx->ke3 = t.l;
		ctx->ke4 = t.r;
		u128_lr(&t, KL, 94);
		ctx->k13 = t.l;
		ctx->k14 = t.r;
		u128_lr(&t, KA, 94);
		ctx->k15 = t.l;
		ctx->k16 = t.r;
		u128_lr(&t, KL, 111);
		ctx->k17 = t.l;
		ctx->k18 = t.r;
		u128_lr(&t, KA, 111);
		ctx->kw3 = t.l;
		ctx->kw4 = t.r;
	} else {
		ctx->kw1 = KL.l;
		ctx->kw2 = KL.r;
		ctx->k1  = KB.l;
		ctx->k2  = KB.r;
		u128_lr(&t, KR, 15);
		ctx->k3  = t.l;
		ctx->k4  = t.r;
		u128_lr(&t, KA, 15);
		ctx->k5  = t.l;
		ctx->k6  = t.r;
		u128_lr(&t, KR, 30);
		ctx->ke1 = t.l;
		ctx->ke2 = t.r;
		u128_lr(&t, KB, 30);
		ctx->k7  = t.l;
		ctx->k8  = t.r;
		u128_lr(&t, KL, 45);
		ctx->k9  = t.l;
		ctx->k10 = t.r;
		u128_lr(&t, KA, 45);
		ctx->k11 = t.l;
		ctx->k12 = t.r;
		u128_lr(&t, KL, 60);
		ctx->ke3 = t.l;
		ctx->ke4 = t.r;
		u128_lr(&t, KR, 60);
		ctx->k13 = t.l;
		ctx->k14 = t.r;
		u128_lr(&t, KB, 60);
		ctx->k15 = t.l;
		ctx->k16 = t.r;
		u128_lr(&t, KL, 77);
		ctx->k17 = t.l;
		ctx->k18 = t.r;
		u128_lr(&t, KA, 77);
		ctx->ke5 = t.l;
		ctx->ke6 = t.r;
		u128_lr(&t, KR, 94);
		ctx->k19 = t.l;
		ctx->k20 = t.r;
		u128_lr(&t, KA, 94);
		ctx->k21 = t.l;
		ctx->k22 = t.r;
		u128_lr(&t, KL, 111);
		ctx->k23 = t.l;
		ctx->k24 = t.r;
		u128_lr(&t, KB, 111);
		ctx->kw3 = t.l;
		ctx->kw4 = t.r;
	}
}

void camellia_encrypt_buffer_ecb(const struct camellia_ctx *ctx, uint8_t *buf, size_t len)
{
	size_t i;
	uint64_t l, r;

	for (i = 0; i + 15 < len; i += 16) {
		l = read_be64(buf + i);
		r = read_be64(buf + i + 8);
		camellia_encipher(ctx, &l, &r);
		write_be64(buf + i,     l);
		write_be64(buf + i + 8, r);
	}
}

void camellia_decrypt_buffer_ecb(const struct camellia_ctx *ctx, uint8_t *buf, size_t len)
{
	size_t i;
	uint64_t l, r;

	for (i = 0; i + 15 < len; i += 16) {
		l = read_be64(buf + i);
		r = read_be64(buf + i + 8);
		camellia_decipher(ctx, &l, &r);
		write_be64(buf + i,     l);
		write_be64(buf + i + 8, r);
	}
}

void camellia_encrypt_buffer_cbc(const struct camellia_ctx *ctx, uint8_t *buf, size_t len, const uint64_t iv[2])
{
	size_t i;
	uint64_t l, r, iiv[2];

	iiv[0] = iv[0];
	iiv[1] = iv[1];
	for (i = 0; i + 15 < len; i += 16) {
		l = read_be64(buf + i)     ^ iiv[0];
		r = read_be64(buf + i + 8) ^ iiv[1];
		camellia_encipher(ctx, &l, &r);
		write_be64(buf + i,     l);
		write_be64(buf + i + 8, r);
		iiv[0] = l;
		iiv[1] = r;
	}
}

void camellia_decrypt_buffer_cbc(const struct camellia_ctx *ctx, uint8_t *buf, size_t len, const uint64_t iv[2])
{
	size_t i;
	uint64_t l, r, iiv[2], ct[2];

	iiv[0] = iv[0];
	iiv[1] = iv[1];
	for (i = 0; i + 15 < len; i += 16) {
		ct[0] = l = read_be64(buf + i);
		ct[1] = r = read_be64(buf + i + 8);
		camellia_decipher(ctx, &l, &r);
		write_be64(buf + i,     l ^ iiv[0]);
		write_be64(buf + i + 8, r ^ iiv[1]);
		iiv[0] = ct[0];
		iiv[1] = ct[1];
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
	struct camellia_ctx ctx;
	const uint8_t key128[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
	const uint8_t key192[24] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	                            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
	const uint8_t key256[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	                            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	const uint8_t     pt[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
	const uint8_t  ct128[16] = {0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43};
	const uint8_t  ct192[16] = {0xB4, 0x99, 0x34, 0x01, 0xB3, 0xE9, 0x96, 0xF8, 0x4E, 0xE5, 0xCE, 0xE7, 0xD7, 0x9B, 0x09, 0xB9};
	const uint8_t  ct256[16] = {0x9A, 0xCC, 0x23, 0x7D, 0xFF, 0x16, 0xD7, 0x6C, 0x20, 0xEF, 0x7C, 0x91, 0x9E, 0x3A, 0x75, 0x09};
	uint8_t       buf[16];
	int cmp_enc, cmp_dec;

	fprintf(stderr, "Camellia-128 selftest\n");
	memcpy(buf, pt, sizeof(pt));
	camellia_init(&ctx, key128, 128);
	fprintf(stderr, "128-bit key         = %08X%08X%08X%08X\n", read_be32(key128), read_be32(key128+4), read_be32(key128+8), read_be32(key128+12));
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	camellia_encrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        ciphertext  = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_enc = memcmp(buf, ct128, 16);
	camellia_decrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_dec = memcmp(buf, pt, 16);

	if (cmp_enc || cmp_dec) {
		fprintf(stderr, "ERROR\n");
		return 1;
	}
	fprintf(stderr, "OK\n");

	fprintf(stderr, "Camellia-192 selftest\n");
	memcpy(buf, pt, sizeof(pt));
	camellia_init(&ctx, key192, 192);
	fprintf(stderr, "192-bit key         = %08X%08X%08X%08X%08X%08X\n", read_be32(key192), read_be32(key192+4), read_be32(key192+8), read_be32(key192+12), read_be32(key192+16), read_be32(key192+20));
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	camellia_encrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        ciphertext  = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_enc = memcmp(buf, ct192, 16);
	camellia_decrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_dec = memcmp(buf, pt, 16);

	if (cmp_enc || cmp_dec) {
		fprintf(stderr, "ERROR\n");
		return 1;
	}
	fprintf(stderr, "OK\n");

	fprintf(stderr, "Camellia-256 selftest\n");
	memcpy(buf, pt, sizeof(pt));
	camellia_init(&ctx, key256, 256);
	fprintf(stderr, "256-bit key         = %08X%08X%08X%08X%08X%08X%08X%08X\n", read_be32(key256), read_be32(key256+4), read_be32(key256+8), read_be32(key256+12), read_be32(key256+16), read_be32(key256+20), read_be32(key256+24), read_be32(key256+28));
	fprintf(stderr, "        plaintext   = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	camellia_encrypt_buffer_ecb(&ctx, buf, 16);
	fprintf(stderr, "        ciphertext  = %08X%08X%08X%08X\n", read_be32(buf), read_be32(buf+4), read_be32(buf+8), read_be32(buf+12));
	cmp_enc = memcmp(buf, ct256, 16);
	camellia_decrypt_buffer_ecb(&ctx, buf, 16);
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
			camellia_init(&ctx, key128, 128);
			fprintf(stderr, "encrypt:\n");
			for (i = 0; i < RUNS; i++) {
				gettimeofday(&t0,  NULL);
				camellia_encrypt_buffer_ecb(&ctx, buf, BUFDIM);
				gettimeofday(&t1,  NULL);
				PRINT_INTERVAL;
			}
			fprintf(stderr, "decrypt:\n");
			for (i = 0; i < RUNS; i++) {
				gettimeofday(&t0,  NULL);
				camellia_decrypt_buffer_ecb(&ctx, buf, BUFDIM);
				gettimeofday(&t1,  NULL);
				PRINT_INTERVAL;
			}
			free(buf);
		}
	}

	return 0;
}
#endif
