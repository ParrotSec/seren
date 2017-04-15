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

#include <string.h>
#include "md5.h"
#include "rw.h"

static const uint32_t s[64] = {
7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,	/* round 1 */
5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,	/* round 2 */
4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,	/* round 3 */
6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21	/* round 4 */
};

static const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

#ifndef SMALL
static const uint32_t G[64] = {                                /* i = 0..63      */
0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, /* i              */
1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12, /* (5*i + 1) % 16 */
5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2, /* (3*i + 5) % 16 */
0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9  /* (7*i) % 16     */
};
#endif

#define LR(x, c) ((x) << (c) | (x) >> (32 - (c)))

/* original functions */
//#define FF(b, c, d) ((b & c) | (~b & d))
#define FG(b, c, d) ((d & b) | (~d & c)) /* faster than equivalent because it can be parallelized */
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))
/* equivalent functions */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
//#define FG(b, c, d) FF (d, b, c)       /* this one is always true */


static void md5_blocks(uint32_t h[4], const uint8_t *buf, size_t nblocks)
{
	size_t n;
	uint32_t i, a, b, c, d, w[16];

	/* Process the message in successive 512-bit (64 bytes) chunks */
	for (n = 0; n < nblocks; n++) {

		/* break chunk into sixteen 32-bit little-endian words w[g], 0 ≤ g ≤ 15 */
		for (i = 0; i < 16; i++)
			w[i] = read_le32(buf + n * 64 + i * 4);

		/* Initialize hash value for this chunk */
		a = h[0];
		b = h[1];
		c = h[2];
		d = h[3];

#ifdef SMALL
		/* Main loop */
		for (i = 0; i < 64; i++) {
			uint32_t f, g, tmp;

			switch (i >> 4) {
			case 0:
				f = FF(b, c, d);
				g = i;
				break;
			case 1:
				f = FG(b, c, d);
				g = (5*i + 1) & 0x0f;
				break;
			case 2:
				f = FH(b, c, d);
				g = (3*i + 5) & 0x0f;
				break;
			case 3:
				f = FI(b, c, d);
				g = (7*i) & 0x0f;
				break;
			}
			tmp  = d;
			d    = c;
			c    = b;
			b    = b + LR((a + f + k[i] + w[g]), s[i]);
			a    = tmp;
		}
#else

#define OP(i, f, a, b, c, d)                 \
	do {                                     \
		a = a + f(b, c, d) + k[i] + w[G[i]]; \
		a = b + LR(a, s[i]);                 \
	} while (0)

#define OP4(i, f) \
	OP(i, f, a, b, c, d); OP(i+1, f, d, a, b, c); OP(i+2, f, c, d, a, b); OP(i+3, f, b, c, d, a)

#define OP16(i, f) \
	OP4(i, f); OP4(i+4, f); OP4(i+8, f); OP4(i+12, f)

		/* Main loop */
		OP16( 0, FF);  /* first  round */
		OP16(16, FG);  /* second round */
		OP16(32, FH);  /* third  round */
		OP16(48, FI);  /* fourth round */
#endif

		/* Add this chunk's hash to result so far */
		h[0] = h[0] + a;
		h[1] = h[1] + b;
		h[2] = h[2] + c;
		h[3] = h[3] + d;
	}
}

void md5_buffer(const uint8_t *buf, size_t len, uint8_t digest[16])
{
	uint8_t  fillbuf[128];
	size_t   n, nblocks;
	uint64_t bitlen;
	uint32_t h[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

	bitlen  = len * 8;
	nblocks = len / 64;
	n       = len % 64;

	/* process the bulk of the data (whole blocks) */
	md5_blocks(h, buf, nblocks);

	/* copy the rest */
	memcpy(fillbuf, buf + nblocks * 64, n);

	/* insert padding, append length */
	fillbuf[n++] = 0x80;
	while (n % 64 != 56)
		fillbuf[n++] = 0;
	write_le64(fillbuf + n, bitlen);
	n += 8;

	/* process last blocks */
	nblocks = n / 64;
	md5_blocks(h, fillbuf, nblocks);

	/* fill in md5 hash */
	for(n = 0; n < 4; n++)
		write_le32(digest + 4 * n, h[n]);
}

#ifdef SELFTEST
#include <stdio.h>

struct tv {
	char *input;
	char *hexdigest;
};

int main()
{
	struct tv tv[] = {
		{"", "d41d8cd98f00b204e9800998ecf8427e"},
		{"a", "0cc175b9c0f1b6a831c399e269772661"},
		{"abc", "900150983cd24fb0d6963f7d28e17f72"},
		{"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
		{"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"}
	};

	int     i, j;
	uint8_t digest[16];
	char    hexdigest[32+1];

	for (i = 0; i < 7; i++) {
		md5_buffer((uint8_t *)tv[i].input, strlen(tv[i].input), digest);
		for (j = 0; j < 16; j++)
			sprintf(hexdigest + 2 * j, "%02x", digest[j]);
		fprintf(stderr, "md5('%s') = %s\n", tv[i].input, hexdigest);

		if (memcmp(tv[i].hexdigest, hexdigest, 32)) {
			fprintf(stderr, "ERROR\n");
			return 1;
		}
	}
	fprintf(stderr, "OK\n");

	return 0;
}
#endif
