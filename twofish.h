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

#ifndef TWOFISH_H
#define TWOFISH_H

#include <stddef.h>
#include <stdint.h>

struct twofish_ctx {
	/* 128-bit, 192-bit or 256-bit key, max 32 bytes */
	uint8_t  key[32];
	size_t   keylen;  /* in bits */

	/* subkeys */
	uint32_t K[40];

	/* s-boxes */
#if 0
	uint8_t S0[256];
	uint8_t S1[256];
	uint8_t S2[256];
	uint8_t S3[256];
#else
	uint32_t SF0[256];
	uint32_t SF1[256];
	uint32_t SF2[256];
	uint32_t SF3[256];
#endif
};

void twofish_init(struct twofish_ctx *ctx, const uint8_t key[], size_t keylen);

/* For all the following functions len must be multiple of 16.
 * Encryption and decryption will be performed "in place",
 * that is, overwriting the data in buf.
 */

/* electronic codebook */
void twofish_encrypt_buffer_ecb(const struct twofish_ctx *ctx, uint8_t *buf, size_t len);
void twofish_decrypt_buffer_ecb(const struct twofish_ctx *ctx, uint8_t *buf, size_t len);

/* cipher-block chaining */
void twofish_encrypt_buffer_cbc(const struct twofish_ctx *ctx, uint8_t *buf, size_t len, const uint64_t iv[2]);
void twofish_decrypt_buffer_cbc(const struct twofish_ctx *ctx, uint8_t *buf, size_t len, const uint64_t iv[2]);

#endif
