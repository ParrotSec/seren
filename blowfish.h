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

#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stddef.h>
#include <stdint.h>

struct blowfish_ctx {
	/* 32-bit to 448-bit key, max 56 bytes */
	uint8_t  key[56];
	size_t   keylen;  /* in bits */

	/* subkeys */
	uint32_t  P[ 18];
	uint32_t S1[256];
	uint32_t S2[256];
	uint32_t S3[256];
	uint32_t S4[256];
};

void blowfish_init(struct blowfish_ctx *ctx, const uint8_t key[], size_t keylen);

/* For all the following functions len must be multiple of 8.
 * Encryption and decryption will be performed "in place",
 * that is, overwriting the data in buf.
 */

/* electronic codebook */
void blowfish_encrypt_buffer_ecb(const struct blowfish_ctx *ctx, uint8_t *buf, size_t len);
void blowfish_decrypt_buffer_ecb(const struct blowfish_ctx *ctx, uint8_t *buf, size_t len);

/* cipher-block chaining */
void blowfish_encrypt_buffer_cbc(const struct blowfish_ctx *ctx, uint8_t *buf, size_t len, const uint32_t iv[2]);
void blowfish_decrypt_buffer_cbc(const struct blowfish_ctx *ctx, uint8_t *buf, size_t len, const uint32_t iv[2]);

#endif
