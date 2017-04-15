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

#ifndef CAMELLIA_H
#define CAMELLIA_H

#include <stddef.h>
#include <stdint.h>

struct camellia_ctx {
	/* 128-bit, 192-bit or 256-bit key, max 32 bytes */
	uint8_t  key[32];
	size_t   keylen;  /* in bits */

	/* subkeys */
	uint64_t kw1, kw2, kw3, kw4;
	uint64_t k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14,
	         k15, k16, k17, k18, k19, k20, k21, k22, k23, k24;
	uint64_t ke1, ke2, ke3, ke4, ke5, ke6;
};

void camellia_init(struct camellia_ctx *ctx, const uint8_t key[], size_t keylen);

/* For all the following functions len must be multiple of 16.
 * Encryption and decryption will be performed "in place",
 * that is, overwriting the data in buf.
 */

/* electronic codebook */
void camellia_encrypt_buffer_ecb(const struct camellia_ctx *ctx, uint8_t *buf, size_t len);
void camellia_decrypt_buffer_ecb(const struct camellia_ctx *ctx, uint8_t *buf, size_t len);

/* cipher-block chaining */
void camellia_encrypt_buffer_cbc(const struct camellia_ctx *ctx, uint8_t *buf, size_t len, const uint64_t iv[2]);
void camellia_decrypt_buffer_cbc(const struct camellia_ctx *ctx, uint8_t *buf, size_t len, const uint64_t iv[2]);

#endif
