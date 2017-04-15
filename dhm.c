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
#include "dhm.h"
#include "rw.h"
#include "md5.h"

#ifdef SELFTEST
#include <stdlib.h>
#define random_rand64 rand
#else
#include "random.h"
#endif

void dhm_init(struct dhm_ctx *ctx, enum dhm_pgid pgid)
{
	gmp_randstate_t rstate;
	mpz_t seed;
	unsigned long nbits;

	memset(ctx, 0, sizeof(*ctx));
	ctx->pgid = pgid;

	/* prepare random number generator */
	gmp_randinit_mt(rstate);
	mpz_init(seed);
	mpz_set_d(seed, (double)random_rand64());
	gmp_randseed(rstate, seed);
	mpz_clear(seed);

	/* init integers */
	mpz_init(ctx->p);
	mpz_init(ctx->g);
	mpz_init(ctx->a);
	mpz_init(ctx->A);
	mpz_init(ctx->B);
	mpz_init(ctx->k);

	/* set prime modulus and generator */
	switch (ctx->pgid) {
	default:
	case pgid_2048:
		nbits = 2048;
		mpz_set_str(ctx->p, DHM_RFC3526_MODP_2048_P, 16);
		mpz_set_str(ctx->g, DHM_RFC3526_MODP_2048_G, 16);
		break;
	case pgid_3072:
		nbits = 3072;
		mpz_set_str(ctx->p, DHM_RFC3526_MODP_3072_P, 16);
		mpz_set_str(ctx->g, DHM_RFC3526_MODP_3072_G, 16);
		break;
	case pgid_4096:
		nbits = 4096;
		mpz_set_str(ctx->p, DHM_RFC3526_MODP_4096_P, 16);
		mpz_set_str(ctx->g, DHM_RFC3526_MODP_4096_G, 16);
		break;
	}

	/* choose secret value a */
	mpz_urandomb(ctx->a, rstate, nbits);
	gmp_randclear(rstate);

	/* compute public key A = g^a mod p */
	mpz_powm(ctx->A, ctx->g, ctx->a, ctx->p);

	/* export public key */
	mpz_export(ctx->pk, &ctx->pklen, 1, 1, 1, 0, ctx->A);
}

void dhm_calc_secret(struct dhm_ctx *ctx, const uint8_t *peer_pk, size_t peer_pklen)
{
	size_t i;
	uint8_t tk[32];

	/* import peer public key */
	mpz_import(ctx->B, peer_pklen, 1, 1, 1, 0, peer_pk);

	/* compute secret key k = B^a mod p */
	mpz_powm(ctx->k, ctx->B, ctx->a, ctx->p);

	/* export secret key */
	mpz_export(ctx->sk, &ctx->sklen, 1, 1, 1, 0, ctx->k);

	/* produce 128-key from ctx->sk */
#ifdef SELFTEST
	memset(tk, 0, sizeof(tk));
	for (i = 0; i < ctx->sklen; i++)
		tk[i & 0x0F] ^= ctx->sk[i];
	memcpy(ctx->key128, tk, sizeof(ctx->key128));
#else
	md5_buffer(ctx->sk, ctx->sklen, ctx->key128);
#endif

	/* produce 256-key from ctx->sk */
	memset(tk, 0, sizeof(tk));
	for (i = 0; i < ctx->sklen; i++)
		tk[i & 0x1F] ^= ctx->sk[i];
	memcpy(ctx->key256, tk, sizeof(ctx->key256));
}

int dhm_compare_pk(struct dhm_ctx *ctx, const uint8_t *peer_pk, size_t peer_pklen)
{
	int ret;
	mpz_t B_new;

	mpz_init(B_new);

	/* import new peer public key */
	mpz_import(B_new, peer_pklen, 1, 1, 1, 0, peer_pk);

	/* compare with the old key, ret = 0 if they are the same */
	ret = mpz_cmp(ctx->B, B_new);

	mpz_clear(B_new);

	return ret;
}

void dhm_clear(struct dhm_ctx *ctx)
{
	mpz_clear(ctx->p);
	mpz_clear(ctx->g);
	mpz_clear(ctx->a);
	mpz_clear(ctx->A);
	mpz_clear(ctx->B);
	mpz_clear(ctx->k);
}

#ifdef SELFTEST
#include <stdio.h>
#include <time.h>

static void print_mp(const mpz_t op, const char *desc)
{
	char *str;

	str = mpz_get_str(NULL, 16, op);
	fprintf(stderr, "%s (%4zd bit, %3zd digits) = %s\n", desc, mpz_sizeinbase(op, 2), mpz_sizeinbase(op, 10), str);
	free(str);
}

int main()
{
	int ret;
	struct dhm_ctx c0, c1;

	srand(time(NULL));

	dhm_init(&c0, pgid_4096);
	print_mp(c0.a, "c0.a");
	print_mp(c0.A, "c0.A");
	fprintf(stderr, "c0.pklen = %zd\n\n", c0.pklen);

	dhm_init(&c1, pgid_4096);
	print_mp(c1.a, "c1.a");
	print_mp(c1.A, "c1.A");
	fprintf(stderr, "c1.pklen = %zd\n\n", c1.pklen);

	// exchange public keys now

	dhm_calc_secret(&c0, c1.pk, c1.pklen);
	print_mp(c0.k, "c0.k");
	dhm_calc_secret(&c1, c0.pk, c0.pklen);
	print_mp(c1.k, "c1.k");

	ret = mpz_cmp(c0.k, c1.k);
	fprintf(stderr, "%s\n", ret ? "ERROR" : "OK");

	dhm_clear(&c0);
	dhm_clear(&c1);

	return (ret != 0);
}
#endif
