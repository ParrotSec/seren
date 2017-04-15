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
#include <stdlib.h>
#include "random.h"
#include "rw.h"

static FILE *fp_rand;

int random_init(void)
{
	fp_rand = fopen("/dev/urandom", "r");

	return fp_rand ? 0 : -1;
}

uint32_t random_rand32(void)
{
	size_t   n = 0;
	uint8_t  buf[4];
	uint32_t r;

	if (fp_rand) {
		do
			n = fread(buf, 1, sizeof(buf), fp_rand);
		while (n != sizeof(buf));
	}

	if (n == 0)
		r = ((uint32_t)(rand() & 0xFFFF) << 16) | ((uint32_t)(rand() & 0xFFFF));
	else
		r = read_be32(buf);

	return r;
}

uint64_t random_rand64(void)
{
	size_t   n = 0;
	uint8_t  buf[8];
	uint64_t r;

	if (fp_rand) {
		do
			n = fread(buf, 1, sizeof(buf), fp_rand);
		while (n != sizeof(buf));
	}

	if (n == 0)
		r = ((uint64_t)(rand() & 0xFFFF) << 48) | ((uint64_t)(rand() & 0xFFFF) << 32) |
		    ((uint64_t)(rand() & 0xFFFF) << 16) | ((uint64_t)(rand() & 0xFFFF));
	else
		r = read_be64(buf);

	return r;
}

void random_close(void)
{
	if (fp_rand)
		fclose(fp_rand);
	fp_rand = NULL;
}
