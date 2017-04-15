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

#include "rw.h"

/* write functions, be */

void write_be64(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v >> 56);
	p[1] = (uint8_t)(v >> 48);
	p[2] = (uint8_t)(v >> 40);
	p[3] = (uint8_t)(v >> 32);
	p[4] = (uint8_t)(v >> 24);
	p[5] = (uint8_t)(v >> 16);
	p[6] = (uint8_t)(v >>  8);
	p[7] = (uint8_t)(v      );
}

void write_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >>  8);
	p[3] = (uint8_t)(v      );
}

void write_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >>  8);
	p[1] = (uint8_t)(v      );
}

/* write functions, le */

void write_le64(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v      );
	p[1] = (uint8_t)(v >>  8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
	p[4] = (uint8_t)(v >> 32);
	p[5] = (uint8_t)(v >> 40);
	p[6] = (uint8_t)(v >> 48);
	p[7] = (uint8_t)(v >> 56);
}

void write_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v      );
	p[1] = (uint8_t)(v >>  8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

void write_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v      );
	p[1] = (uint8_t)(v >>  8);
}


/* read functions, be */

uint64_t read_be64(const uint8_t *p)
{
	uint64_t r;

	r = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
	    ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] <<  8) | (uint64_t)p[7];

	return r;
}

uint32_t read_be32(const uint8_t *p)
{
	return (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3]);
}

uint16_t read_be16(const uint8_t *p)
{
	return (uint16_t)(((uint32_t)p[0] << 8) | (uint32_t)p[1]);
}

/* read functions, le */

uint64_t read_le64(const uint8_t *p)
{
	uint64_t r;

	r = ((uint64_t)p[7] << 56) | ((uint64_t)p[6] << 48) | ((uint64_t)p[5] << 40) | ((uint64_t)p[4] << 32) |
	    ((uint64_t)p[3] << 24) | ((uint64_t)p[2] << 16) | ((uint64_t)p[1] <<  8) | (uint64_t)p[0];

	return r;
}

uint32_t read_le32(const uint8_t *p)
{
	return (((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[0]);
}

uint16_t read_le16(const uint8_t *p)
{
	return (uint16_t)(((uint32_t)p[1] << 8) | (uint32_t)p[0]);
}
