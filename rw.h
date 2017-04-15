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

#ifndef RW_H
#define RW_H

#include <stdint.h>

/* These functions write an integer to the memory location pointed by
 * p. We have two group of functions: _be functions write in big endian
 * order, while _le functions write in little endian order.
 */

void write_be64(uint8_t *p, uint64_t v);
void write_be32(uint8_t *p, uint32_t v);
void write_be16(uint8_t *p, uint16_t v);

void write_le64(uint8_t *p, uint64_t v);
void write_le32(uint8_t *p, uint32_t v);
void write_le16(uint8_t *p, uint16_t v);

/* These functions read an integer from the memory location pointed by
 * p. Again two groups: _be for big endian and _le for little endian.
 */

uint64_t read_be64(const uint8_t *p);
uint32_t read_be32(const uint8_t *p);
uint16_t read_be16(const uint8_t *p);

uint64_t read_le64(const uint8_t *p);
uint32_t read_le32(const uint8_t *p);
uint16_t read_le16(const uint8_t *p);

#endif
