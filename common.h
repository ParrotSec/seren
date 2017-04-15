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

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <time.h>

extern void (*die_cb)(const char *msg, int exit_code);
void die(const char *msg, int exit_code);

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);

const char *ts2datetime(time_t ts);
const char *ts2time(time_t ts);

size_t utf8_bytes_in_sequence(unsigned char first_byte);

#endif
