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
#include "common.h"

void (*die_cb)(const char *msg, int exit_code);

void die(const char *msg, int exit_code)
{
	if (die_cb)
		die_cb(msg, exit_code);

	fputs("\nOops, there was a problem and the program was terminated:\n\n", stderr);
	fputs(msg, stderr);
	fputs("\n\n", stderr);
	exit(exit_code);
}

void *xmalloc(size_t size)
{
	void *m;

	m = malloc(size);
	if (m == NULL)
		die("malloc() failed", 1);

	return m;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *m;

	m = calloc(nmemb, size);
	if (m == NULL)
		die("calloc() failed", 1);

	return m;
}

const char *ts2datetime(time_t ts)
{
	static char str[32];
	struct tm *t;

	t = localtime(&ts);

	if (t)
		sprintf(str, "%04d/%02d/%02d %02d:%02d:%02d",
		        t->tm_year+1900, t->tm_mon+1, t->tm_mday,
		        t->tm_hour, t->tm_min, t->tm_sec);
	else
		sprintf(str, "----/--/-- --:--:--");

	return str;
}

const char *ts2time(time_t ts)
{
	static char str[16];
	struct tm *t;

	t = localtime(&ts);

	if (t)
		sprintf(str, "%02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec);
	else
		sprintf(str, "--:--:--");

	return str;
}

size_t utf8_bytes_in_sequence(unsigned char first_byte)
{
	if ((first_byte & 0x80) == 0)
		return 1;
	else if ((first_byte & 0xE0) == 0xC0)
		return 2;
	else if ((first_byte & 0xF0) == 0xE0)
		return 3;
	else
		return 4;
}
