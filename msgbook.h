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

#ifndef MSGBOOK_H
#define MSGBOOK_H

#include <stdio.h>
#include <time.h>

#define MB_TYPE_ANY      0xFFFFFFFF
#define MB_TYPE_DEBUG    0x00000001
#define MB_TYPE_VERBOSE  0x00000002
#define MB_TYPE_INFO     0x00000004
#define MB_TYPE_WARNING  0x00000008
#define MB_TYPE_ERROR    0x00000010
#define MB_TYPE_GUI      0x00000020
#define MB_TYPE_CHAT     0x00000040
#define MB_TYPE_NUMTYPES 7

#define MBS              2048
#define MB_BACKLOG       50

struct mbrecord {
	time_t           ts;
	unsigned int     type;
	char             module[16];
	char            *msg;
	struct mbrecord *next;
};

struct msgbook {
	struct mbrecord  head;
	int              n;
	void (*print_cb)(time_t ts, unsigned int type, const char *module, const char *msg);
};

extern struct msgbook  mb0;
extern FILE           *fplog;
extern char            msgbuf[MBS];

void logstr(const char *str);
char msgbook_type_name(unsigned int type);

void msgbook_init(struct msgbook *mb);
void msgbook_enqueue(struct msgbook *mb, unsigned int type, const char *module, const char *msg);
int  msgbook_dequeue(struct msgbook *mb, unsigned int requested_type, time_t *ts, unsigned int *type, char *module, char *msg);

void msgbook_print_cb_stderr(time_t ts, unsigned int type, const char *module, const char *msg);
void msgbook_flush(struct msgbook *mb, int print);
void msgbook_print_backlog(struct msgbook *mb);

#endif
