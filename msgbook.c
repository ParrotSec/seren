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
#include <string.h>
#include <time.h>
#include "msgbook.h"
#include "common.h"

struct msgbook  mb0;
FILE           *fplog;
char            msgbuf[MBS];

void logstr(const char *str)
{
	if (str && fplog) {
		fprintf(fplog, "[%s] %s\n", ts2datetime(time(NULL)), str);
		fflush(fplog);
	}
}

char msgbook_type_name(unsigned int type)
{
	unsigned int t;
	char names[MB_TYPE_NUMTYPES] = {'D', 'V', 'I', 'W', 'E', 'G', 'C'};

	if (type == MB_TYPE_ANY)
		return '*';

	for (t = 0; t < MB_TYPE_NUMTYPES; t++) {
		if ((1U << t) == type)
			return names[t];
	}
	return '?';
}

void msgbook_init(struct msgbook *mb)
{
	memset(&mb->head, 0, sizeof(mb->head));
	mb->n         = 0;
	mb->print_cb  = NULL;
}

void msgbook_enqueue(struct msgbook *mb, unsigned int type, const char *module, const char *msg)
{
	time_t ts;
	struct mbrecord *r, *last;

	ts = time(NULL);

	/* save message to log file */
	if (fplog) {
		if (type == MB_TYPE_CHAT)
			fprintf(fplog, "[%s] (%c) %s> %s\n", ts2datetime(ts), msgbook_type_name(type), module, msg);
		else
			fprintf(fplog, "[%s] (%c) [%s] %s\n", ts2datetime(ts), msgbook_type_name(type), module, msg);
		fflush(fplog);
	}

	/* if we have a print callback, print the message and keep only a limited backlog */
	if (mb->print_cb) {
		mb->print_cb(ts, type, module, msg);

		while (mb->n >= MB_BACKLOG) {
			time_t       ts_;
			unsigned int type_;
			char         module_[16];
			char         msg_[MBS];

			msgbook_dequeue(mb, MB_TYPE_ANY, &ts_, &type_, module_, msg_);
		}
	}

	/* allocate and fill new record */
	r = xcalloc(1, sizeof(*r));
	r->ts   = ts;
	r->type = type;
	strncpy(r->module, module, 15);
	r->msg  = xmalloc(strlen(msg)+1);
	strcpy(r->msg, msg);
	r->next = NULL;

	/* find last record */
	last = &mb->head;
	while (last->next != NULL)
		last = last->next;

	/* add newly allocated record at the end of the queue */
	last->next = r;
	mb->n++;
}

int msgbook_dequeue(struct msgbook *mb, unsigned int requested_type, time_t *ts, unsigned int *type, char *module, char *msg)
{
	struct mbrecord *p, *r; /* previous and current record */

	/* search record */
	if (requested_type != MB_TYPE_ANY) {
		p = &mb->head;
		r = mb->head.next;
		while (r) {
			if (r->type == requested_type)
				break;
			p = p->next;
			r = r->next;
		}
	} else {
		p = &mb->head;
		r = mb->head.next;
	}

	/* if the queue was empty or no record of the specified type was found, return */
	if (!r)
		return -1;

	/* delete current record from the queue */
	p->next = r->next;
	mb->n--;

	/* copy record fields to output parameters */
	*ts   = r->ts;
	*type = r->type;
	strcpy(module, r->module);
	strcpy(msg, r->msg);

	/* free current record */
	free(r->msg);
	free(r);

	return 0;
}

void msgbook_print_cb_stderr(time_t ts, unsigned int type, const char *module, const char *msg)
{
	if (type == MB_TYPE_CHAT)
		fprintf(stderr, "[%s] (%c) %s> %s\n", ts2datetime(ts), msgbook_type_name(type), module, msg);
	else
		fprintf(stderr, "[%s] (%c) [%s] %s\n", ts2datetime(ts), msgbook_type_name(type), module, msg);
}

void msgbook_flush(struct msgbook *mb, int print)
{
	int          ret;
	time_t       ts;
	unsigned int type;
	char         module[16];
	char         msg[MBS];

	if (print) {
		if (mb->print_cb == NULL)
			return;

		while ((ret = msgbook_dequeue(mb, MB_TYPE_ANY, &ts, &type, module, msg)) != -1)
			mb->print_cb(ts, type, module, msg);
	} else {
		while ((ret = msgbook_dequeue(mb, MB_TYPE_ANY, &ts, &type, module, msg)) != -1)
			;
	}
}

void msgbook_print_backlog(struct msgbook *mb)
{
	int i;
	struct mbrecord *r;

	if (mb->print_cb == NULL)
		return;

	r = mb->head.next;
	for (i = 0; i < mb->n; i++) {
		mb->print_cb(r->ts, r->type, r->module, r->msg);
		r = r->next;
	}
}
