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

#include <stdlib.h>
#include "slist.h"
#include "common.h"

/* returns a pointer to the tail element, or NULL if the list is empty */
struct slist *slist_get_tail(struct slist *l)
{
	if (!l)
		return NULL;

	while (l->next)
		l = l->next;

	return l;
}

/* prepends an element to the head of the list and returns a pointer to the new
   head of the list */
struct slist *slist_prepend(struct slist *l, void *entry)
{
	struct slist *n;

	/* allocate and fill new element */
	n = xmalloc(sizeof(*n));
	n->data = entry;
	n->next = l;

	return n;
}

/* appends an element to the tail of the list and returns a pointer to the (new)
   head of the list */
struct slist *slist_append(struct slist *l, void *entry)
{
	struct slist *n, *tail;

	/* allocate and fill new element */
	n = xmalloc(sizeof(*n));
	n->data = entry;
	n->next = NULL;

	/* if the list was empty, the new element is the head */
	if (!l)
		return n;
	else {
		/* find tail */
		tail = l;
		while (tail->next)
			tail = tail->next;
		/* attach element to the tail */
		tail->next = n;
		return l;
	}
}

/* remove the head of the list and returns a pointer to the new head */
struct slist *slist_remove_head(struct slist *l)
{
	struct slist *head;

	if (!l)
		return NULL;

	head = l;
	l = l->next;
	free(head);

	return l;
}

/* remove the tail of the list and returns a pointer to the (new) head */
struct slist *slist_remove_tail(struct slist *l)
{
	struct slist *prev, *tail;

	if (!l)
		return NULL;

	/* if we have only one element the list becomes empty */
	if (!l->next) {
		free(l);
		return NULL;
	}

	/* we have at least 2 elements, find tail and its previous element */
	prev = l;
	tail = l->next;
	while (tail->next) {
		prev = prev->next;
		tail = tail->next;
	}

	/* disconnect and free tail */
	prev->next = NULL;
	free(tail);

	return l;
}

/* remove an element of the list and returns a pointer to the (new) head */
struct slist *slist_remove_element(struct slist *l, struct slist *ele)
{
	struct slist *prev, *cur;

	if (!l)
		return NULL;

	/* the element is the head, remove it */
	if (l == ele) {
		cur = l;
		l = l->next;
		free(cur);
		return l;
	}

	/* the element is not the head, search for it and its previous element */
	prev = l;
	cur  = l->next;
	while (cur != ele) {
		prev = prev->next;
		cur  = cur->next;
	}

	/* disconnect and free element */
	prev->next = cur->next;
	free(cur);

	return l;
}
