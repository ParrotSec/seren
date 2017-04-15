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

#ifndef SLIST_H
#define SLIST_H

struct slist {
	void         *data;
	struct slist *next;
};

struct slist *slist_get_tail(struct slist *l);
struct slist *slist_prepend(struct slist *l, void *entry);
struct slist *slist_append(struct slist *l, void *entry);
struct slist *slist_remove_head(struct slist *l);
struct slist *slist_remove_tail(struct slist *l);
struct slist *slist_remove_element(struct slist *l, struct slist *ele);

#endif
