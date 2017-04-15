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

#ifndef NC_H
#define NC_H

#include "config.h"

#ifdef HAVE_LIBNCURSESW
#include <stddef.h>
#include <time.h>

#if defined(HAVE_NCURSESW_NCURSES_H)
#include <ncursesw/ncurses.h>
#elif defined(HAVE_NCURSES_H)
#include <ncurses.h>
#endif

#define LBS         1024 /* linebuf size */
#define LBM         1000 /* linebuf max  */
#define HISTORYSIZE 50

/* ncurses context */
struct NContext {
	int                  initialized;
	int                  rows, cols;
	/* windows */
	WINDOW              *win_title;
	WINDOW              *win_message;
	WINDOW              *win_nodelist;
	WINDOW              *win_status;
	WINDOW              *win_input;
	/* keyboard input */
	char                 linebuf[LBS*4];
	size_t               linepos;
	unsigned char        wlinebuf[LBS][4];
	size_t               wlinepos;
	/* input history */
	struct {
		unsigned char    wlinebuf[LBS][4];
		size_t           wlinepos;
	} history[HISTORYSIZE];
	int                  historypos;
	int                  historymove; /* always <= 0 */
	int                  historyfilled;
	char                 histfile[128];
};

struct nc_node_info {
	const char          *nick;
	int                  algo;
	unsigned int         nb_frames;
	unsigned int         bandwidth;
	unsigned int         nb_channels;
	unsigned int         pl10k;
	unsigned int         tm_pl10k;
	double               rtt_us;
	double               dBSPL;
};

extern struct NContext   nctx;

int  nc_init(const char *version, const char *nick, int theme, const char *histfile);
int  nc_resize(const char *version, const char *nick);
void nc_close(void);
void nc_print_bars(const char *version);
void nc_clear_input_line_and_print_prompt(const char *nick, int delete_buffer);
int  nc_scroll_input_text(const char *nick, size_t right_space);
void nc_print_wlinebuf(const char *nick);
void nc_update_linebuf(void);
void nc_status(int micmute, int record, int mode, float peak_percent, double dBSPL,
               const char *timer_str, const char *stat_str);
void nc_nodelist(unsigned int nb_nodes, int mode, struct nc_node_info ni[]);

#endif /* defined(HAVE_LIBNCURSESW) */

#endif
