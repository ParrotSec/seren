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

#include "config.h"

#ifdef HAVE_LIBNCURSESW
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "nc.h"
#include "common.h"
#include "msgbook.h"

#define MODULE "ncurses"

struct NContext nctx;

static int create_windows(void)
{
	/* create title window */
	if ((nctx.win_title = newwin(1, nctx.cols, 0, 0)) == NULL)
		goto create_windows_fail;

	/* create message window */
	if ((nctx.win_message = newwin(nctx.rows - 4, nctx.cols - 17, 2, 0)) == NULL)
		goto create_windows_fail;
	scrollok(nctx.win_message, TRUE);

	/* create nodelist window */
	if ((nctx.win_nodelist = newwin(nctx.rows - 4, 16, 2, nctx.cols - 16)) == NULL)
		goto create_windows_fail;

	/* create status window */
	if ((nctx.win_status = newwin(1, nctx.cols, nctx.rows - 2, 0)) == NULL)
		goto create_windows_fail;

	/* create input window */
	if ((nctx.win_input = newwin(1, nctx.cols, nctx.rows - 1, 0)) == NULL)
		goto create_windows_fail;
	keypad(nctx.win_input, TRUE);

	return 0;

create_windows_fail:
	msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not create ncurses window");
	return -1;
}

static void load_history(void)
{
	FILE *fp;

	if (nctx.histfile[0] == '\0')
		return;

	fp = fopen(nctx.histfile, "r");
	if (fp) {
		size_t h, i, j, len;
		char linebuf[LBS*4], *pc;

		for (h = 0; h < HISTORYSIZE; h++) {
			pc = fgets(linebuf, sizeof(linebuf), fp);
			if (pc == NULL)
				break;

			len = strlen(linebuf);
			if (len >= sizeof(linebuf)-1 || linebuf[len-1] != '\n')
				break;

			/* delete trailing '\n' */
			linebuf[len-1] = '\0';
			len--;

			for (i = 0; i < len; ) {
				for (j = 0; j < utf8_bytes_in_sequence((unsigned char)linebuf[i]); j++) {
					nctx.history[h].wlinebuf[nctx.history[h].wlinepos][j] = (unsigned char)linebuf[i];
					i++;
				}
				nctx.history[h].wlinepos++;
			}
			nctx.historyfilled++;
			nctx.historypos = (nctx.historypos + 1) % HISTORYSIZE;
		}
		fclose(fp);
	}
}

static void store_history(void)
{
	FILE *fp;

	if (nctx.histfile[0] == '\0')
		return;

	fp = fopen(nctx.histfile, "w");
	if (fp) {
		int h, pos;
		size_t i, j;

		pos = (nctx.historypos - nctx.historyfilled + HISTORYSIZE) % HISTORYSIZE;
		for (h = 0; h < nctx.historyfilled; h++) {
			for (i = 0; i < nctx.history[pos].wlinepos; i++) {
				for (j = 0; j < utf8_bytes_in_sequence(nctx.history[pos].wlinebuf[i][0]); j++)
					fputc(nctx.history[pos].wlinebuf[i][j], fp);
			}
			fputc('\n', fp);
			pos = (pos + 1) % HISTORYSIZE;
		}
		fclose(fp);
	}
}

static void nc_print_cb(time_t ts, unsigned int type, const char *module, const char *msg)
{
	if (type == MB_TYPE_DEBUG || type == MB_TYPE_VERBOSE) {
		wattron(nctx.win_message, COLOR_PAIR(1));
		wprintw(nctx.win_message, "[%s][%s] %s\n", ts2time(ts), module, msg);
		wattroff(nctx.win_message, COLOR_PAIR(1));
	} else if (type == MB_TYPE_WARNING) {
		wattron(nctx.win_message, COLOR_PAIR(2));
		wprintw(nctx.win_message, "[%s][%s] %s\n", ts2time(ts), module, msg);
		wattroff(nctx.win_message, COLOR_PAIR(2));
	} else if (type == MB_TYPE_ERROR) {
		wattron(nctx.win_message, COLOR_PAIR(3));
		wprintw(nctx.win_message, "[%s][%s] %s\n", ts2time(ts), module, msg);
		wattroff(nctx.win_message, COLOR_PAIR(3));
	} else if (type == MB_TYPE_GUI) {
		wattron(nctx.win_message, COLOR_PAIR(4));
		wprintw(nctx.win_message, "[%s][%s] %s\n", ts2time(ts), module, msg);
		wattroff(nctx.win_message, COLOR_PAIR(4));
	} else if (type == MB_TYPE_CHAT) {
		wattron(nctx.win_message, A_BOLD);
		wprintw(nctx.win_message, "[%s] %s> %s\n", ts2time(ts), module, msg);
		wattroff(nctx.win_message, A_BOLD);
	} else {
		wprintw(nctx.win_message, "[%s][%s] %s\n", ts2time(ts), module, msg);
	}

	wnoutrefresh(nctx.win_message);
	wnoutrefresh(nctx.win_input);
	doupdate();
}

static void nc_die_cb(const char *msg, int exit_code)
{
	/* shut down ncurses if necessary */
	nc_close();

	logstr(msg);

	(void)exit_code;
}

int nc_init(const char *version, const char *nick, int theme, const char *histfile)
{
	initscr();
	if (has_colors() == FALSE) {
		endwin();
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Your terminal does not support colors");
		return -1;
	}
	start_color();
	if (theme <=0 || theme > 2) { /* classic theme */
		/* main windows / messages colors */
		assume_default_colors(COLOR_WHITE, COLOR_BLUE);
		init_pair(1, COLOR_GREEN,  COLOR_BLACK);
		init_pair(2, COLOR_YELLOW, COLOR_BLACK);
		init_pair(3, COLOR_RED,    COLOR_BLACK);
		init_pair(4, COLOR_WHITE,  COLOR_BLUE);
		/* bars colors */
		init_pair(10, COLOR_BLACK,  COLOR_WHITE);
		init_pair(11, COLOR_GREEN,  COLOR_WHITE);
		init_pair(12, COLOR_YELLOW, COLOR_WHITE);
		init_pair(13, COLOR_RED,    COLOR_WHITE);
	} else if (theme == 1) { /* dark theme */
		assume_default_colors(COLOR_WHITE, COLOR_BLACK);
		init_pair(1, COLOR_GREEN,  COLOR_BLACK);
		init_pair(2, COLOR_YELLOW, COLOR_BLACK);
		init_pair(3, COLOR_RED,    COLOR_BLACK);
		init_pair(4, COLOR_CYAN,   COLOR_BLACK);

		init_pair(10, COLOR_BLACK,  COLOR_WHITE);
		init_pair(11, COLOR_GREEN,  COLOR_WHITE);
		init_pair(12, COLOR_YELLOW, COLOR_WHITE);
		init_pair(13, COLOR_RED,    COLOR_WHITE);
	} else if (theme == 2) { /* clear theme */
		assume_default_colors(COLOR_BLACK, COLOR_WHITE);
		init_pair(1, COLOR_GREEN,  COLOR_WHITE);
		init_pair(2, COLOR_YELLOW, COLOR_WHITE);
		init_pair(3, COLOR_RED,    COLOR_WHITE);
		init_pair(4, COLOR_CYAN,   COLOR_WHITE);

		init_pair(10, COLOR_WHITE,  COLOR_CYAN);
		init_pair(11, COLOR_WHITE,  COLOR_CYAN);
		init_pair(12, COLOR_YELLOW, COLOR_CYAN);
		init_pair(13, COLOR_RED,    COLOR_CYAN);
	}
	cbreak();
	noecho();
	getmaxyx(stdscr, nctx.rows, nctx.cols);

	if (create_windows() == -1) {
		endwin();
		return -1;
	}

	nc_print_bars(version);
	nc_clear_input_line_and_print_prompt(nick, 1);

	if (histfile)
		strncpy(nctx.histfile, histfile, sizeof(nctx.histfile)-1);
	load_history();

	mb0.print_cb = nc_print_cb;
	die_cb       = nc_die_cb;

	nctx.initialized = 1;

	return 0;
}

int nc_resize(const char *version, const char *nick)
{
	/* delete windows */
	delwin(nctx.win_title);
	delwin(nctx.win_message);
	delwin(nctx.win_status);
	delwin(nctx.win_input);

	/* reset ncurses and get new dimensions */
	endwin();
	refresh();
	getmaxyx(stdscr, nctx.rows, nctx.cols);
	clear();
	refresh();

	/* recreate windows */
	if (create_windows() == -1)
		return -1;

	nc_print_bars(version);
	msgbook_print_backlog(&mb0);
#if 0
	snprintf(msgbuf, MBS, "Window resized to %dx%d", nctx.cols, nctx.rows);
	msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
#endif
	nc_clear_input_line_and_print_prompt(nick, 1);

	return 0;
}

void nc_close(void)
{
	/* shut down ncurses */
	if (nctx.initialized) {
		store_history();
		endwin();
		nctx.initialized = 0;
		msgbook_flush(&mb0, 0);
		mb0.print_cb = msgbook_print_cb_stderr;
		msgbook_flush(&mb0, 1);
	}
}

void nc_print_bars(const char *version)
{
	/* title bar */
	mvwprintw(nctx.win_title, 0, 0, " Seren, ver. %s", version);
	mvwchgat(nctx.win_title, 0, 0, -1, A_NORMAL, 10, NULL);
	wnoutrefresh(nctx.win_title);

	/* status bar */
	mvwaddch(nctx.win_status, 0, 0, ' ');
	mvwchgat(nctx.win_status, 0, 0, -1, A_NORMAL, 10, NULL);
	wnoutrefresh(nctx.win_status);

	doupdate();
}

void nc_clear_input_line_and_print_prompt(const char *nick, int delete_buffer)
{
	if (delete_buffer) {
		memset(nctx.wlinebuf, 0, sizeof(nctx.wlinebuf));
		nctx.wlinepos = 0;
	}

	mvwprintw(nctx.win_input, 0, 0, "%s> ", nick);
	wclrtoeol(nctx.win_input);
	wrefresh(nctx.win_input);
}

int nc_scroll_input_text(const char *nick, size_t right_space)
{
	int available_space;

	available_space = nctx.cols - ((int)strlen(nick) + 2) - /* leave a space on the right */ 1;
	if (available_space > 0 && nctx.wlinepos >= (size_t)available_space) {
		size_t i, j;

		nc_clear_input_line_and_print_prompt(nick, 0);
		for (i = nctx.wlinepos - (size_t)available_space + right_space; i < nctx.wlinepos; i++) {
			for (j = 0; j < utf8_bytes_in_sequence(nctx.wlinebuf[i][0]); j++)
				waddch(nctx.win_input, nctx.wlinebuf[i][j]);
		}
		return 1;
	}
	return 0;
}

void nc_print_wlinebuf(const char *nick)
{
	if (!nc_scroll_input_text(nick, 1)) {
		size_t i, j;

		nc_clear_input_line_and_print_prompt(nick, 0);
		for (i = 0; i < nctx.wlinepos; i++) {
			for (j = 0; j < utf8_bytes_in_sequence(nctx.wlinebuf[i][0]); j++)
				waddch(nctx.win_input, nctx.wlinebuf[i][j]);
		}
	}
	wrefresh(nctx.win_input);
}

void nc_update_linebuf(void)
{
	size_t i, j;

	memset(nctx.linebuf, 0, sizeof(nctx.linebuf));
	nctx.linepos = 0;
	for (i = 0; i < nctx.wlinepos; i++) {
		for (j = 0; j < utf8_bytes_in_sequence(nctx.wlinebuf[i][0]); j++)
			nctx.linebuf[nctx.linepos++] = (char)nctx.wlinebuf[i][j];
	}
}

void nc_status(int micmute, int record, int mode, float peak_percent, double dBSPL,
               const char *timer_str, const char *stat_str)
{
	int peakcolor, n, h;
	const char * const mode_name[] = {"CLR", "SEC", "PSK"};

	if (micmute)
		peakcolor = 13;
	else
		peakcolor = (peak_percent <= 50.0f) ? 11 : ((peak_percent <= 80.0f) ? 12 : 13);

	wmove(nctx.win_status, 0, 0);
	wattron(nctx.win_status, COLOR_PAIR(10));
	wprintw(nctx.win_status, "\r%s[", timer_str);
	mode = mode <= 0 ? 0 : (mode > 2 ? 2 : mode);
	wattron(nctx.win_status, COLOR_PAIR(11+mode));
	waddstr(nctx.win_status, mode_name[mode]);
	wattron(nctx.win_status, COLOR_PAIR(10));
	waddch(nctx.win_status, '|');
	wattron(nctx.win_status, COLOR_PAIR(13));
	waddstr(nctx.win_status, record ? "REC" : "   ");
	wattron(nctx.win_status, COLOR_PAIR(10));
	waddstr(nctx.win_status, "]  mic[");
	n = micmute ? -90 : (int)lrint(dBSPL);
	n = (n < -50) ? 0 : (n+50); /* min -50dB */
	n = (n + 2) / 3;            /* 3dB step  */
	/*wprintw(nctx.win_status, "%+05.1f|", dBSPL);*/
	for (h = 0; h < 14; h++)
		waddch(nctx.win_status, h < n ? '#' : ' ');
	waddch(nctx.win_status, '|');
	wattron(nctx.win_status, COLOR_PAIR(peakcolor));
	if (micmute)
		wprintw(nctx.win_status, "MUTE");
	else
		wprintw(nctx.win_status, "%3.0f%%", peak_percent);
	wattron(nctx.win_status, COLOR_PAIR(10));
	wprintw(nctx.win_status, "]  %s", stat_str);
	wattroff(nctx.win_status, COLOR_PAIR(10));
	wchgat(nctx.win_status, -1, A_NORMAL, 10, NULL);

	wnoutrefresh(nctx.win_status);
	wnoutrefresh(nctx.win_input);
	doupdate();
}

void nc_nodelist(unsigned int nb_nodes, int mode, struct nc_node_info ni[])
{
	unsigned int i;
	const char * const algo_name[] = {
		"XTEA",
		"CAST",
		"BLOW",
		"CAME",
		"TWOF",
		" ?? ",
		" -- "
	};

	werase(nctx.win_nodelist);
	mvwaddstr(nctx.win_nodelist, 0, 0, "      Nodes\n\n");
	for (i = 0; i < nb_nodes; i++) {
		if (ni[i].nick) {
			int n, h;

			if (i == 0) {
				wprintw(nctx.win_nodelist, " * %s\n ", ni[0].nick);
			} else {
				int health;
				unsigned int pl10k_max;
				const char *current_algo;

				pl10k_max = ni[i].pl10k >= ni[i].tm_pl10k ? ni[i].pl10k : ni[i].tm_pl10k;
				health = pl10k_max <= 5000U ? 0 : (pl10k_max <= 50000U ? 1 : 2);

				wattron(nctx.win_nodelist, COLOR_PAIR(1+health));
				wprintw(nctx.win_nodelist, " %d %.12s\n ", i-1, ni[i].nick[0] == '\0' ? "?" : ni[i].nick);
				wattroff(nctx.win_nodelist, COLOR_PAIR(1+health));

				waddch(nctx.win_nodelist, ACS_VLINE);
				if (ni[i].algo < 0 || ni[i].algo > 3)
					ni[i].algo = 4;
				current_algo = mode == 0 ? algo_name[6] :
				              (mode == 1 ? algo_name[ni[i].algo] : algo_name[ni[0].algo]);
				wprintw(nctx.win_nodelist, " %s %3.0f/%3u\n ", current_algo, ni[i].rtt_us * 0.001, ni[i].nb_frames*20);

				waddch(nctx.win_nodelist, ACS_VLINE);
				wprintw(nctx.win_nodelist, " %2ukHz %s\n ", ni[i].bandwidth/1000, ni[i].nb_channels == 2 ? "stereo" : " mono ");

				waddch(nctx.win_nodelist, ACS_VLINE);
				wprintw(nctx.win_nodelist, " %.1f↓  %.1f↑\n ",
				        (float)ni[i].pl10k / 10000.0f, (float)ni[i].tm_pl10k / 10000.0f);
			}

			waddch(nctx.win_nodelist, ACS_LLCORNER);
			n = ni[i].nb_frames == 0 ? -90 : (int)lrint(ni[i].dBSPL);
			n = (n < -50) ? 0 : (n+50); /* min -50dB */
			n = (n + 2) / 3;            /* 3dB step  */
			/*wprintw(nctx.win_nodelist, "%+05.1f|", dBSPL[i]);*/
			for (h = 0; h < 14; h++)
				waddch(nctx.win_nodelist, h < n ? '#' : ' ');
		}
	}
	mvwvline(nctx.win_nodelist, 0, 0, ACS_VLINE, nctx.rows - 4 - 1);
	mvwaddch(nctx.win_nodelist, 1, 0, ACS_LTEE);
	mvwhline(nctx.win_nodelist, 1, 1, ACS_HLINE, 16);
	wnoutrefresh(nctx.win_nodelist);
	wnoutrefresh(nctx.win_input);
	doupdate();
}

#undef MODULE

#endif /* defined(HAVE_LIBNCURSESW) */
