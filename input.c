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
#include <string.h>
#include "input.h"

char   *cmd_host;
char   *cmd_key;
char    cmd_name;
int     cmd_node;
int     cmd_bitrate;
int     cmd_port;
int     cmd_mode;
int     cmd_algo;
int     cmd_verbose;
float   cmd_gain;

enum cmd_type {
	ct_none,
	ct_string,
	ct_char,
	ct_int,
	ct_float,
	ct_double
};

struct cmd {
	const char    *long_name;
	char           short_name;

	unsigned int   nb_args;
	struct {
		enum cmd_type  type;
		const char    *name;
		unsigned int   optional;
		unsigned int   check_range;
		double         min;
		double         max;
		void          *data;
	} arg[CMD_MAXARGS];

	const char    *description1;
	const char    *description2;
	const char    *shortcut;
};

#define ARGZ {ct_none, NULL, 0, 0, 0, 0, NULL}
#define PNONE { ARGZ }

static const struct cmd commands[] = {
	{ "help",       'h', 1, { {ct_char, "[command]", 1, 0, 0.0, 0.0, &cmd_name} }, "print help", NULL, NULL },
	{ "info",       'i', 0, PNONE, "print info", NULL, "F4" },
	{ "micmute",    'm', 0, PNONE, "toggle mic mute", NULL, "F5" },
	{ "loopback",   'l', 0, PNONE, "toggle audio loopback", NULL, "F6" },
	{ "chattones",  't', 0, PNONE, "toggle chat tones", NULL, NULL },
	{ "ringtone",   'T', 0, PNONE, "toggle ringtone", NULL, NULL },
	{ "autoaccept", 'a', 0, PNONE, "toggle autoaccept calls", NULL, NULL },
	{ "fifo",       'f', 0, PNONE, "toggle fifo", NULL, NULL },
	{ "oggrec",     'r', 0, PNONE, "toggle ogg recording", NULL, NULL },
	{ "wavrec",     'R', 0, PNONE, "toggle wav recording", NULL, NULL },
	{ "micgain",    'g', 1, { {ct_float, "gain", 0, 1, -40.0, 40.0, &cmd_gain} }, "set mic gain in dB", NULL, NULL },
	{ "nodegain",   'G', 2, { {ct_int, "n", 0, 0, 0.0, 0.0, &cmd_node}, {ct_float, "gain", 0, 1, -40.0, 40.0, &cmd_gain} }, "set node n gain in dB", NULL, NULL },
	{ "bitrate",    'b', 1, { {ct_int, "bitrate", 0, 1, 6000.0, 512000.0, &cmd_bitrate} }, "set bitrate", NULL, NULL },
	{ "kill",       'k', 1, { {ct_int, "n", 0, 0, 0.0, 0.0, &cmd_node} }, "kill node n", NULL, NULL },
	{ "call",       'c', 2, { {ct_string, "host", 0, 0, 0.0, 0.0, &cmd_host}, {ct_int, "[port]", 1, 0, 0.0, 0.0, &cmd_port} }, "call host", NULL, NULL },
	{ "abortcall",  'C', 0, PNONE, "abort calling", NULL, NULL },
	{ "hangup",     'H', 0, PNONE, "hangup call", NULL, NULL },
	{ "accept",     'y', 0, PNONE, "accept call", NULL, "F7" },
	{ "refuse",     'n', 0, PNONE, "refuse call", NULL, "F8" },
	{ "mode",       'e', 1, { {ct_int, "mode", 0, 1, 0.0, 2.0, &cmd_mode} }, "set node mode", "0:clear, 1:secure, 2:psk", NULL },
	{ "algo",       'X', 1, { {ct_int, "algo", 0, 1, 0.0, 4.0, &cmd_algo} }, "set encryption algorithm", "0:XTEA, 1:CAST5, 2:Blowfish, 3:Camellia, 4:Twofish", NULL },
	{ "key",        'x', 1, { {ct_string, "key", 0, 0, 0.0, 0.0, &cmd_key} }, "set pre-shared key", NULL, NULL },
	{ "verbose",    'v', 1, { {ct_int, "level", 0, 1, 0.0, 3.0, &cmd_verbose} }, "set verbosity level", NULL, NULL },
	{ "quit",       'q', 0, PNONE, "quit", NULL, "C-c" },
	{ NULL,         ' ', 0, PNONE, NULL, NULL, NULL }
};

static void insert_spaces(char *str, size_t len, size_t num)
{
	size_t l;
	char spaces[256];

	l = sizeof(spaces);
	memset(spaces, 0, l);
	num = num > l-1 ? l-1 : num;
	memset(spaces, ' ', num);

	l = strlen(str);
	if (l < len-1)
		snprintf(str+l, len-l, "%s", spaces);
}

static int str_append(char *dest, size_t dlen, const char *src)
{
	size_t l, space;

	if (dlen <= 1)
		return -1;

	l = strlen(dest);
	if (l >= dlen-1)
		return -1;

	space = dlen-1 - l;

	strncat(dest, src, space);

	l = strlen(src);

	return (int)(l < space ? l : space);
}

void cmd_get_global_help(char *str, size_t len)
{
	unsigned int i, j;
	size_t k;
	char line[256], buf[256];

	str[0] = '\0';
	snprintf(str, len, "help:\ncommand          description                range\n");

	for (i = 0; commands[i].long_name; i++) {
		/* first line */
		line[0] = '\0';
		snprintf(buf, sizeof(buf), " /%c", commands[i].short_name);
		str_append(line, sizeof(line), buf);

		k = 14;
		for (j = 0; j < commands[i].nb_args; j++) {
			if (commands[i].arg[j].name) {
				snprintf(buf, sizeof(buf), " %s", commands[i].arg[j].name);
				str_append(line, sizeof(line), buf);
				k -= strlen(buf);
			}
		}
		insert_spaces(line, sizeof(line), k);

		k = 26;
		snprintf(buf, sizeof(buf), "%s", commands[i].description1);
		str_append(line, sizeof(line), buf);
		k -= strlen(buf);
		insert_spaces(line, sizeof(line), k);

		for (j = 0; j < commands[i].nb_args; j++) {
			if (commands[i].arg[j].check_range) {
				switch (commands[i].arg[j].type) {
				case ct_none:
				case ct_string:
					break;
				case ct_char:
					snprintf(buf, sizeof(buf), " [%c,%c]", (char)commands[i].arg[j].min, (char)commands[i].arg[j].max);
					break;
				case ct_int:
					snprintf(buf, sizeof(buf), " [%d,%d]", (int)commands[i].arg[j].min, (int)commands[i].arg[j].max);
					break;
				case ct_float:
				case ct_double:
					snprintf(buf, sizeof(buf), " [%.1f,%.1f]", commands[i].arg[j].min, commands[i].arg[j].max);
					break;
				}
				str_append(line, sizeof(line), buf);
			}
		}
		str_append(line, sizeof(line), "\n");

		str_append(str, len, line);

		/* second line */
		line[0] = '\0';
		if (commands[i].description2) {
			k = 17;
			insert_spaces(line, sizeof(line), k);

			snprintf(buf, sizeof(buf), "%s\n", commands[i].description2);
			str_append(line, sizeof(line), buf);
		}

		str_append(str, len, line);
	}

	/* shortcut line */
	line[0] = '\0';
	snprintf(line, sizeof(line), "\nshortcuts:");
	for (i = 0; commands[i].long_name; i++) {
		if (commands[i].shortcut) {
			snprintf(buf, sizeof(buf), " /%c:%s", commands[i].short_name, commands[i].shortcut);
			str_append(line, sizeof(line), buf);
		}
	}

	str_append(str, len, line);
}

int cmd_get_option_help(char name, char *str, size_t len)
{
	unsigned int i, j, found, print_range;
	char buf[256];

	str[0] = '\0';

	found = 0;
	for (i = 0; commands[i].long_name; i++) {
		if (commands[i].short_name == name) {
			found = 1;
			break;
		}
	}
	if (!found) {
		snprintf(str, len, "Unknown command '%c'", name);
		return CMD_UNKNOWN;
	}

	snprintf(buf, sizeof(buf), "help for '%c':", commands[i].short_name);
	str_append(str, len, buf);

	snprintf(buf, sizeof(buf), "\n%12s /%c", "format:", commands[i].short_name);
	str_append(str, len, buf);
	for (j = 0; j < commands[i].nb_args; j++) {
		if (commands[i].arg[j].name) {
			snprintf(buf, sizeof(buf), " %s", commands[i].arg[j].name);
			str_append(str, len, buf);
		}
	}

	snprintf(buf, sizeof(buf), "\n%12s %u", "args:", commands[i].nb_args);
	str_append(str, len, buf);
	if (commands[i].nb_args) {
		snprintf(buf, sizeof(buf), "\n%12s", "type:");
		str_append(str, len, buf);
		for (j = 0; j < commands[i].nb_args; j++) {
			if (j)
				str_append(str, len, ",");

			switch (commands[i].arg[j].type) {
				case ct_none:
					str_append(str, len, " none");
					break;
				case ct_string:
					str_append(str, len, " string");
					break;
				case ct_char:
					str_append(str, len, " char");
					break;
				case ct_int:
					str_append(str, len, " int");
					break;
				case ct_float:
					str_append(str, len, " float");
					break;
				case ct_double:
					str_append(str, len, " double");
					break;
				}
		}
	}

	print_range = 0;
	for (j = 0; j < commands[i].nb_args; j++) {
		if (commands[i].arg[j].check_range) {
			print_range = 1;
			break;
		}
	}
	if (print_range) {
		snprintf(buf, sizeof(buf), "\n%12s", "range:");
		str_append(str, len, buf);
		for (j = 0; j < commands[i].nb_args; j++) {
			if (commands[i].arg[j].check_range) {
				switch (commands[i].arg[j].type) {
				case ct_none:
				case ct_string:
					break;
				case ct_char:
					snprintf(buf, sizeof(buf), " [%c,%c]", (char)commands[i].arg[j].min, (char)commands[i].arg[j].max);
					break;
				case ct_int:
					snprintf(buf, sizeof(buf), " [%d,%d]", (int)commands[i].arg[j].min, (int)commands[i].arg[j].max);
					break;
				case ct_float:
				case ct_double:
					snprintf(buf, sizeof(buf), " [%.1f,%.1f]", commands[i].arg[j].min, commands[i].arg[j].max);
					break;
				}
				str_append(str, len, buf);
			} else {
				str_append(str, len, " []");
			}
		}
	}

	snprintf(buf, sizeof(buf), "\n%12s %s", "desc1:", commands[i].description1);
	str_append(str, len, buf);
	if (commands[i].description2) {
		snprintf(buf, sizeof(buf), "\n%12s %s", "desc2:", commands[i].description2);
		str_append(str, len, buf);
	}

	return CMD_OK;
}

int cmd_parse(char *line, char *name, unsigned int *nb_args_read)
{
	unsigned int i, j, found;
	size_t len;
	char *pc, *start, *end;

	len = strlen(line);
	if (len < 2 || line[0] != '/')
		return CMD_ERROR;

	found = 0;
	*name = line[1];
	for (i = 0; commands[i].long_name; i++) {
		if (commands[i].short_name == *name) {
			found = 1;
			break;
		}
	}
	if (!found)
		return CMD_UNKNOWN;

	if (commands[i].nb_args) {
		int need_arg = 0;

		for (j = 0; j < commands[i].nb_args; j++) {
			if (commands[i].arg[j].optional == 0)
				need_arg++;
		}
		if (need_arg && len < 3)
			return CMD_MISSING_PARAM;
		if (need_arg && len >= 3 && line[2] != ' ')
			return CMD_ERROR;
	}

	*nb_args_read = 0;
	start = &line[3];
	for (j = 0; j < commands[i].nb_args; j++) {
		char   v_char;
		int    v_int;
		float  v_float;
		double v_double;

		/* skip spaces */
		while (start && *start == ' ')
			start++;

		/* check if we can read the next argument */
		if (start == NULL || *start == '\0') {
			if (commands[i].arg[j].optional)
				break;
			else
				return CMD_MISSING_PARAM;
		}

		switch (commands[i].arg[j].type) {
		case ct_none:
			break;
		case ct_string:
			pc = strchr(start, ' ');
			if (pc) {
				end = pc;
				*end = '\0';
				*((char **)commands[i].arg[j].data) = start;
				start = end+1;
			} else {
				*((char **)commands[i].arg[j].data) = start;
				start = NULL;
			}
			(*nb_args_read)++;
			break;
		case ct_char:
			v_char = 0;
			sscanf(start, "%c", &v_char);
			if (commands[i].arg[j].check_range) {
				if (v_char < (char)commands[i].arg[j].min || v_char > (char)commands[i].arg[j].max)
					return CMD_INVALID_RANGE;
			}
			*((char *)commands[i].arg[j].data) = v_char;
			(*nb_args_read)++;
			start = strchr(start, ' ');
			break;
		case ct_int:
			v_int = -1;
			sscanf(start, "%d", &v_int);
			if (commands[i].arg[j].check_range) {
				if (v_int < (int)commands[i].arg[j].min || v_int > (int)commands[i].arg[j].max)
					return CMD_INVALID_RANGE;
			}
			*((int *)commands[i].arg[j].data) = v_int;
			(*nb_args_read)++;
			start = strchr(start, ' ');
			break;
		case ct_float:
			v_float = 0.0f;
			sscanf(start, "%f", &v_float);
			if (commands[i].arg[j].check_range) {
				if (v_float < (float)commands[i].arg[j].min || v_float > (float)commands[i].arg[j].max)
					return CMD_INVALID_RANGE;
			}
			*((float *)commands[i].arg[j].data) = v_float;
			(*nb_args_read)++;
			start = strchr(start, ' ');
			break;
		case ct_double:
			v_double = 0.0;
			sscanf(start, "%lf", &v_double);
			if (commands[i].arg[j].check_range) {
				if (v_double < commands[i].arg[j].min || v_double > commands[i].arg[j].max)
					return CMD_INVALID_RANGE;
			}
			*((double *)commands[i].arg[j].data) = v_double;
			(*nb_args_read)++;
			start = strchr(start, ' ');
			break;
		}
	}

	return CMD_OK;
}
