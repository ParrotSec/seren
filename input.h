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

#ifndef INPUT_H
#define INPUT_H

#define CMD_MAXARGS        2

#define CMD_OK             0
#define CMD_ERROR         -1
#define CMD_UNKNOWN       -2
#define CMD_MISSING_PARAM -3
#define CMD_INVALID_RANGE -4

extern char   *cmd_host;
extern char   *cmd_key;
extern char    cmd_name;
extern int     cmd_node;
extern int     cmd_bitrate;
extern int     cmd_port;
extern int     cmd_mode;
extern int     cmd_algo;
extern int     cmd_verbose;
extern float   cmd_gain;

void cmd_get_global_help(char *str, size_t len);
int  cmd_get_option_help(char name, char *str, size_t len);
int  cmd_parse(char *line, char *name, unsigned int *nb_args_read);

#endif
