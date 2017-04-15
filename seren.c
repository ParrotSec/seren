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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pc-engine.h"
#include "common.h"
#include "msgbook.h"
#include "input.h"
#include "nc.h"
#include "stun.h"
#include "random.h"

#define SERENDIR  ".seren"
#define LOGFILE   "seren.log"
#define CONFFILE  "seren.conf"
#define HISTFILE  "history"
#define FIFOIN    "fifo_in"
#define FIFOOUT   "fifo_out"
#define MODULE    "main"

static volatile sig_atomic_t keep_going;
#ifdef HAVE_LIBNCURSESW
static volatile sig_atomic_t window_resized;
#endif

static void signal_handler(int sig)
{
	if (sig == SIGINT)
		keep_going = 0;
#ifdef HAVE_LIBNCURSESW
	if (sig == SIGWINCH)
		window_resized = 1;
#endif
}

static void handle_events(struct pc_context *pctx)
{
	struct slist *p;

	p = pctx->events;
	while (p) {
		struct slist *pnext = p->next;
		struct pc_event *ev = p->data;

		switch (ev->type) {
		case event_type_mute:
			snprintf(msgbuf, MBS, "Mute: %s", pctx->micmute ? "on" : "off");
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_loopback:
			snprintf(msgbuf, MBS, "Loopback: %s", pctx->lb ? "on" : "off");
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_tones:
			snprintf(msgbuf, MBS, "Tones: %s", pctx->tone.enable ? "on" : "off");
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_ringtone:
			snprintf(msgbuf, MBS, "Ringtone: %s", pctx->ringtone.enable ? "on" : "off");
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_autoaccept_calls:
			snprintf(msgbuf, MBS, "Autoaccept calls: %s", pctx->autoaccept_calls ? "on" : "off");
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_fifo:
			snprintf(msgbuf, MBS, "Fifo: %s", pctx->fifo ? "on" : "off");
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_recording:
			snprintf(msgbuf, MBS, "Recording: %s%s%s", pctx->record ? "on" : "off",
			         pctx->record ? ", file: " : "",
			         pctx->record ? pctx->record_filename : "");
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_micgain:
			snprintf(msgbuf, MBS, "Mic gain: %.2f dB", pctx->micgain_dB);
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_bitrate:
			snprintf(msgbuf, MBS, "Bitrate: %d bit/s", pctx->bitrate);
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_mode:
			snprintf(msgbuf, MBS, "Encryption mode: %s",
			pctx->mode == mode_clear ? "clear" : (pctx->mode == mode_secure ? "secure" : "pre-shared key"));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_setalgo:
			snprintf(msgbuf, MBS, "Algorithm: %s", pc_algo_name[pctx->algo]);
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_setpsk:
			{
				size_t i, l;

				snprintf(msgbuf, MBS, "pre-shared key: %zd bit, ", pctx->psklen);
				for (i = 0; i < pctx->psklen / 8; i++) {
					l = strlen(msgbuf);
					snprintf(msgbuf+l, MBS-l, "%02x", pctx->psk[i]);
				}
			}
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_nodegain:
			snprintf(msgbuf, MBS, "Gain for %s (%s:%hu) set to %.2f dB",
			         ev->nick, inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port), ev->f);
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_node_delete:
			snprintf(msgbuf, MBS, "%s%s(%s:%hu) has left (reason: %s)",
			         ev->nick[0] ? ev->nick : "", ev->nick[0] ? " " : "",
			         inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port),
			         ev->i == DELETE_REASON_LEFT ? "call ended" : "timeout");
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_node_add:
			snprintf(msgbuf, MBS, "%s%s(%s:%hu) has joined the conference",
			         ev->nick[0] ? ev->nick : "", ev->nick[0] ? " " : "",
			         inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_chat:
			msgbook_enqueue(&mb0, MB_TYPE_CHAT, ev->nick, (char *)ev->data);
			break;
		case event_type_calling_in_progress:
			snprintf(msgbuf, MBS, "Calling %s:%hu...",
			         inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_calling_aborted:
			snprintf(msgbuf, MBS, "Calling %s:%hu aborted",
			         inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_incoming_call:
			snprintf(msgbuf, MBS, "%s (%s:%hu) is calling: /y to accept, /n to refuse",
			         ev->nick, inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_incoming_call_lost:
			snprintf(msgbuf, MBS, "Lost one call from %s (%s:%hu)",
			         ev->nick, inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_chose_refused:
			snprintf(msgbuf, MBS, "Call from %s (%s:%hu) refused",
			          ev->nick, inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_chose_accepted:
			snprintf(msgbuf, MBS, "Call from %s (%s:%hu) accepted",
			         ev->nick, inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_call_refused:
			snprintf(msgbuf, MBS, "%s%s(%s:%hu) refused the call (reason: %s)",
			         ev->nick[0] ? ev->nick : "", ev->nick[0] ? " " : "",
			         inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port),
			         ev->i == REFUSE_REASON_USER ? "user refused the call" :
			         (ev->i == REFUSE_REASON_VERSION ? "version mismatch" : "node is full"));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_call_accepted:
			snprintf(msgbuf, MBS, "%s%s(%s:%hu) accepted the call",
			         ev->nick[0] ? ev->nick : "", ev->nick[0] ? " " : "",
			         inet_ntoa(ev->addr.sin_addr), ntohs(ev->addr.sin_port));
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		case event_type_call_hangup:
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, "Hang up");
			break;
		case event_type_verbose:
			snprintf(msgbuf, MBS, "Verbosity level: %d", *pctx->verbose);
			msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);
			break;
		}

		free(ev->data);
		free(ev);
		pctx->events = slist_remove_element(pctx->events, p);

		p = pnext;
	}
}

/* Returns: 0 on success, -1 on error, 1 if command was /q */
static int parse_and_execute_command(const char *command_line, struct pc_context *pctx)
{
	char cl[128], name;
	int ret;
	unsigned int nb_args_read;
	size_t len;

	if (command_line == NULL)
		return -1;

	len = strlen(command_line);
	if (len > 127) {
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Command string is too long");
		return -1;
	}

	/* copy command line */
	strncpy(cl, command_line, 127);
	cl[127] = '\0';
	len = strlen(cl);

	/* delete trailing '\n' if necessary */
	if (cl[len-1] == '\n') {
		cl[len-1] = '\0';
		len--;
	}

	/* parse command */
	ret = cmd_parse(cl, &name, &nb_args_read);
	switch (ret) {
	case CMD_ERROR:
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Bad command string");
		return -1;
	case CMD_UNKNOWN:
		snprintf(msgbuf, MBS, "Unknown command '%c'", name);
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return -1;
	case CMD_MISSING_PARAM:
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Missing command parameter");
		return -1;
	case CMD_INVALID_RANGE:
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Invalid parameter range");
		return -1;
	default:
		break;
	}

	switch (name) {
	case 'h':
		if (nb_args_read == 0)
			cmd_get_global_help(msgbuf, MBS);
		else
			cmd_get_option_help(cmd_name, msgbuf, MBS);
		msgbook_enqueue(&mb0, MB_TYPE_INFO, MODULE, msgbuf);
		break;
	case 'i':
		pc_engine_cmd_print_info(pctx);
		break;
	case 'm':
		pc_engine_cmd_toggle_mute(pctx);
		break;
	case 'l':
		pc_engine_cmd_toggle_loopback(pctx);
		break;
	case 't':
		pc_engine_cmd_toggle_tones(pctx);
		break;
	case 'T':
		pc_engine_cmd_toggle_ringtone(pctx);
		break;
	case 'a':
		pc_engine_cmd_toggle_autoaccept_calls(pctx);
		break;
	case 'f':
		pc_engine_cmd_toggle_fifo(pctx);
		break;
	case 'r':
	case 'R':
		ret = pc_engine_cmd_toggle_recording(pctx, name == 'r' ? REC_OPUS : REC_WAVE);
		if (ret == -1)
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not start recording");
		break;
	case 'g':
		ret = pc_engine_cmd_set_micgain(pctx, cmd_gain);
		if (ret == -1)
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not set micgain");
		break;
	case 'G':
		ret = pc_engine_cmd_set_nodegain(pctx, cmd_node, cmd_gain);
		if (ret == -1)
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not set node gain");
		break;
	case 'b':
		ret = pc_engine_cmd_set_bitrate(pctx, cmd_bitrate);
		if (ret == -1)
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not set bitrate");
		break;
	case 'k':
		ret = pc_engine_cmd_kill_node(pctx, cmd_node);
		if (ret == -1)
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not kill node");
		break;
	case 'c':
		if (nb_args_read == 1)
			cmd_port = 8110;

		ret = pc_engine_cmd_call_node(pctx, cmd_host, (uint16_t)cmd_port);
		if (ret == -1) {
			snprintf(msgbuf, MBS, "Could not call '%s:%d'", cmd_host, cmd_port);
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		}
		break;
	case 'C':
		pc_engine_cmd_abort_calling(pctx);
		break;
	case 'H':
		pc_engine_cmd_hangup(pctx);
		break;
	case 'y':
		pc_engine_cmd_accept_call(pctx);
		break;
	case 'n':
		pc_engine_cmd_refuse_call(pctx);
		break;
	case 'e':
		ret = pc_engine_cmd_set_mode(pctx, cmd_mode);
		if (ret == -1)
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not set mode");
		break;
	case 'X':
		ret = pc_engine_cmd_set_algo(pctx, cmd_algo);
		if (ret == -1)
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not set algo");
		break;
	case 'x':
		{
			char key[128];
			size_t klen;

			/* key is at most 384-bit = 48 bytes = 96 hex characters. */
			memset(key, 0, sizeof(key));
			strncpy(key, cmd_key, 96);
			klen = strlen(key);

			pc_engine_cmd_set_psk(pctx, (unsigned char *)key, klen);
		}
		break;
	case 'v':
		ret = pc_engine_cmd_set_verbose(pctx, cmd_verbose);
		if (ret == -1)
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, "Could not set verbosity level");
		break;
	case 'q':
		return 1;
		break;
	default:
		snprintf(msgbuf, MBS, "Command '%c' not handled", name);
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
	}

	return 0;
}

static void usage(void)
{
	fputs(
"Usage: seren [option...]\n"
"\n"
"Options:\n"
"  -h             print help\n"
"  -v             increment verbosity level\n"
"  -L logfile     log messages to logfile       ($HOME/.seren/seren.log)\n"
#ifdef HAVE_LIBNCURSESW
"  -N             disable ncurses interface\n"
"  -t theme       set ncurses theme\n"
"                 0-simple, 1-dark, 2-clear     (1)\n"
#endif
"  -n nick        set nickname                  (login name)\n"
"  -p port        set udp listening port        (8110)\n"
"  -b bitrate     set bitrate in bit/s          (16000)\n"
"  -C complexity  set encoder complexity [0-10] (10)\n"
#ifdef DEFAULT_PULSE
"  -d audiodev    set playback audio device     (pulse)\n"
#else
"  -d audiodev    set playback audio device     (hw:0,0)\n"
#endif
"  -D audiodev    set capture audio device      (playback device)\n"
"  -c host[:port] autocall host on startup\n"
"  -a             autoaccept calls\n"
"  -S             disable STUN\n",
	stderr);
}

struct options {
	int   verbose;
	char *logfile;
#ifdef HAVE_LIBNCURSESW
	int   disable_ncurses;
	int   ncurses_theme;
#endif
	char  nick[NICKLEN];
	int   local_port;
	int   bitrate;
	int   complexity;
	char *audiodevice_playback;
	char *audiodevice_capture;
	char *autocall_host;
	int   autoaccept_calls;
	int   disable_stun;
};

static void parse_conf_file(const char *filename, struct options *options)
{
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp) {
		/* create default conf file */
		FILE *fp_w = fopen(filename, "w");
		if (fp_w) {
			fputs(
"# Seren configuration file\n"
"# To activate an option uncomment the associated line\n"
"\n"
"#verbose          0\n"
"#logfile          /path/to/log\n"
"#disable_ncurses  0\n"
"#ncurses_theme    1\n"
"#nick             mynick\n"
"#port             8110\n"
"#bitrate          16000\n"
"#complexity       10\n"
"#playback_dev     hw:0,0\n"
"#capture_dev      hw:0,0\n"
"#autocall_host    0.0.0.0:8110\n"
"#autoaccept_calls 0\n"
"#disable_stun     0\n",
			fp_w);
			fclose(fp_w);
		}
		return;
	}

	while (1) {
		char buf[128], *pc, *name, *value;
		size_t len;

		/* read an entire line */
		pc = fgets(buf, 128, fp);
		if (pc == NULL)
			break;

		/* skip if it's a comment or does not end with '\n' */
		len = strlen(buf);
		if (buf[0] == '#' || buf[len-1] != '\n')
			continue;

		/* delete trailing '\n' */
		buf[len-1] = '\0';
		len--;

		/* skip leading spaces */
		while (*pc == ' ')
			pc++;
		name = pc;

		/* find space(s) that separates property name from value */
		pc = strchr(name, ' ');
		if (pc == NULL)
			continue;
		*pc = '\0';
		/* skip leading spaces */
		pc++;
		while (*pc == ' ')
			pc++;
		value = pc;
		/* delete trailing spaces */
		pc = strchr(value, ' ');
		if (pc)
			*pc = '\0';

		if (strcmp(name, "verbose") == 0) {
			options->verbose = atoi(value);
		} else if (strcmp(name, "logfile") == 0) {
			free(options->logfile);
			options->logfile = xmalloc(strlen(value)+1);
			strcpy(options->logfile, value);
#ifdef HAVE_LIBNCURSESW
		} else if (strcmp(name, "disable_ncurses") == 0) {
			options->disable_ncurses = atoi(value);
		} else if (strcmp(name, "ncurses_theme") == 0) {
			options->ncurses_theme = atoi(value);
#endif
		} else if (strcmp(name, "nick") == 0) {
			strncpy(options->nick, value, NICKLEN-1);
			options->nick[NICKLEN-1] = '\0';
		} else if (strcmp(name, "port") == 0) {
			options->local_port = atoi(value);
		} else if (strcmp(name, "bitrate") == 0) {
			options->bitrate = atoi(value);
		} else if (strcmp(name, "complexity") == 0) {
			options->complexity = atoi(value);
		} else if (strcmp(name, "playback_dev") == 0) {
			free(options->audiodevice_playback);
			options->audiodevice_playback = xmalloc(strlen(value)+1);
			strcpy(options->audiodevice_playback, value);
		} else if (strcmp(name, "capture_dev") == 0) {
			free(options->audiodevice_capture);
			options->audiodevice_capture = xmalloc(strlen(value)+1);
			strcpy(options->audiodevice_capture, value);
		} else if (strcmp(name, "autocall_host") == 0) {
			free(options->autocall_host);
			options->autocall_host = xmalloc(strlen(value)+1);
			strcpy(options->autocall_host, value);
		} else if (strcmp(name, "autoaccept_calls") == 0) {
			options->autoaccept_calls = (value[0] == '1') ? 1 : 0;
		} else if (strcmp(name, "disable_stun") == 0) {
			options->disable_stun = (value[0] == '1') ? 1 : 0;
		}
	}
	fclose(fp);
}


int main(int argc, char *argv[])
{
	int                  ret, opt, pollret, keep_going_capture;
	struct pollfd        pfds[6];
	unsigned int         nfds, skip_stdin = 0;
	struct options       options;
	const char          *home;
	char                 login[NICKLEN], path0[128], path1[128];
	struct sigaction     act;
	struct pc_context    pctx;


	/* set locale and print banner */
	die_cb = NULL;
	srand((unsigned int)(time(NULL) ^ getpid()));
	setlocale(LC_ALL, "");
	fprintf(stderr, "%s, ver. %s\n\n", PACKAGE_NAME, PACKAGE_VERSION);

	/* make seren directory */
	home = getenv("HOME");
	if (home == NULL || home[0] == '\0' || strlen(home) > 100)
		die("$HOME is not defined, empty or too long", 1);
	strcpy(path0, home);
	strcat(path0, "/"SERENDIR);
	mkdir(path0, S_IRUSR|S_IWUSR|S_IXUSR /*| S_IRGRP|S_IWGRP|S_IXGRP*/);

	/* set default options */
	memset(&options, 0, sizeof(options));
	ret = getlogin_r(login, sizeof(login));
	strncpy(options.nick, ret == 0 ? login : "anonymous", NICKLEN-1);
	options.nick[NICKLEN-1]      = '\0';
#ifdef HAVE_LIBNCURSESW
	options.ncurses_theme        = 1;
#endif
	options.local_port           = 8110;
	options.bitrate              = 16000;
	options.complexity           = 10;
#ifdef DEFAULT_PULSE
	options.audiodevice_playback = strdup("pulse");
#else
	options.audiodevice_playback = strdup("hw:0,0");
#endif

	/* read options from conf file */
	strcpy(path0, home);
	strcat(path0, "/"SERENDIR"/"CONFFILE);
	parse_conf_file(path0, &options);

	/* parse command line options */
	while ((opt = getopt(argc, argv,
"hvL:"
#ifdef HAVE_LIBNCURSESW
"Nt:"
#endif
"n:p:b:C:d:D:c:aS"
	)) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
		case 'v':
			options.verbose++;
			break;
		case 'L':
			free(options.logfile);
			options.logfile = xmalloc(strlen(optarg)+1);
			strcpy(options.logfile, optarg);
			break;
#ifdef HAVE_LIBNCURSESW
		case 'N':
			options.disable_ncurses = 1;
			break;
		case 't':
			options.ncurses_theme = atoi(optarg);
			break;
#endif
		case 'n':
			strncpy(options.nick, optarg, NICKLEN-1);
			options.nick[NICKLEN-1] = '\0';
			break;
		case 'p':
			options.local_port = atoi(optarg);
			break;
		case 'b':
			options.bitrate = atoi(optarg);
			break;
		case 'C':
			options.complexity = atoi(optarg);
			break;
		case 'd':
			free(options.audiodevice_playback);
			options.audiodevice_playback = xmalloc(strlen(optarg)+1);
			strcpy(options.audiodevice_playback, optarg);
			break;
		case 'D':
			free(options.audiodevice_capture);
			options.audiodevice_capture = xmalloc(strlen(optarg)+1);
			strcpy(options.audiodevice_capture, optarg);
			break;
		case 'c':
			free(options.autocall_host);
			options.autocall_host = xmalloc(strlen(optarg)+1);
			strcpy(options.autocall_host, optarg);
			break;
		case 'a':
			options.autoaccept_calls = 1;
			break;
		case 'S':
			options.disable_stun = 1;
			break;
		default:
			fprintf(stderr, "\n");
			usage();
			exit(1);
		}
	}

#if 0
	fprintf(stderr, "verbose=%d logfile='%s'", options.verbose, options.logfile);
#ifdef HAVE_LIBNCURSESW
	fprintf(stderr, " disable_ncurses=%d ncurses_theme=%d", options.disable_ncurses, options.ncurses_theme);
#endif
	fprintf(stderr, " nick='%s' local_port=%d bitrate=%d complexity=%d audiodevice_playback='%s' audiodevice_capture='%s'"
	                " autocall_host='%s' autoaccept_calls=%d disable_stun=%d\n",
	        options.nick, options.local_port, options.bitrate, options.complexity, options.audiodevice_playback,
	        options.audiodevice_capture, options.autocall_host, options.autoaccept_calls, options.disable_stun);
#endif

	/* init msgbook */
	msgbook_init(&mb0);
	mb0.print_cb = msgbook_print_cb_stderr;

	/* open log file */
	strcpy(path0, home);
	strcat(path0, "/"SERENDIR"/"LOGFILE);
	fplog = fopen(options.logfile ? options.logfile : path0, "a");
	if (!fplog) {
		snprintf(msgbuf, MBS, "Cannot open log file '%s'", options.logfile ? options.logfile : path0);
		die(msgbuf, 1);
	}
	logstr(PACKAGE_STRING);

	/* init random module */
	ret = random_init();
	if (ret == -1)
		msgbook_enqueue(&mb0, MB_TYPE_WARNING, MODULE, "Could not open /dev/urandom, using rand()");

	/* init parole-conference engine */
	strcpy(path0, home);
	strcat(path0, "/"SERENDIR"/"FIFOIN);
	mkfifo(path0, S_IRUSR|S_IWUSR);

	strcpy(path1, home);
	strcat(path1, "/"SERENDIR"/"FIFOOUT);
	mkfifo(path1, S_IRUSR|S_IWUSR);

	ret = pc_engine_init(&pctx, options.nick, (uint16_t)options.local_port, options.bitrate,
	                     options.complexity, options.audiodevice_playback, options.audiodevice_capture,
	                     path0, path1, options.autoaccept_calls, pfds, &nfds, &options.verbose);
	if (ret == -1)
		die("pc_engine_init() failed", 1);

#ifdef HAVE_LIBNCURSESW
	/* init ncurses */
	memset(&nctx, 0, sizeof(nctx));
	if (!options.disable_ncurses) {
		strcpy(path0, home);
		strcat(path0, "/"SERENDIR"/"HISTFILE);
		ret = nc_init(PACKAGE_VERSION, pctx.nick, options.ncurses_theme, path0);
		if (ret == -1)
			die("nc_init() failed", 1);

		/* install signal handler for window resize */
		act.sa_handler = signal_handler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_RESTART;
		ret = sigaction(SIGWINCH, &act, NULL);
		if (ret == -1)
			die("sigaction() failed", 1);
		window_resized = 0;

		if (options.verbose) {
			snprintf(msgbuf, MBS, "ncurses interface started, loaded %d commands from history", nctx.historyfilled);
			msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, MODULE, msgbuf);
		}
	}
#endif
	if (
#ifdef HAVE_LIBNCURSESW
	options.disable_ncurses &&
#endif
	1) {
		/* set stdin unbuffered */
		ret = setvbuf(stdin, NULL, _IONBF, 0);
		if (ret)
			die("setvbuf() failed", 1);
	}

	/* install SIGINT signal handler */
	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	ret = sigaction(SIGINT, &act, NULL);
	if (ret == -1)
		die("sigaction() failed", 1);
	keep_going = 1;

	/* install SIGPIPE signal handler */
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	ret = sigaction(SIGPIPE, &act, NULL);
	if (ret == -1)
		die("sigaction() failed", 1);

	/* welcome messages */
	msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, "Welcome to Seren! Enter /h for help");
	snprintf(msgbuf, MBS, "Listening for incoming calls on udp port %hu...", pctx.local_port);
	msgbook_enqueue(&mb0, MB_TYPE_GUI, MODULE, msgbuf);

	/* get external ip address */
	if (!options.disable_stun) {
		char *ip = stun_get_external_ip(&options.verbose);
		if (ip)
			strcpy(pctx.external_ip, ip);
	}

	/* autocall host on startup if necessary */
	if (options.autocall_host) {
		char *command;

		command = xmalloc(3+strlen(options.autocall_host)+1);
		strcpy(command, "/c ");
		strcat(command, options.autocall_host);

		parse_and_execute_command(command, &pctx);
		free(command);
	}

	/* start engine */
	ret = pc_engine_start(&pctx);
	if (ret == -1)
		die("pc_engine_start() failed", 1);
	keep_going_capture = 1;


	/* main loop */
	while (keep_going || keep_going_capture) {
		/* poll: is stdin, audio_from_capture or udp_socket ready? */
		pollret = poll(pfds+skip_stdin, nfds-skip_stdin, -1);

		/* poll can return -1 when a signal arrives, errno will be EINTR */
		if (pollret == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				snprintf(msgbuf, MBS, "poll(): %s", strerror(errno));
				die(msgbuf, 1);
			}
		}
#if 0
		/* timeout (it should never happen as we specified -1 when calling poll) */
		if (pollret == 0) {
			logstr("poll timeout");
			continue;
		}
#endif
#ifdef HAVE_LIBNCURSESW
		/* window resize */
		if (!options.disable_ncurses && window_resized) {
			if (nc_resize(PACKAGE_VERSION, pctx.nick) == -1)
				die("nc_resize() failed", 1);

			window_resized = 0;
		}
#endif


		/** UDP SOCKET **/
		if (pfds[fd_idx_udpsocket].revents & POLLERR)
			die("udp socket POLLERR", 1);

		/* process data from socket if ready */
		if (pfds[fd_idx_udpsocket].revents & POLLIN) {
			/* read and process packet */
			ret = pc_engine_network_ready(&pctx);
			handle_events(&pctx);
			continue;
		}


		/** STDIN **/
		if (pfds[fd_idx_stdin].revents & POLLERR)
			die("stdin file descriptor POLLERR", 1);
		if (pfds[fd_idx_stdin].revents & POLLNVAL)
			die("stdin file descriptor POLLNVAL", 1);
		if (!(pfds[fd_idx_stdin].revents & POLLIN) && pfds[fd_idx_stdin].revents & POLLHUP) {
			skip_stdin = 1;
			pfds[fd_idx_stdin].events  = 0;
			pfds[fd_idx_stdin].revents = 0;
			if (options.verbose >= 2)
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "POLLHUP, will stop polling stdin");
		}

		if (
#ifdef HAVE_LIBNCURSESW
		options.disable_ncurses &&
#endif
		pfds[fd_idx_stdin].revents & POLLIN) {
			char linebuf[256], *pc;
			size_t len;

			pc = fgets(linebuf, 256, stdin);

			/* end of file */
			if (pc == NULL) {
				pfds[fd_idx_stdin].events = 0;
				if (options.verbose >= 2)
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "EOF, will stop polling stdin");
				continue;
			}

			len = strlen(linebuf);

			/* chat */
			if (len > 1 && linebuf[0] != '/') {
				/* delete trailing '\n' if necessary */
				if (linebuf[len-1] == '\n') {
					linebuf[len-1] = '\0';
					len--;
				}

				pc_engine_cmd_send_chat(&pctx, linebuf, len+1);
				handle_events(&pctx);
			}

			/* command */
			if (len > 1 && linebuf[0] == '/') {
				ret = parse_and_execute_command(linebuf, &pctx);
				if (ret == 1)
					keep_going = 0;

				handle_events(&pctx);
			}
		}

#ifdef HAVE_LIBNCURSESW
		if (!options.disable_ncurses && pfds[fd_idx_stdin].revents & POLLIN) {
			int ch;
			size_t len, nbytes;

			/* we are going to read one char at a time, skipping special keys, to fill a line */
			ch = wgetch(nctx.win_input);

			/* print read chars on -vvv */
			if (options.verbose >= 3) {
				snprintf(msgbuf, MBS, "key: %d|0%o|0x%x", ch, ch, ch);
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
			}

			switch (ch) {
			case ERR:
				/* this happens for example with ./seren < file at the end of file */
				pfds[fd_idx_stdin].events = 0;
				if (options.verbose >= 2)
					msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "getch() returned ERR, will stop polling stdin");
				continue;
			case 9: /* TAB, nick autocomplete */
				if (nctx.wlinepos && nctx.wlinebuf[nctx.wlinepos-1][0] != ' ' && nctx.wlinepos < LBM-NICKLEN-10) {
					size_t pos, partial_len, j;
					char partial[NICKLEN];
					unsigned int i;
					const char *nicks[MAX_NUMBER_OF_NODES+1];

					/* find start position of partial nick */
					pos = nctx.wlinepos-1;
					while (1) {
						if (nctx.wlinebuf[pos][0] == ' ') {
							pos++;
							break;
						}
						if (pos == 0 || nctx.wlinepos-pos >= NICKLEN-2)
							break;
						pos--;
					}
					partial_len = nctx.wlinepos-pos;

					/* copy partial nick */
					memset(partial, 0, sizeof(partial));
					for (j = pos; j < nctx.wlinepos; j++)
						partial[j-pos] = (char)nctx.wlinebuf[j][0];

					if (options.verbose >= 3) {
						snprintf(msgbuf, MBS, "autocomplete: wlinepos: %zd, pos: %zd, len: %zd, partial: %s", nctx.wlinepos, pos, partial_len, partial);
						msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
					}

					/* extract nick list */
					memset(nicks, 0, sizeof(nicks));
					nicks[0] = pctx.nick;
					for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
						if (pctx.nodes[i])
							nicks[i+1] = pctx.nodes[i]->nick;
					}

					/* find matching nick */
					for (i = 0; i < MAX_NUMBER_OF_NODES+1; i++) {
						if (nicks[i]) {
							size_t nick_len = strlen(nicks[i]);

							if (nick_len >= partial_len && strncmp(nicks[i], partial, partial_len) == 0) {
								char cc;

								if (options.verbose >= 3) {
									snprintf(msgbuf, MBS, "autocomplete: matching nick found: %s", nicks[i]);
									msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
								}
								/* insert remaining chars */
								for (j = partial_len; j < nick_len; j++) {
									cc = nicks[i][j];
									nc_scroll_input_text(pctx.nick, 1);
									nctx.wlinebuf[nctx.wlinepos++][0] = (unsigned char)cc;
									waddch(nctx.win_input, (chtype)cc);
								}
								/* insert ':' and/or space */
								if (pos == 0) {
									cc = ':';
									nc_scroll_input_text(pctx.nick, 1);
									nctx.wlinebuf[nctx.wlinepos++][0] = (unsigned char)cc;
									waddch(nctx.win_input, (chtype)cc);
								}
								cc = ' ';
								nc_scroll_input_text(pctx.nick, 1);
								nctx.wlinebuf[nctx.wlinepos++][0] = (unsigned char)cc;
								waddch(nctx.win_input, (chtype)cc);

								wrefresh(nctx.win_input);
								break;
							}
						}
					}
				}
				continue;
			case 27: /* ESC */
				continue;
			case KEY_DOWN:
				if (nctx.historymove < 0) {
					/* store current buffer to history */
					memcpy(nctx.history[nctx.historypos].wlinebuf, nctx.wlinebuf, sizeof(nctx.history[nctx.historypos].wlinebuf));
					nctx.history[nctx.historypos].wlinepos = nctx.wlinepos;

					/* select next history buffer */
					nctx.historypos = (nctx.historypos + 1) % HISTORYSIZE;
					nctx.historymove++;

					/* load buffer from history */
					memcpy(nctx.wlinebuf, nctx.history[nctx.historypos].wlinebuf, sizeof(nctx.wlinebuf));
					nctx.wlinepos = nctx.history[nctx.historypos].wlinepos;

					/* print buffer */
					nc_print_wlinebuf(pctx.nick);
				}
				continue;
			case KEY_UP:
				if (-HISTORYSIZE+1 < nctx.historymove && -nctx.historyfilled < nctx.historymove) {
					/* store current buffer to history */
					memcpy(nctx.history[nctx.historypos].wlinebuf, nctx.wlinebuf, sizeof(nctx.history[nctx.historypos].wlinebuf));
					nctx.history[nctx.historypos].wlinepos = nctx.wlinepos;

					/* select previous history buffer */
					nctx.historypos = (nctx.historypos - 1) < 0 ? HISTORYSIZE - 1 : nctx.historypos - 1;
					nctx.historymove--;

					/* load buffer from history */
					memcpy(nctx.wlinebuf, nctx.history[nctx.historypos].wlinebuf, sizeof(nctx.wlinebuf));
					nctx.wlinepos = nctx.history[nctx.historypos].wlinepos;

					/* print buffer */
					nc_print_wlinebuf(pctx.nick);
				}
				continue;
			case KEY_LEFT:
			case KEY_RIGHT:
			case KEY_HOME:
			case KEY_DC:
			case KEY_IC:
			case KEY_NPAGE:
			case KEY_PPAGE:
			case KEY_ENTER:
			case KEY_END:
			case KEY_RESIZE:
				continue;
			case 127: /* DEL */
			case KEY_BACKSPACE:
				if (nctx.wlinepos) {
					nctx.wlinepos--;

					/* delete one char either by scrolling text or by adding a space */
					if (!nc_scroll_input_text(pctx.nick, 0)) {
						int y, x;

						getyx(nctx.win_input, y, x);
						mvwaddch(nctx.win_input, y, x-1, ' ');
						wmove(nctx.win_input, y, x-1);
					}
					wrefresh(nctx.win_input);
				}
				continue;
			case KEY_F(4):
				pc_engine_cmd_print_info(&pctx);
				continue;
			case KEY_F(5):
				pc_engine_cmd_toggle_mute(&pctx);
				continue;
			case KEY_F(6):
				pc_engine_cmd_toggle_loopback(&pctx);
				continue;
			case KEY_F(7):
				pc_engine_cmd_accept_call(&pctx);
				continue;
			case KEY_F(8):
				pc_engine_cmd_refuse_call(&pctx);
				continue;
			default:
				break;
			}

			/* limit max characters read */
			if (ch != '\n' && nctx.wlinepos >= LBM) {
				pctx.tone.play = (pctx.tone.play > 10*ONE_OPUS_FRAME) ? pctx.tone.play : 10*ONE_OPUS_FRAME;
				continue;
			}

			/* scroll text if necessary */
			nc_scroll_input_text(pctx.nick, 1);

			/* insert char */
			nbytes = utf8_bytes_in_sequence((unsigned char)ch);
			nctx.wlinebuf[nctx.wlinepos][0] = (unsigned char)ch;
			waddch(nctx.win_input, (chtype)ch);
			if (nbytes == 1) {
				nctx.wlinepos++;
				wrefresh(nctx.win_input);
				if (ch != '\n')
					continue;
			} else {
				size_t i;

				for (i = 1; i < nbytes; i++) {
					ch = wgetch(nctx.win_input);
					/* print read chars on -vvv */
					if (options.verbose >= 3) {
						snprintf(msgbuf, MBS, "key: %u|0%o", ch, ch);
						msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
					}
					nctx.wlinebuf[nctx.wlinepos][i] = (unsigned char)ch;
					waddch(nctx.win_input, (chtype)ch);
				}
				nctx.wlinepos++;
				wrefresh(nctx.win_input);
				continue;
			}

			/* store current buffer to history */
			nctx.historypos = (nctx.historypos - nctx.historymove) % HISTORYSIZE;
			memcpy(nctx.history[nctx.historypos].wlinebuf, nctx.wlinebuf, sizeof(nctx.history[nctx.historypos].wlinebuf));
			nctx.history[nctx.historypos].wlinepos = nctx.wlinepos - 1; /* discard '\n' */
			nctx.historypos = (nctx.historypos + 1) % HISTORYSIZE;
			nctx.historymove = 0;
			nctx.historyfilled = (nctx.historyfilled + 1) > HISTORYSIZE ? HISTORYSIZE : (nctx.historyfilled + 1);

			/* we have a trailing '\n', now insert '\0' */
			nctx.wlinebuf[nctx.wlinepos++][0] = '\0';
			nc_update_linebuf();
			nc_clear_input_line_and_print_prompt(pctx.nick, 1);

			len = strlen(nctx.linebuf);

			/* chat */
			if (len > 1 && nctx.linebuf[0] != '/') {
				/* delete trailing '\n' */
				nctx.linebuf[len-1] = '\0';
				len--;

				pc_engine_cmd_send_chat(&pctx, nctx.linebuf, len+1);
				handle_events(&pctx);
			}

			/* command */
			if (len > 1 && nctx.linebuf[0] == '/') {
				ret = parse_and_execute_command(nctx.linebuf, &pctx);
				if (ret == 1)
					keep_going = 0;

				handle_events(&pctx);
			}
		}
#endif


		/** AUDIO CAPTURE **/
		pc_engine_fix_revents(&pctx, pfds);

		if (pfds[fd_idx_audiocapture].revents & POLLERR) {
			if (!(pfds[fd_idx_audiocapture].revents & POLLIN))
				die("Audio Capture POLLERR", 1);
		}

		/* process captured audio if ready */
		if (pfds[fd_idx_audiocapture].revents & POLLIN && keep_going_capture) {

			pc_engine_step(&pctx);
			pc_engine_audio_ready(&pctx);
			handle_events(&pctx);

			/* time to exit? */
			if (keep_going == 0) {
				keep_going_capture = 0;
				pc_engine_goodbye(&pctx);
			}

			/* periodic info refresh */
			if (pctx.ic_total % 10 == 0) {
				unsigned int i;

#ifdef HAVE_LIBNCURSESW
				/* ncurses status and lateral bar */
				if (!options.disable_ncurses) {
					char                timer_str[16];
					char                stat_str[48];
					struct nc_node_info ni[MAX_NUMBER_OF_NODES+1];

					snprintf(timer_str, 16, "%02u:%02u:%02u", (pctx.ic_talk+pctx.ic_mute)/180000,
						     ((pctx.ic_talk+pctx.ic_mute)/3000)%60, ((pctx.ic_talk+pctx.ic_mute)/50)%60);

					snprintf(stat_str, 48, "%4.1fkB/s↑  %4.1fkB/s↓   pl[%4.2f%%] ",
						     pctx.bw_upload, pctx.bw_download, pctx.packet_loss_g);

					memset(ni, 0, sizeof(ni));
					ni[0].nick        = pctx.nick;
					ni[0].algo        = pctx.algo;
					ni[0].nb_frames   = pctx.micmute ? 0 : 1;
					ni[0].bandwidth   = (unsigned int)pctx.bandwidth_hz;
					ni[0].nb_channels = channels;
					ni[0].dBSPL       = pctx.dBSPL;
					for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
						if (pctx.nodes[i]) {
							ni[i+1].nick        = pctx.nodes[i]->nick;
							ni[i+1].algo        = pctx.nodes[i]->algo;
							ni[i+1].nb_frames   = pctx.nodes[i]->nb_frames;
							ni[i+1].bandwidth   = (unsigned int)pctx.nodes[i]->bandwidth_hz;
							ni[i+1].nb_channels = (unsigned int)pctx.nodes[i]->nb_channels;
							ni[i+1].pl10k       = (unsigned int)(10000.0f * pctx.nodes[i]->packet_loss);
							ni[i+1].tm_pl10k    = pctx.nodes[i]->tm_pl10k;
							ni[i+1].rtt_us      = pctx.nodes[i]->rtt_us;
							ni[i+1].dBSPL       = pctx.nodes[i]->dBSPL;
						}
					}

					nc_status(pctx.micmute, pctx.record, pctx.mode, pctx.peak_percent, pctx.dBSPL,
					          timer_str, stat_str);

					nc_nodelist(MAX_NUMBER_OF_NODES+1, pctx.mode, ni);
				}
#endif

				/* reset sos and peak counters */
				for (i = 0; i < MAX_NUMBER_OF_NODES; i++) {
					if (pctx.nodes[i]) {
						pctx.nodes[i]->sos   = 0;
						pctx.nodes[i]->sos_N = 0;
					}
				}
				pctx.sos   = 0;
				pctx.sos_N = 0;
				pctx.peak_percent = 0.0f;
			}
		}
	}

	/* check if we still have stuff on the socket */
	while ((pollret = poll(pfds+fd_idx_udpsocket, 1, 250)) > 0) {
		struct udp_packet udp_packet;
		if (pfds[fd_idx_udpsocket].revents & POLLIN)
			udp_receive_packet(pctx.sockfd, &udp_packet);
	}

	/* clean up */
	pc_engine_cleanup(&pctx);
	handle_events(&pctx);
	free(options.logfile);
	free(options.audiodevice_playback);
	free(options.audiodevice_capture);
	free(options.autocall_host);
	random_close();

	/* exit */
#ifdef HAVE_LIBNCURSESW
	if (options.disable_ncurses)
		msgbook_flush(&mb0, 0);
	else
		nc_close();
#else
	msgbook_flush(&mb0, 0);
#endif

	return 0;
}

#undef MODULE
