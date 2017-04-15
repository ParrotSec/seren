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

#ifndef PC_ENGINE_H
#define PC_ENGINE_H

#include <stdio.h>
#include <stdint.h>
#include <poll.h>
#include <netinet/in.h>
#include <opus/opus.h>
#include <ogg/ogg.h>
#include "udp.h"
#include "audio.h"
#include "tones.h"
#include "slist.h"
#include "dhm.h"

extern const unsigned int samplerate;
extern const unsigned int channels;

/* engine version */
#define PC_ENGINE_VERSION_BYTES    3
#define PC_ENGINE_VERSION_MAJOR    0
#define PC_ENGINE_VERSION_MINOR    3
#define PC_ENGINE_VERSION_SUBMINOR 0
#define PC_ENGINE_VERSION_INT      ((PC_ENGINE_VERSION_MAJOR<<16)+(PC_ENGINE_VERSION_MINOR<<8)+PC_ENGINE_VERSION_SUBMINOR)

/* maximum length of nickname */
#define NICKLEN             16

/* maximum number of nodes of the network (excluding our node) */
#define MAX_NUMBER_OF_NODES 9

/* node timeout (in units of 20ms): if we don't receive packets from a node
 * for more than TIMEOUT/50 seconds, then that node will be deleted.
 */
#define TIMEOUT             300

/* one opus audio frame is 20ms at 48kHz. Note that 960 are alsa frames,
 * and need to be multiplied by channels to get the number of samples.
 */
#define ONE_OPUS_FRAME      960


/* events created by the engine */
enum pc_event_type {
	event_type_mute,
	event_type_loopback,
	event_type_tones,
	event_type_ringtone,
	event_type_autoaccept_calls,
	event_type_fifo,
	event_type_recording,
	event_type_micgain,
	event_type_bitrate,
	event_type_mode,
	event_type_setalgo,
	event_type_setpsk,
	event_type_nodegain,
	event_type_node_delete,
	event_type_node_add,
	event_type_chat,
	event_type_calling_in_progress,
	event_type_calling_aborted,
	event_type_incoming_call,
	event_type_incoming_call_lost,
	event_type_chose_refused,
	event_type_chose_accepted,
	event_type_call_refused,
	event_type_call_accepted,
	event_type_call_hangup,
	event_type_verbose
};

struct pc_event {
	enum pc_event_type type;
	struct sockaddr_in addr;
	char               nick[NICKLEN];
	int                i;
	float              f;
	void              *data;
};

/* mode of operation */
enum pc_mode {
	mode_clear,   /* all traffic is sent in clear */
	mode_secure,  /* encrypted traffic, using DHM key exchange and a different key for each link */
	mode_psk      /* encrypted traffic, using a pre-shared key */
};

enum pc_algo {
	algo_xtea,
	algo_cast128,
	algo_blowfish,
	algo_camellia,
	algo_twofish
};

extern const char * const pc_algo_name[];

/* send recipe: send a packet every resend_interval, at most resend_maxnum times */
struct pc_sendrecipe {
	struct sockaddr_in addr;
	struct udp_packet  udp_packet;
	int                resend_interval; /* in unit of 20ms */
	int                resend_maxnum;
	int                resend_watchdog; /* decrement each cycle, resend when <=0 and set this to resend_interval */
	int                packets_sent;    /* stop when this is >= resend_maxnum */
};

struct pc_caller {
	struct sockaddr_in addr;
	char               nick[NICKLEN];
	enum dhm_pgid      pgid;
	enum pc_algo       algo;
	size_t             pklen;
	uint8_t            pk[DHM_MAX_LEN];
	int                timeout;
};

struct pc_pcmframe {
	opus_int16         pcm[2*ONE_OPUS_FRAME];
	unsigned int       pcmlen; /* in frames */
};

struct pc_node {
	struct sockaddr_in addr;
	char               nick[NICKLEN];

	int                status;
	int                timeout;
	uint32_t           sequence_number;
	uint32_t           last_sequence_number;
	uint32_t           packets_received;
	uint32_t           packets_lost;
	float              packet_loss;

	/* opus decoder */
	OpusDecoder       *dec;
	opus_int32         gain_Q8_dB;
	opus_int32         bandwidth_hz;
	opus_int32         nb_channels;

	/* list of pcm opus frames, 20ms each (struct pc_pcmframe) */
	struct slist      *pcmframes;
	unsigned int       nb_frames;

	/* secure mode */
	enum dhm_pgid      pgid;
	enum pc_algo       algo;
	struct dhm_ctx     dhm;
	void              *cipher_ctx;

	/* dbSPL vu-meter */
	uint64_t           sos;   /* sum of squares */
	uint32_t           sos_N;
	double             dBSPL; /* range= -90..0 */

	/* telemetry */
	uint32_t           tm_pl10k;

	/* rtt */
	double             rtt_us;
};

struct pc_context {
	/* my nickname */
	char                 nick[NICKLEN];

	/* external ip */
	char                 external_ip[16];

	/* udp socket */
	int                  sockfd;
	uint16_t             local_port;

	/* options */
	int                  autoaccept_calls;
	int                 *verbose;
	int                  telemetry;
	int                  rtt;

	/* audio data */
	struct audio_data    ad_capture, ad_playback;
	const char          *audiodevice_playback;
	const char          *audiodevice_capture;
	uint32_t             ic_total; /* total capture frame counter */
	uint32_t             ic_talk;  /*  talk capture frame counter */
	uint32_t             ic_mute;  /*  mute capture frame counter */
	float                micgain_dB, peak_percent;
	int                  overruns, underruns, micmute;

	/* audio fifos */
	int                  fifo;
	char                 fifoin[128];
	int                  fifoinfd;
	char                 fifoout[128];
	int                  fifooutfd;

	/* audio loopback */
	int                  lb;
	opus_int16           lb_pcm[2*ONE_OPUS_FRAME];
	unsigned int         lb_pcmlen; /* in frames */

	/* dbSPL vu-meter */
	uint64_t             sos;   /* sum of squares */
	uint32_t             sos_N;
	double               dBSPL; /* range= -90..0 */

	/* opus encoder */
	OpusEncoder         *enc;
	opus_int32           bitrate, complexity, bandwidth, bandwidth_hz;

	/* recording */
	int                  record;
	char                 record_filename[64];
	FILE                *record_fp;
	uint32_t             record_bytes_written;
	opus_int16           record_pcm[2*ONE_OPUS_FRAME];
	OpusEncoder         *record_enc;
	ogg_stream_state     record_oss;
	int64_t              record_packetno;

	/* decoded pcm data */
	opus_int16           pcm[2*ONE_OPUS_FRAME];
	unsigned int         pcmlen; /* in frames */

	/* encryption */
	enum pc_mode         mode;
	enum pc_algo         algo;
	void                *cipher_ctx;
	size_t               psklen;         /* in bits         */
	uint8_t              psk[48];        /* max 384-bit     */
	enum dhm_pgid        preferred_pgid; /* for mode_secure */

	/* array of nodes */
	struct pc_node      *nodes[MAX_NUMBER_OF_NODES];

	/* list of events (struct pc_event) */
	struct slist        *events;
#if 0
	/* list of packets to send periodically (struct pc_sendrecipe) */
	struct slist        *sendrecipes;
#endif
	/* outstanding call */
	struct pc_sendrecipe *call;

	/* list of callers (struct pc_caller) */
	struct slist        *callers;

	/* tone */
	struct pc_tone       tone;

	/* calltone */
	struct pc_calltone   calltone;

	/* ringtone */
	struct pc_ringtone   ringtone;

	/* stats */
	uint32_t             packets_received_g;
	uint32_t             packets_lost_g;
	float                packet_loss_g;
	size_t               bytes_out_per_sec;
	size_t               bytes_in_per_sec;
	float                bw_upload;
	float                bw_download;
};

/* recording format */
#define REC_OFF  0
#define REC_WAVE 1
#define REC_OPUS 2

/* reasons for deleting a node */
#define DELETE_REASON_LEFT    0
#define DELETE_REASON_TIMEOUT 1

/* reasons for refusing a call */
#define REFUSE_REASON_USER    0
#define REFUSE_REASON_VERSION 1
#define REFUSE_REASON_FULL    2

/* pc_engine_network_ready() return values */
#define RES_ERROR       -1
#define RES_OK           0
#define RES_REFUSED      1

extern unsigned int fd_idx_stdin;
extern unsigned int fd_idx_udpsocket;
extern unsigned int fd_idx_audiocapture;
extern unsigned int fd_idx_audioplayback;

const char *pc_engine_version_string(void);

int  pc_engine_init(struct pc_context *pctx, const char *nick, uint16_t local_port, int bitrate, int complexity,
                    const char *audiodevice_playback, const char *audiodevice_capture, const char *fifoin,
                    const char *fifoout, int autoaccept_calls, struct pollfd *pfds, unsigned int *nfds, int *verbose);
int  pc_engine_start(struct pc_context *pctx);
void pc_engine_fix_revents(struct pc_context *pctx, struct pollfd *pfds);
int  pc_engine_network_ready(struct pc_context *pctx);
void pc_engine_step(struct pc_context *pctx);
void pc_engine_audio_ready(struct pc_context *pctx);
void pc_engine_goodbye(struct pc_context *pctx);
void pc_engine_cleanup(struct pc_context *pctx);

void pc_engine_cmd_print_info(struct pc_context *pctx);
void pc_engine_cmd_toggle_mute(struct pc_context *pctx);
void pc_engine_cmd_toggle_loopback(struct pc_context *pctx);
void pc_engine_cmd_toggle_tones(struct pc_context *pctx);
void pc_engine_cmd_toggle_ringtone(struct pc_context *pctx);
void pc_engine_cmd_toggle_autoaccept_calls(struct pc_context *pctx);
void pc_engine_cmd_toggle_fifo(struct pc_context *pctx);
void pc_engine_cmd_stop_recording(struct pc_context *pctx);
int  pc_engine_cmd_toggle_recording(struct pc_context *pctx, int rec_format);
int  pc_engine_cmd_set_micgain(struct pc_context *pctx, float gain_dB);
int  pc_engine_cmd_set_bitrate(struct pc_context *pctx, int bitrate);
int  pc_engine_cmd_set_mode(struct pc_context *pctx, int mode);
int  pc_engine_cmd_set_algo(struct pc_context *pctx, int algo);
void pc_engine_cmd_set_psk(struct pc_context *pctx, const unsigned char *hexkey, size_t len);
int  pc_engine_cmd_set_nodegain(struct pc_context *pctx, int idx, float gain_dB);
int  pc_engine_cmd_kill_node(struct pc_context *pctx, int idx);
int  pc_engine_cmd_call_node(struct pc_context *pctx, const char *host, uint16_t port);
void pc_engine_cmd_abort_calling(struct pc_context *pctx);
void pc_engine_cmd_hangup(struct pc_context *pctx);
void pc_engine_cmd_send_chat(struct pc_context *pctx, const char *buf, size_t len);
void pc_engine_cmd_accept_call(struct pc_context *pctx);
void pc_engine_cmd_refuse_call(struct pc_context *pctx);
int  pc_engine_cmd_set_verbose(struct pc_context *pctx, int verbose);

#endif
