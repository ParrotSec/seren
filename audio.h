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

#ifndef AUDIO_H
#define AUDIO_H

#include <alsa/asoundlib.h>
#include <poll.h>
#include <stdint.h>

struct audio_data {
	const char          *device;
	snd_pcm_stream_t     stream;
	snd_pcm_access_t     access;
	snd_pcm_format_t     format;
	snd_pcm_t           *pcm_handle;

	/* hw params */
	snd_pcm_hw_params_t *hw_params;
	unsigned int         rate;
	unsigned int         channels;
	unsigned int         periods;
	snd_pcm_uframes_t    period_size;
	unsigned int         period_time;
	snd_pcm_uframes_t    buffer_size;
	unsigned int         buffer_time;

	/* sw params */
	snd_pcm_sw_params_t *sw_params;
	snd_pcm_uframes_t    avail_min;
	snd_pcm_uframes_t    start_threshold;
	snd_pcm_uframes_t    stop_threshold;

	struct pollfd       *pfds;
	unsigned int         nfds;
	unsigned short       revents;

	/* buffer */
	int16_t             *alsabuffer;
	snd_pcm_uframes_t    alsabuffersize;
	snd_pcm_sframes_t    frames;
	snd_pcm_sframes_t    avail;
	float                peak_percent;

	const int           *verbose;
};

int  audio_init(struct audio_data *ad, const char *device, snd_pcm_stream_t streamtype,
				unsigned int rate, unsigned int channels, struct pollfd *pfds, const int *verbose);
int  audio_start(struct audio_data *ad);
int  audio_stop(struct audio_data *ad);
void audio_poll_descriptors_revents(struct audio_data *ad);
snd_pcm_sframes_t audio_avail(struct audio_data *ad, int silent);
snd_pcm_sframes_t audio_read(struct audio_data *ad, int silent);
snd_pcm_sframes_t audio_write(struct audio_data *ad, int16_t *buffer, snd_pcm_uframes_t buffersize, int silent);
int  audio_recover(struct audio_data *ad, int err, int silent);
void audio_find_peak(struct audio_data *ad);
int  audio_close(struct audio_data *ad);

#endif
