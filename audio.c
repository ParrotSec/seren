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
#include <errno.h>
#include "audio.h"
#include "common.h"
#include "msgbook.h"

#define MODULE "alsa"

int audio_init(struct audio_data *ad, const char *device, snd_pcm_stream_t streamtype,
				unsigned int rate, unsigned int channels, struct pollfd *pfds, const int *verbose)
{
	int err, dir;

	ad->device          = device;
	ad->stream          = streamtype;
	ad->access          = SND_PCM_ACCESS_RW_INTERLEAVED;
	ad->format          = SND_PCM_FORMAT_S16_LE;
	ad->pcm_handle      = NULL;
	ad->hw_params       = NULL;
	ad->rate            = rate;
	ad->channels        = channels;
	ad->periods         = 10;
/*	ad->period_size     = */
	ad->period_time     = 20000;
/*	ad->buffer_size     = */
/*	ad->buffer_time     = */
	ad->sw_params       = NULL;
/*	ad->avail_min       = period_size; */
/*	ad->start_threshold = */
/*	ad->stop_threshold  = */
	ad->pfds            = pfds;
	ad->nfds            = 0;
	ad->alsabuffer      = NULL;
	ad->alsabuffersize  = 0;
	ad->frames          = 0;
	ad->avail           = 0;
	ad->peak_percent    = 0.0f;
	ad->verbose         = verbose;

	/* open pcm device */
	if (*ad->verbose) {
		snprintf(msgbuf, MBS, "Opening pcm audio device '%s' for %s...",
		         ad->device, ad->stream == SND_PCM_STREAM_CAPTURE ? "capture" : "playback");
		msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, MODULE, msgbuf);
	}
	if ((err = snd_pcm_open(&ad->pcm_handle, ad->device, ad->stream, 0)) < 0) {
		snprintf(msgbuf, MBS, "Cannot open audio device '%s' (%s)", ad->device, snd_strerror(err));
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return -1;
	}

	/* allocate and initialize hardware parameters structure */
	if (*ad->verbose >= 2)
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Allocating structure for hardware parameters...");
	if ((err = snd_pcm_hw_params_malloc(&ad->hw_params)) < 0) {
		snprintf(msgbuf, MBS, "Cannot allocate hardware parameter structure (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_any(ad->pcm_handle, ad->hw_params)) < 0) {
		snprintf(msgbuf, MBS, "Cannot initialize hardware parameter structure (%s)", snd_strerror(err));
		goto fail;
	}
	/* set hardware parameters */
	if (*ad->verbose)
		msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, MODULE, "Setting hardware parameters...");
	if ((err = snd_pcm_hw_params_set_access(ad->pcm_handle, ad->hw_params, ad->access)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set access type (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_set_format(ad->pcm_handle, ad->hw_params, ad->format)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set sample format (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_set_rate(ad->pcm_handle, ad->hw_params, ad->rate, 0)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set sample rate (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_set_channels(ad->pcm_handle, ad->hw_params, ad->channels)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set channel count (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_set_period_time(ad->pcm_handle, ad->hw_params, ad->period_time, 0)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set period time (%s)", snd_strerror(err));
		goto fail;
	}
#if 1
	if ((err = snd_pcm_hw_params_set_periods(ad->pcm_handle, ad->hw_params, ad->periods, 0)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set periods (%s)", snd_strerror(err));
		goto fail;
	}
#endif
	/* apply hardware parameters to pcm device and prepare device */
	if (*ad->verbose >= 2)
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Applying hardware parameters...");
	if ((err = snd_pcm_hw_params(ad->pcm_handle, ad->hw_params)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set parameters (%s)", snd_strerror(err));
		goto fail;
	}
#if 0
	if ((err = snd_pcm_prepare(ad->pcm_handle)) < 0) {
		snprintf(msgbuf, MBS, "Cannot prepare audio interface for use (%s)", snd_strerror(err));
		goto fail;
	}
#endif
	/* read hardware parameters */
	if (*ad->verbose >= 2)
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Reading hardware parameters...");
	if ((err = snd_pcm_hw_params_get_rate(ad->hw_params, &ad->rate, &dir)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get rate (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_get_channels(ad->hw_params, &ad->channels)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get channel count (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_get_periods(ad->hw_params, &ad->periods, &dir)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get periods (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_get_period_size(ad->hw_params, &ad->period_size, &dir)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get period size (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_get_period_time(ad->hw_params, &ad->period_time, &dir)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get period time (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_get_buffer_size(ad->hw_params, &ad->buffer_size)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get buffer size (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_hw_params_get_buffer_time(ad->hw_params, &ad->buffer_time, &dir)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get buffer time (%s)", snd_strerror(err));
		goto fail;
	}
	/* print hardware parameters */
	if (*ad->verbose >= 2) {
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Hardware parameters chosen:");
		snprintf(msgbuf, MBS, "  rate        = %u", ad->rate);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		snprintf(msgbuf, MBS, "  channels    = %u", ad->channels);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		snprintf(msgbuf, MBS, "  periods     = %u", ad->periods);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		snprintf(msgbuf, MBS, "  period_size = %lu", ad->period_size);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		snprintf(msgbuf, MBS, "  period_time = %u us", ad->period_time);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		snprintf(msgbuf, MBS, "  buffer_size = %lu", ad->buffer_size);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		snprintf(msgbuf, MBS, "  buffer_time = %u us", ad->buffer_time);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
	}
	/* free hardware parameters */
	snd_pcm_hw_params_free(ad->hw_params);



	/* allocate and initialize software parameters structure */
	if (*ad->verbose >= 2)
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Allocating structure for software parameters...");
	if ((err = snd_pcm_sw_params_malloc(&ad->sw_params)) < 0) {
		snprintf(msgbuf, MBS, "Cannot allocate software parameter structure (%s)", snd_strerror(err));
		goto fail;
	}
	/* read software parameters */
	if (*ad->verbose >= 2)
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Getting current software parameters...");
	if ((err = snd_pcm_sw_params_current(ad->pcm_handle, ad->sw_params)) < 0) {
		snprintf(msgbuf, MBS, "Cannot initialize software parameters structure (%s)", snd_strerror(err));
		goto fail;
	}
	/* set software parameters */
	if (*ad->verbose)
		msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, MODULE, "Setting software parameters...");
#if 1
	/* playback: if the samples in ring buffer are >= start_threshold, and the stream is not running,
	             it will be started
	   capture:  if we try to read a number of frames >= start_threshold, then the stream will be started */
	ad->start_threshold = 2*ad->period_size;
	if ((err = snd_pcm_sw_params_set_start_threshold(ad->pcm_handle, ad->sw_params, ad->start_threshold)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set start threshold (%s)", snd_strerror(err));
		goto fail;
	}
#endif
#if 0
	/* playback: if the available (empty) samples in ring buffer are >= stop_threshold, then the stream
	             will be stopped. stop_threshold can be > buffer_size to delay underrun
	   capture:  if the available (filled) samples in ring buffer are >= stop_threshold, then the stream
	             will be stopped. stop_threshold can be > buffer_size to delay overrun */
	ad->stop_threshold = ad->buffer_size;
	if ((err = snd_pcm_sw_params_set_stop_threshold(ad->pcm_handle, ad->sw_params, ad->stop_threshold)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set stop threshold (%s)", snd_strerror(err));
		goto fail;
	}
#endif
#if 0
	ad->avail_min = ad->period_size;
	if ((err = snd_pcm_sw_params_set_avail_min(ad->pcm_handle, ad->sw_params, ad->avail_min)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set minimum available count (%s)", snd_strerror(err));
		goto fail;
	}
#endif
	/* apply software parameters */
	if (*ad->verbose >= 2)
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Applying software parameters...");
	if ((err = snd_pcm_sw_params(ad->pcm_handle, ad->sw_params)) < 0) {
		snprintf(msgbuf, MBS, "Cannot set software parameters (%s)", snd_strerror(err));
		goto fail;
	}
	/* read software parameters */
	if (*ad->verbose >= 2)
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Reading software parameters...");
	if ((err = snd_pcm_sw_params_current(ad->pcm_handle, ad->sw_params)) < 0) {
		snprintf(msgbuf, MBS, "Cannot initialize software parameters structure (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_sw_params_get_avail_min(ad->sw_params, &ad->avail_min)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get minimum available count (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_sw_params_get_start_threshold(ad->sw_params, &ad->start_threshold)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get start threshold (%s)", snd_strerror(err));
		goto fail;
	}
	if ((err = snd_pcm_sw_params_get_stop_threshold(ad->sw_params, &ad->stop_threshold)) < 0) {
		snprintf(msgbuf, MBS, "Cannot get stop threshold (%s)", snd_strerror(err));
		goto fail;
	}
	/* print software parameters */
	if (*ad->verbose >= 2) {
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, "Software parameters chosen:");
		snprintf(msgbuf, MBS, "  avail_min       = %lu", ad->avail_min);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		snprintf(msgbuf, MBS, "  start_threshold = %lu", ad->start_threshold);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
		snprintf(msgbuf, MBS, "  stop_threshold  = %lu", ad->stop_threshold);
		msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
	}
	/* free software parameters */
	snd_pcm_sw_params_free(ad->sw_params);



	/* poll */
	if (ad->pfds) {
		ad->nfds = (unsigned int)snd_pcm_poll_descriptors_count(ad->pcm_handle);
		err = snd_pcm_poll_descriptors(ad->pcm_handle, ad->pfds, ad->nfds);
		if (*ad->verbose >= 2) {
			unsigned int i;
			snprintf(msgbuf, MBS, "Poll descriptors = %u", ad->nfds);
			msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
			for (i = 0; i < ad->nfds; i++) {
				snprintf(msgbuf, MBS, "  %d: fd = %d,%s%s", i, ad->pfds[i].fd,
				         ad->pfds[i].events & POLLIN  ? " POLLIN"  : "",
				         ad->pfds[i].events & POLLOUT ? " POLLOUT" : "");
				msgbook_enqueue(&mb0, MB_TYPE_DEBUG, MODULE, msgbuf);
			}
		}
	}

	/* prepare alsa buffer */
	ad->alsabuffersize = ad->period_size;
	ad->alsabuffer     = xcalloc(ad->channels * sizeof(*ad->alsabuffer), ad->alsabuffersize);

	return 0;

fail:
	msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
	snd_pcm_close(ad->pcm_handle);
	free(ad->alsabuffer);
	return -1;
}

int audio_start(struct audio_data *ad)
{
	int err;

	if (*ad->verbose)
		msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, MODULE, "Starting pcm audio device...");

	if ((err = snd_pcm_start(ad->pcm_handle)) < 0) {
		snprintf(msgbuf, MBS, "Cannot start pcm stream (%s)", snd_strerror(err));
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return -1;
	}

	return 0;
}

int audio_stop(struct audio_data *ad)
{
	int err;

	if (*ad->verbose)
		msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, MODULE, "Stopping pcm audio device...");

	if ((err = snd_pcm_drop(ad->pcm_handle)) < 0) {
		snprintf(msgbuf, MBS, "Cannot stop pcm stream (%s)", snd_strerror(err));
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return -1;
	}

	return 0;
}

void audio_poll_descriptors_revents(struct audio_data *ad)
{
	snd_pcm_poll_descriptors_revents(ad->pcm_handle, ad->pfds, ad->nfds, &ad->revents);
}

snd_pcm_sframes_t audio_avail(struct audio_data *ad, int silent)
{
	if ((ad->avail = snd_pcm_avail(ad->pcm_handle)) < 0) {
		if (*ad->verbose || !silent) {
			snprintf(msgbuf, MBS, "Cannot get pcm avail (%s)", snd_strerror((int)ad->avail));
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		}
	}

	return ad->avail;
}

snd_pcm_sframes_t audio_read(struct audio_data *ad, int silent)
{
	if ((ad->frames = snd_pcm_readi(ad->pcm_handle, ad->alsabuffer, ad->alsabuffersize)) < 0) {
		if (*ad->verbose || !silent) {
			snprintf(msgbuf, MBS, "Cannot read from pcm (%s)", snd_strerror((int)ad->frames));
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		}
	}

	return ad->frames;
}

snd_pcm_sframes_t audio_write(struct audio_data *ad, int16_t *buffer, snd_pcm_uframes_t buffersize, int silent)
{
	if ((ad->frames = snd_pcm_writei(ad->pcm_handle, buffer, buffersize)) < 0) {
		if (*ad->verbose || !silent) {
			snprintf(msgbuf, MBS, "Cannot write to pcm (%s)", snd_strerror((int)ad->frames));
			msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		}
	}

	return ad->frames;
}

int audio_recover(struct audio_data *ad, int err, int silent)
{
	return snd_pcm_recover(ad->pcm_handle, err, silent);
}

void audio_find_peak(struct audio_data *ad)
{
	unsigned int s;
	int v, peak = 0;

	for (s = 0; s < (unsigned int)ad->frames * ad->channels; s++) {
		v = abs(ad->alsabuffer[s]);
		if (v > peak)
			peak = v;
	}

	ad->peak_percent = 100.0f * (float)peak / (float)(INT16_MAX+1);
}

int audio_close(struct audio_data *ad)
{
	int err;

	if (*ad->verbose)
		msgbook_enqueue(&mb0, MB_TYPE_VERBOSE, MODULE, "Closing audio device...");

	if ((err = snd_pcm_close(ad->pcm_handle)) < 0) {
		snprintf(msgbuf, MBS, "Cannot close pcm stream (%s)", snd_strerror(err));
		msgbook_enqueue(&mb0, MB_TYPE_ERROR, MODULE, msgbuf);
		return -1;
	}

	free(ad->alsabuffer);

	return 0;
}

#undef MODULE
