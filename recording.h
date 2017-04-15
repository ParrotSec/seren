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

#ifndef RECORDING_H
#define RECORDING_H

#include <stdio.h>
#include <stdint.h>
#include <opus/opus.h>
#include <ogg/ogg.h>

/* wave recording */
FILE *wave_start_recording(const char *filename, unsigned int samplerate, unsigned int channels);
void wave_write_data(const int16_t *pcm, unsigned int channels, unsigned int frames,
                     uint32_t *bytes_written, FILE *fp);
void wave_stop_recording(uint32_t bytes_written, FILE *fp);

/* ogg/opus recording */
FILE *oggopus_start_recording(const char *filename, unsigned int samplerate, unsigned int channels,
                              OpusEncoder **enc, ogg_stream_state *oss);
void oggopus_write_data(const int16_t *pcm, unsigned int frames, OpusEncoder *enc,
                        ogg_stream_state *oss, int64_t *packetno, int eos, FILE *fp);
void oggopus_stop_recording(OpusEncoder **enc, ogg_stream_state *oss, FILE *fp);

#endif
