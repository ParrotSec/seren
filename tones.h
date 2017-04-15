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

#ifndef TONES_H
#define TONES_H

#include <stdint.h>

struct pc_tone {
	int16_t             *pcm;
	unsigned int         pcmlen; /* in frames */
	unsigned int         pos;    /* in frames */
	unsigned int         play;   /* in frames */
	int                  enable;
};

struct pc_calltone {
	int16_t             *pcm;
	unsigned int         pcmlen; /* in frames */
	unsigned int         pos;    /* in frames */
};

struct pc_ringtone {
	int16_t             *pcm;
	unsigned int         pcmlen; /* in frames */
	unsigned int         pos;    /* in frames */
	int                  enable;
};

void tones_generate_tone(struct pc_tone *tone, unsigned int samplerate, unsigned int channels, unsigned int one_frame);
void tones_generate_calltone(struct pc_calltone *calltone, unsigned int samplerate, unsigned int channels, unsigned int one_frame);
void tones_generate_ringtone(struct pc_ringtone *ringtone, unsigned int song_index,
                             unsigned int samplerate, unsigned int channels, unsigned int one_frame);

#endif
