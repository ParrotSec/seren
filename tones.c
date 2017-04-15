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

#include <stddef.h>
#include <math.h>
#include "tones.h"
#include "common.h"

/* Note frequencies: http://cs.nyu.edu/courses/fall03/V22.0201-003/notes.htm */

#define NOTE_C3  130.81f
#define NOTE_C3d 138.59f
#define NOTE_D3  146.83f
#define NOTE_D3d 155.56f
#define NOTE_E3  164.81f
#define NOTE_F3  174.61f
#define NOTE_F3d 185.00f
#define NOTE_G3  196.00f
#define NOTE_G3d 207.65f
#define NOTE_A3  220.00f
#define NOTE_A3d 233.08f
#define NOTE_B3  246.94f

#define NOTE_C4  261.63f
#define NOTE_C4d 277.18f
#define NOTE_D4  293.66f
#define NOTE_D4d 311.13f
#define NOTE_E4  329.63f
#define NOTE_F4  349.23f
#define NOTE_F4d 369.99f
#define NOTE_G4  392.00f
#define NOTE_G4d 415.30f
#define NOTE_A4  440.00f
#define NOTE_A4d 466.16f
#define NOTE_B4  493.88f

#define NOTE_C5  523.25f
#define NOTE_C5d 554.37f
#define NOTE_D5  587.33f
#define NOTE_D5d 622.25f
#define NOTE_E5  659.26f
#define NOTE_F5  698.46f
#define NOTE_F5d 739.99f
#define NOTE_G5  783.99f
#define NOTE_G5d 830.61f
#define NOTE_A5  880.00f
#define NOTE_A5d 932.33f
#define NOTE_B5  987.77f

#define NOTE_C6  1046.50f
#define NOTE_C6d 1108.73f
#define NOTE_D6  1174.66f
#define NOTE_D6d 1244.51f
#define NOTE_E6  1318.51f
#define NOTE_F6  1396.91f
#define NOTE_F6d 1479.98f
#define NOTE_G6  1567.98f
#define NOTE_G6d 1661.22f
#define NOTE_A6  1760.00f
#define NOTE_A6d 1864.66f
#define NOTE_B6  1975.53f

struct note {
	float        freq;
	unsigned int duration; /* in milliseconds */
};

struct song {
	const char        *title;
	const struct note *notes;
};

/* http://www.radiomarconi.com/marconi/mameli_spartito.gif */
#define D 600
static const struct note const inno_mameli[] = {
	{NOTE_D4,  D},

	{NOTE_D4,  D/2+D/4},
	{NOTE_E4,  D/4},
	{NOTE_D4,  2*D},
	{NOTE_B4,  D},

	{NOTE_B4,  D/2+D/4},
	{NOTE_C5,  D/4},
	{NOTE_B4,  2*D},
	{NOTE_B4,  D},

	{NOTE_D5,  D/2+D/4},
	{NOTE_C5,  D/4},
	{NOTE_B4,  2*D},
	{NOTE_A4,  D},

	{NOTE_B4,  D/2+D/4},
	{NOTE_A4,  D/4},
	{NOTE_G4,  2*D},
	{NOTE_D4,  D},


	{NOTE_D4,  D/2+D/4},
	{NOTE_E4,  D/4},
	{NOTE_D4,  2*D},
	{NOTE_B4,  D},

	{NOTE_B4,  D/2+D/4},
	{NOTE_C5,  D/4},
	{NOTE_B4,  2*D},
	{NOTE_B4,  D},

	{NOTE_D5,  D/2+D/4},
	{NOTE_C5,  D/4},
	{NOTE_B4,  2*D},
	{NOTE_A4,  D},

	{NOTE_B4,  D/2+D/4},
	{NOTE_A4,  D/4},
	{NOTE_G4,  2*D},
	{NOTE_B4,  D},

	{NOTE_B4,  D},
	{NOTE_F4d, 2*D},
	{NOTE_G4,  D/2+D/4},
	{NOTE_A4,  D/4},


	{NOTE_G4,  D/2+D/4},
	{NOTE_F4d, D/4},
	{NOTE_E4,  2*D},
	{NOTE_G4,  D},

	{NOTE_F4d, D/2+D/4},
	{NOTE_G4,  D/4},
	{NOTE_A4,  2*D},
	{NOTE_B3,  D},

	{NOTE_B4,  2*D},
	{NOTE_C5,  D},
	{NOTE_D4,  D},

	{NOTE_D4,  D/2+D/4},
	{NOTE_E4,  D/4},
	{NOTE_D4,  2*D},
	{NOTE_B4,  D},

	{NOTE_B4,  D/2+D/4},
	{NOTE_C5,  D/4},
	{NOTE_B4,  2*D},
	{NOTE_B4,  D},


	{NOTE_D5,  D/2+D/4},
	{NOTE_C5,  D/4},
	{NOTE_B4,  D},
	{NOTE_B4,  D/2},
	{NOTE_D5,  D/2},
	{NOTE_A4,  D/2},
	{NOTE_D5,  D/2},

	{NOTE_G4,  2*D},

	{    0.0,  0}
};
#undef D

#define D 700
static const struct note const god_save_the_queen[] = {
	{NOTE_G4,  D},
	{NOTE_G4,  D},
	{NOTE_A4,  D},

	{NOTE_F4d, D+D/2},
	{NOTE_G4,  D/2},
	{NOTE_A4,  D},

	{NOTE_B4,  D},
	{NOTE_B4,  D},
	{NOTE_C5,  D},

	{NOTE_B4,  D+D/2},
	{NOTE_A4,  D/2},
	{NOTE_G4,  D},

	{NOTE_A4,  D},
	{NOTE_G4,  D},
	{NOTE_F4d, D},

	{NOTE_G4,  3*D},

	{NOTE_D5,  D},
	{NOTE_D5,  D},
	{NOTE_D5,  D},

	{NOTE_D5,  D+D/2},
	{NOTE_C5,  D/2},
	{NOTE_B4,  D},

	{NOTE_C5,  D},
	{NOTE_C5,  D},
	{NOTE_C5,  D},

	{NOTE_C5,  D+D/2},
	{NOTE_B4,  D/2},
	{NOTE_A4,  D},

	{NOTE_B4,  D},
	{NOTE_C5,  D/2},
	{NOTE_B4,  D/2},
	{NOTE_A4,  D/2},
	{NOTE_G4,  D/2},

	{NOTE_B4,  D+D/2},
	{NOTE_C5,  D/2},
	{NOTE_D5,  D},

	{NOTE_E5,  D/2},
	{NOTE_C5,  D/2},
	{NOTE_B4,  D},
	{NOTE_A4,  D},

	{NOTE_G4,  2*D},

	{    0.0,  0}
};
#undef D

#define D 500
static const struct note const ode_to_joy[] = {
	{NOTE_B4,  D},
	{NOTE_B4,  D},
	{NOTE_C5,  D},
	{NOTE_D5,  D},
	{NOTE_D5,  D},
	{NOTE_C5,  D},
	{NOTE_B4,  D},
	{NOTE_A4,  D},
	{NOTE_G4,  D},
	{NOTE_G4,  D},
	{NOTE_A4,  D},
	{NOTE_B4,  D},
	{NOTE_B4,  D+D/2},
	{NOTE_A4,  D/2},
	{NOTE_A4,  2*D},

	{NOTE_B4,  D},
	{NOTE_B4,  D},
	{NOTE_C5,  D},
	{NOTE_D5,  D},
	{NOTE_D5,  D},
	{NOTE_C5,  D},
	{NOTE_B4,  D},
	{NOTE_A4,  D},
	{NOTE_G4,  D},
	{NOTE_G4,  D},
	{NOTE_A4,  D},
	{NOTE_B4,  D},
	{NOTE_A4,  D+D/2},
	{NOTE_G4,  D/2},
	{NOTE_G4,  2*D},

	{NOTE_A4,  D},
	{NOTE_A4,  D},
	{NOTE_B4,  D},
	{NOTE_G4,  D},
	{NOTE_A4,  D},
	{NOTE_B4,  D/2},
	{NOTE_C5,  D/2},
	{NOTE_B4,  D},
	{NOTE_G4,  D},
	{NOTE_A4,  D},
	{NOTE_B4,  D/2},
	{NOTE_C5,  D/2},
	{NOTE_B4,  D},
	{NOTE_A4,  D},
	{NOTE_G4,  D},
	{NOTE_A4,  D},
	{NOTE_D4,  2*D},

	{NOTE_B4,  D},
	{NOTE_B4,  D},
	{NOTE_C5,  D},
	{NOTE_D5,  D},
	{NOTE_D5,  D},
	{NOTE_C5,  D},
	{NOTE_B4,  D},
	{NOTE_A4,  D},
	{NOTE_G4,  D},
	{NOTE_G4,  D},
	{NOTE_A4,  D},
	{NOTE_B4,  D},
	{NOTE_A4,  D+D/2},
	{NOTE_G4,  D/2},
	{NOTE_G4,  2*D},

	{    0.0,  0},
};
#undef D

/* http://en.wikipedia.org/wiki/Nokia_tune */
#define D 500
static const struct note const nokia_ringtone[] = {
	{NOTE_E6,  D/2},
	{NOTE_D6,  D/2},
	{NOTE_F5d, D},
	{NOTE_G5d, D},
	{NOTE_C6d, D/2},
	{NOTE_B5,  D/2},
	{NOTE_D5,  D},
	{NOTE_E5,  D},
	{NOTE_B5,  D/2},
	{NOTE_A5,  D/2},
	{NOTE_C5d, D},
	{NOTE_E5,  D},
	{NOTE_A5,  2*D+D},
	{    0.0,  0}
};
#undef D

#define D 600
static const struct note const over_the_rainbow[] = {
	{NOTE_C4,  2*D},
	{NOTE_C5,  2*D},

	{NOTE_B4,  D},
	{NOTE_G4,  D/2},
	{NOTE_A4,  D/2},
	{NOTE_B4,  D},
	{NOTE_C5,  D},

	{NOTE_C4,  2*D},
	{NOTE_A4,  2*D},

	{NOTE_G4,  4*D},

	{NOTE_A3,  2*D},
	{NOTE_F4,  2*D},

	{NOTE_E4,  D},
	{NOTE_C4,  D/2},
	{NOTE_D4,  D/2},
	{NOTE_E4,  D},
	{NOTE_F4,  D},

	{NOTE_D4,  D},
	{NOTE_B3,  D/2},
	{NOTE_C4,  D/2},
	{NOTE_D4,  D},
	{NOTE_E4,  D},

	{NOTE_C4,  4*D},

	{    0.0,  0}
};
#undef D

static const struct song songs[] = {
	{ "Inno di mameli", inno_mameli },
	{ "God save the Queen", god_save_the_queen },
	{ "Ode to joy", ode_to_joy },
	{ "Nokia ringtone", nokia_ringtone },
	{ "Over the rainbow", over_the_rainbow },
	{ NULL, NULL }
};

#if 0
static double sinc(double x)
{
	if (x == 0.0)
		return 1.0;

	return (sin(M_PI*x) / (M_PI*x));
}
#endif

static float sincf(float x)
{
	float arg;

	if (x == 0.0f)
		return 1.0f;

	arg = (float)M_PI * x;

	return (sinf(arg) / (arg));
}

void tones_generate_tone(struct pc_tone *tone, unsigned int samplerate, unsigned int channels, unsigned int one_frame)
{
	unsigned int i;
	float volume, arg, v;

	/* tone buffer, 0.5s, in alsa frames */
	tone->pcmlen = ((samplerate / 2) / one_frame) * one_frame;
	tone->pcm    = xcalloc(channels * sizeof(*tone->pcm), tone->pcmlen);

	volume = 10000.0f;
	arg = 2.0f * (float)M_PI * 440.0f / (float)samplerate;
	if (channels == 1) {
		for (i = 0; i < tone->pcmlen; i++) {
			v = volume * sinf(arg * (float)i);
			tone->pcm[i] = (int16_t)lrintf(v);
		}
	} else {
		for (i = 0; i < tone->pcmlen; i++) {
			v = volume * sinf(arg * (float)i);
			tone->pcm[channels*i    ] = (int16_t)lrintf(v);
			tone->pcm[channels*i + 1] = (int16_t)lrintf(v);
		}
	}
	tone->pos    = 0;
	tone->play   = 0;
	tone->enable = 0;
}

void tones_generate_calltone(struct pc_calltone *calltone, unsigned int samplerate, unsigned int channels, unsigned int one_frame)
{
	unsigned int i;
	float volume, arg, v;

	/* calltone buffer, 5s, in alsa frames */
	calltone->pcmlen = ((samplerate * 5) / one_frame) * one_frame;
	calltone->pcm    = xcalloc(channels * sizeof(*calltone->pcm), calltone->pcmlen);

	/* ITU-T E.180 ringing tone for Italy, 425Hz, 4/1, start at 0.5s */
	volume = 20000.0f;
	arg = 2.0f * (float)M_PI * 425.0f / (float)samplerate;
	if (channels == 1) {
		for (i = samplerate / 2; i < (3 * samplerate) / 2; i++) {
			v = volume * sinf(arg * (float)i);
			calltone->pcm[i] = (int16_t)lrintf(v);
		}
	} else {
		for (i = samplerate / 2; i < (3 * samplerate) / 2; i++) {
			v = volume * sinf(arg * (float)i);
			calltone->pcm[channels*i    ] = (int16_t)lrintf(v);
			calltone->pcm[channels*i + 1] = (int16_t)lrintf(v);
		}
	}
	calltone->pos = 0;
}

void tones_generate_ringtone(struct pc_ringtone *ringtone, unsigned int song_index,
                             unsigned int samplerate, unsigned int channels, unsigned int one_frame)
{
	unsigned int n, nb_songs, duration, samples, pos;
	float inverse_samplerate, volume, arg, v;
	const struct note *notes;

	/* get number of songs */
	for (n = 0; ; n++) {
		if (songs[n].title == NULL)
			break;
	}
	nb_songs = n;

	/* make sure the user selected a valid song */
	if (song_index >= nb_songs)
		song_index = 0;
	notes = songs[song_index].notes;

	/* compute ringtone duration */
	duration = 0;
	for (n = 0; notes[n].duration != 0; n++)
		duration += notes[n].duration;
	duration += 500 + 1500;             /* start silence + end silence */
	duration = (duration + 999) / 1000; /* duration is now in seconds */

	/* allocate memory for the samples buffer */
	ringtone->pcmlen = ((duration * samplerate) / one_frame) * one_frame;
	ringtone->pcm    = xcalloc(channels * sizeof(*ringtone->pcm), ringtone->pcmlen);

	/* synthesize ringtone */
	pos = channels * samplerate / 2; /* skip 0.5s */
	inverse_samplerate = 1.0f / (float)samplerate;
	volume = 20000.0f;
	for (n = 0; notes[n].duration != 0; n++) {
		unsigned int i;

		samples = samplerate * notes[n].duration / 1000;
		arg = 2.0f * (float)M_PI * notes[n].freq * inverse_samplerate;

		if (channels == 1) {
			for (i = 0; i < samples; i++) {
				v = volume * sinf(arg * (float)i);

				/* sinc modulation */
				v *= sincf((float)i * 2.0f * inverse_samplerate);

				ringtone->pcm[pos + i] = (int16_t)lrintf(v);
			}
		} else {
			for (i = 0; i < samples; i++) {
				v = volume * sinf(arg * (float)i);
#if 0
				/* square wave */
				v = v < 0.0 ? -1 : 1;

				/* exponential modulation */
				v *= expf(-(float)i / (1.0f * samples));
#endif
				/* sinc modulation */
				v *= sincf((float)i * 2.0f * inverse_samplerate);

				ringtone->pcm[pos + channels*i    ] = (int16_t)lrintf(v);
				ringtone->pcm[pos + channels*i + 1] = (int16_t)lrintf(v);
			}
		}
		pos += channels * samples;
	}

	ringtone->pos    = 0;
	ringtone->enable = 1;
}
