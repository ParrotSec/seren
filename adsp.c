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

#include <math.h>
#include "adsp.h"

void adsp_sum_s32_s16(int32_t *pcm32, const int16_t *pcm16, size_t samples)
{
	size_t i;

	for (i = 0; i < samples; i += 2) {
		pcm32[i  ] += pcm16[i  ];
		pcm32[i+1] += pcm16[i+1];
	}
}

void adsp_copy_s16_s32(int16_t *pcm16, const int32_t *pcm32, size_t samples)
{
	size_t i;

	for (i = 0; i < samples; i += 2) {
		pcm16[i  ] = (int16_t)pcm32[i  ];
		pcm16[i+1] = (int16_t)pcm32[i+1];
	}
}

void adsp_compress_tanh_s16_s32(int16_t *pcm16, const int32_t *pcm32, size_t samples)
{
	size_t i;

	for (i = 0; i < samples; i += 2) {
		pcm16[i  ] = (int16_t)lrintf(32767.0f * tanhf((float)pcm32[i  ] * (1.0f/32768.0f)));
		pcm16[i+1] = (int16_t)lrintf(32767.0f * tanhf((float)pcm32[i+1] * (1.0f/32768.0f)));
	}
}

void adsp_scale_s16_s32(int16_t *pcm16, const int32_t *pcm32, size_t samples, float gain)
{
	size_t i;

	for (i = 0; i < samples; i += 2) {
		pcm16[i  ] = (int16_t)lrintf((float)pcm32[i  ] * gain);
		pcm16[i+1] = (int16_t)lrintf((float)pcm32[i+1] * gain);
	}
}


void adsp_sum_and_clip_s16_s16(int16_t *pcm16_d, const int16_t *pcm16_s, size_t samples)
{
	size_t i;
	int32_t vl, vr;

	for (i = 0; i < samples; i += 2) {
		vl = (int32_t)pcm16_s[i  ] + (int32_t)pcm16_d[i  ];
		vr = (int32_t)pcm16_s[i+1] + (int32_t)pcm16_d[i+1];
		vl = (vl < INT16_MIN) ? INT16_MIN : ((vl > INT16_MAX) ? INT16_MAX : vl);
		vr = (vr < INT16_MIN) ? INT16_MIN : ((vr > INT16_MAX) ? INT16_MAX : vr);
		pcm16_d[i  ] = (int16_t)vl;
		pcm16_d[i+1] = (int16_t)vr;
	}
}

void adsp_scale_and_clip_s16_s16(int16_t *pcm16, size_t samples, float gain)
{
	size_t i;
	int32_t vl, vr;

	for (i = 0; i < samples; i += 2) {
		vl = (int32_t)lrintf((float)pcm16[i  ] * gain);
		vr = (int32_t)lrintf((float)pcm16[i+1] * gain);
		vl = (vl < INT16_MIN) ? INT16_MIN : ((vl > INT16_MAX) ? INT16_MAX : vl);
		vr = (vr < INT16_MIN) ? INT16_MIN : ((vr > INT16_MAX) ? INT16_MAX : vr);
		pcm16[i  ] = (int16_t)vl;
		pcm16[i+1] = (int16_t)vr;
	}
}


int32_t adsp_find_peak_s16_2ch(const int16_t *pcm, size_t samples)
{
	size_t i;
	int32_t vl, vr, pl, pr, nl, nr;

	pl = pr = nl = nr = 0;
	for (i = 0; i < samples; i += 2) {
		vl = pcm[i  ];
		vr = pcm[i+1];
		if (vl > pl)
			pl = vl;
		if (vl < nl)
			nl = vl;
		if (vr > pr)
			pr = vr;
		if (vr < nr)
			nr = vr;
	}
	pl = pl > -nl ? pl : -nl;
	pr = pr > -nr ? pr : -nr;
	return pl > pr ? pl : pr;
}

int32_t adsp_find_peak_s32_2ch(const int32_t *pcm, size_t samples)
{
	size_t i;
	int32_t vl, vr, pl, pr, nl, nr;

	pl = pr = nl = nr = 0;
	for (i = 0; i < samples; i += 2) {
		vl = pcm[i  ];
		vr = pcm[i+1];
		if (vl > pl)
			pl = vl;
		if (vl < nl)
			nl = vl;
		if (vr > pr)
			pr = vr;
		if (vr < nr)
			nr = vr;
	}
	pl = pl > -nl ? pl : -nl;
	pr = pr > -nr ? pr : -nr;
	return pl > pr ? pl : pr;
}

uint64_t adsp_sum_of_squares(const int16_t *pcm, size_t samples)
{
	size_t i;
	int64_t vl, vr;
	uint64_t suml, sumr;

	suml = sumr = 0;
	for (i = 0; i < samples; i += 2) {
		vl = pcm[i  ];
		vr = pcm[i+1];
		vl *= vl;
		vr *= vr;
		suml += (uint64_t)vl;
		sumr += (uint64_t)vr;
	}
	return suml + sumr;
}
