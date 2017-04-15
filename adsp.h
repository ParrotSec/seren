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

#ifndef ADSP_H
#define ADSP_H

#include <stddef.h>
#include <stdint.h>

void     adsp_sum_s32_s16(int32_t *pcm32, const int16_t *pcm16, size_t samples);
void     adsp_copy_s16_s32(int16_t *pcm16, const int32_t *pcm32, size_t samples);
void     adsp_compress_tanh_s16_s32(int16_t *pcm16, const int32_t *pcm32, size_t samples);
void     adsp_scale_s16_s32(int16_t *pcm16, const int32_t *pcm32, size_t samples, float gain);

void     adsp_sum_and_clip_s16_s16(int16_t *pcm16_d, const int16_t *pcm16_s, size_t samples);
void     adsp_scale_and_clip_s16_s16(int16_t *pcm16, size_t samples, float gain);

int32_t  adsp_find_peak_s16_2ch(const int16_t *pcm, size_t samples);
int32_t  adsp_find_peak_s32_2ch(const int32_t *pcm, size_t samples);
uint64_t adsp_sum_of_squares(const int16_t *pcm, size_t samples);

#endif
