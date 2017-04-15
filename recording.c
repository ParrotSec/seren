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

#include <stdlib.h>
#include <string.h>
#include "recording.h"
#include "rw.h"
#include "common.h"

#define MKTAG(a, b, c, d) ((a << 24) | (b << 16) | (c << 8) | d)

FILE *wave_start_recording(const char *filename, unsigned int samplerate, unsigned int channels)
{
	FILE *fp;

	fp = fopen(filename, "w");
	if (fp) {
		uint8_t  header[64];
		uint8_t *d = header;
		size_t   l = 0;

		write_be32(d, MKTAG('R', 'I', 'F', 'F')); d+=4; l+=4;
		write_le32(d, 0);                         d+=4; l+=4; //ChunkSize
		write_be32(d, MKTAG('W', 'A', 'V', 'E')); d+=4; l+=4;

		write_be32(d, MKTAG('f', 'm', 't', ' ')); d+=4; l+=4; //Subchunk1ID
		write_le32(d, 16);                        d+=4; l+=4; //Subchunk1Size
		write_le16(d, 1);                         d+=2; l+=2; //AudioFormat
		write_le16(d, (uint16_t)channels);        d+=2; l+=2; //NumChannels
		write_le32(d, samplerate);                d+=4; l+=4; //SampleRate
		write_le32(d, samplerate * channels * 2); d+=4; l+=4; //ByteRate = SampleRate * NumChannels * BitsPerSample/8
		write_le16(d, (uint16_t)(channels * 2));  d+=2; l+=2; //BlockAlign = NumChannels * BitsPerSample/8
		write_le16(d, 16);                        d+=2; l+=2; //BitsPerSample

		write_be32(d, MKTAG('d', 'a', 't', 'a')); d+=4; l+=4;
		write_le32(d, 0);                         d+=4; l+=4; //Subchunk2Size = NumSamples * NumChannels * BitsPerSample/8

		fwrite(header, 1, l, fp);
	}

	return fp;
}

void wave_write_data(const int16_t *pcm, unsigned int channels, unsigned int frames,
                     uint32_t *bytes_written, FILE *fp)
{
	fwrite(pcm, sizeof(pcm[0]), channels * frames, fp);
	*bytes_written += (uint32_t)(sizeof(pcm[0]) * channels * frames);
}

void wave_stop_recording(uint32_t bytes_written, FILE *fp)
{
	uint8_t size[4];

	fseek(fp, 4, SEEK_SET);
	write_le32(size, 36+bytes_written);
	fwrite(size, 1, 4, fp);

	fseek(fp, 40, SEEK_SET);
	write_le32(size, bytes_written);
	fwrite(size, 1, 4, fp);

	fclose(fp);
}



static ogg_packet *make_opus_header0_oggpacket(unsigned int samplerate, unsigned int channels)
{
	size_t         size = 19;
	ogg_packet    *op;
	unsigned char *data;

	op   = xmalloc(sizeof(*op));
	data = xmalloc(size);

	memcpy(data, "OpusHead", 8);       /* identifier */
	data[8] = 1;                       /* version */
	data[9] = (unsigned char)channels; /* channels */
	write_le16(data+10, 0);            /* pre-skip */
	write_le32(data+12, samplerate);   /* original sample rate */
	write_le16(data+16, 0);            /* gain */
	data[18] = 0;                      /* channel mapping family */

	op->packet     = data;
	op->bytes      = (long)size;
	op->b_o_s      = 1;
	op->e_o_s      = 0;
	op->granulepos = 0;
	op->packetno   = 0;

	return op;
}

static ogg_packet *make_opus_header1_oggpacket(const char *vendor)
{
	const char    *identifier = "OpusTags";
	size_t         size;
	ogg_packet    *op;
	unsigned char *data;

	size = strlen(identifier) + 4 + strlen(vendor) + 4;
	op   = xmalloc(sizeof(*op));
	data = xmalloc(size);

	memcpy(data, identifier, 8);
	write_le32(data+8, (uint32_t)strlen(vendor));
	memcpy(data+12, vendor, strlen(vendor));
	write_le32(data+12+strlen(vendor), 0);

	op->packet     = data;
	op->bytes      = (long)size;
	op->b_o_s      = 0;
	op->e_o_s      = 0;
	op->granulepos = 0;
	op->packetno   = 1;

	return op;
}

static int write_ogg_packet(ogg_stream_state *ostream, ogg_packet *opacket, FILE *fp, int flush)
{
	ogg_page opage;

	/* Submit a raw packet to the streaming layer */
	if (ogg_stream_packetin(ostream, opacket) == 0) {
		/* Output a completed page if the stream contains enough packets to form a full page. */
		while (flush ? ogg_stream_flush(ostream, &opage) : ogg_stream_pageout(ostream, &opage)) {
			fwrite(opage.header, 1, (size_t)opage.header_len, fp);
			fwrite(opage.body  , 1, (size_t)opage.body_len,   fp);
		}
	} else {
		return -1;
	}
	return 0;
}

FILE *oggopus_start_recording(const char *filename, unsigned int samplerate, unsigned int channels,
                              OpusEncoder **enc, ogg_stream_state *oss)
{
	int          ret, error;
	FILE        *fp;
	ogg_packet  *opacket_opus_header[2];

	/* create encoder state */
	*enc = opus_encoder_create((opus_int32)samplerate, (int)channels, OPUS_APPLICATION_VOIP, &error);
	if (error != OPUS_OK) {
		*enc = NULL;
		return NULL;
	}
	error = opus_encoder_ctl(*enc, OPUS_SET_BITRATE(32000));
	error = opus_encoder_ctl(*enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));

	/* open file */
	fp = fopen(filename, "w");
	if (!fp) {
		opus_encoder_destroy(*enc);
		*enc = NULL;
		return NULL;
	}

	/* ogg init */
	ret = ogg_stream_init(oss, rand());
	if (ret != 0) {
		opus_encoder_destroy(*enc);
		*enc = NULL;
		fclose(fp);
		return NULL;
	}

	/* opus header packets */
	opacket_opus_header[0] = make_opus_header0_oggpacket(samplerate, channels);
	opacket_opus_header[1] = make_opus_header1_oggpacket("Seren");
	write_ogg_packet(oss, opacket_opus_header[0], fp, 1);
	write_ogg_packet(oss, opacket_opus_header[1], fp, 1);
	free(opacket_opus_header[0]->packet);
	free(opacket_opus_header[0]);
	free(opacket_opus_header[1]->packet);
	free(opacket_opus_header[1]);

	return fp;
}

void oggopus_write_data(const int16_t *pcm, unsigned int frames, OpusEncoder *enc,
                        ogg_stream_state *oss, int64_t *packetno, int eos, FILE *fp)
{
	uint8_t    opus_enc_packet[4000];
	opus_int32 opus_enc_packetlen;
	ogg_packet opacket;

	/* encoding */
	opus_enc_packetlen = opus_encode(enc, pcm, (int)frames, opus_enc_packet, 4000);
	if (opus_enc_packetlen < 0)
		return;

	/* forge ogg packet */
	opacket.packet     = opus_enc_packet;
	opacket.bytes      = opus_enc_packetlen;
	opacket.b_o_s      = 0;
	opacket.e_o_s      = (eos != 0);
	opacket.granulepos = (*packetno-1)*frames;
	opacket.packetno   = *packetno;

	/* write ogg packet to file */
	write_ogg_packet(oss, &opacket, fp, 0);

	*packetno += 1;
}

void oggopus_stop_recording(OpusEncoder **enc, ogg_stream_state *oss, FILE *fp)
{
	ogg_page opage;

	while (ogg_stream_flush(oss, &opage)) {
		fwrite(opage.header, 1, (size_t)opage.header_len, fp);
		fwrite(opage.body  , 1, (size_t)opage.body_len,   fp);
	}

	ogg_stream_clear(oss);
	opus_encoder_destroy(*enc);
	*enc = NULL;
	fclose(fp);
}
