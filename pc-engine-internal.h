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

#ifndef PC_ENGINE_INTERNAL_H
#define PC_ENGINE_INTERNAL_H

#define UDP_PACKET_MASK_MODE           0xC000
#define UDP_PACKET_MASK_UNUSED         0x3000
#define UDP_PACKET_MASK_FAMILY         0x0F00
#define UDP_PACKET_MASK_TYPE           0x00FF

#define UDP_PACKET_MASK_MFTYPE         0xCFFF
#define UDP_PACKET_MASK_FTYPE          0x0FFF

#define UDP_PACKET_MODE_CLEAR          0x0000
#define UDP_PACKET_MODE_SECURE         0x4000
#define UDP_PACKET_MODE_PSK            0x8000
#define UDP_PACKET_MODE_RESERVED       0xC000

#define UDP_PACKET_FAMILY_HANDSHAKE    0x0000
#define UDP_PACKET_FAMILY_DATA         0x0100
#define UDP_PACKET_FAMILY_RELAY        0x0200
#define UDP_PACKET_FAMILY_TELEMETRY    0x0300
#define UDP_PACKET_FAMILY_RTT          0x0400
#define UDP_PACKET_FAMILY_ENCRYPTED    0x0F00

/* A CALL udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be),  (mode, family, type)
 * Payload:
 *   pc_engine_version_major     (uint8)
 *   pc_engine_version_minor     (uint8)
 *   pc_engine_version_subminor  (uint8)
 *   nick                        (NICKLEN bytes)
 *   pgid                        (uint8)
 *   algo                        (uint8)
 *   pklen                       (uint16, be)
 *   pk                          (variable)
 */
#define UDP_PACKET_TYPE_CALL           0
#define UDP_PACKET_FTYPE_CALL          (UDP_PACKET_FAMILY_HANDSHAKE | UDP_PACKET_TYPE_CALL)

/* A CONNECT udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 * Payload:
 *   same as for CALL packet
 */
#define UDP_PACKET_TYPE_CONNECT        1
#define UDP_PACKET_FTYPE_CONNECT       (UDP_PACKET_FAMILY_HANDSHAKE | UDP_PACKET_TYPE_CONNECT)

/* A REFUSE udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 * Payload:
 *   reason                      (uint16, be)
 */
#define UDP_PACKET_TYPE_REFUSE         2
#define UDP_PACKET_FTYPE_REFUSE        (UDP_PACKET_FAMILY_HANDSHAKE | UDP_PACKET_TYPE_REFUSE)

/* A TABLE udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 * Payload:
 *   pklen                       (uint16, be)
 *   pk                          (variable)
 *   table_size                  (uint16, be)
 *   my_nick                     (NICKLEN bytes)
 * repeat table_size-1 times for all other nodes except caller:
 *   nick                        (NICKLEN bytes)
 *   addr                        (uint32, be)
 *   port                        (uint16, be)
 */
#define UDP_PACKET_TYPE_TABLE          3
#define UDP_PACKET_FTYPE_TABLE         (UDP_PACKET_FAMILY_HANDSHAKE | UDP_PACKET_TYPE_TABLE)

/* A BYE udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 */
#define UDP_PACKET_TYPE_BYE            4
#define UDP_PACKET_FTYPE_BYE           (UDP_PACKET_FAMILY_HANDSHAKE | UDP_PACKET_TYPE_BYE)


/* An AUDIO udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 *   sequence_number             (uint32, be)
 * Payload:
 *   data                        (variable size, 4000 byte max)
 *
 * The field sequence_number must start at 0 for the first packet and increase
 * monotonically. The payload data is the opus packet coming out of the encoder.
 */
#define UDP_PACKET_TYPE_AUDIO          0
#define UDP_PACKET_FTYPE_AUDIO         (UDP_PACKET_FAMILY_DATA | UDP_PACKET_TYPE_AUDIO)
#define UDP_PACKET_AUDIO_HEADER_LEN    6
#define UDP_PACKET_AUDIO_PAYLOAD_LEN   4000
#define UDP_PACKET_AUDIO_MAXLEN        (UDP_PACKET_AUDIO_HEADER_LEN + UDP_PACKET_AUDIO_PAYLOAD_LEN)

/* A NOP udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 */
#define UDP_PACKET_TYPE_NOP            1
#define UDP_PACKET_FTYPE_NOP           (UDP_PACKET_FAMILY_DATA | UDP_PACKET_TYPE_NOP)

/* A CHAT udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 * Payload:
 *   data                        (UTF-8 string, null terminated, variable size)
 */
#define UDP_PACKET_TYPE_CHAT           2
#define UDP_PACKET_FTYPE_CHAT          (UDP_PACKET_FAMILY_DATA | UDP_PACKET_TYPE_CHAT)


/* A RELAY udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 *   dest_addr                   (uint32, be)
 *   dest_port                   (uint16, be)
 * Payload:
 *   packet to relay             (variable size)
 */
#define UDP_PACKET_TYPE_RELAY          0
#define UDP_PACKET_FTYPE_RELAY         (UDP_PACKET_FAMILY_RELAY | UDP_PACKET_TYPE_RELAY)

/* A RELAYED udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 *   source_addr                 (uint32, be)
 *   source_port                 (uint16, be)
 * Payload:
 *   packet relayed              (variable size)
 */
#define UDP_PACKET_TYPE_RELAYED        1
#define UDP_PACKET_FTYPE_RELAYED       (UDP_PACKET_FAMILY_RELAY | UDP_PACKET_TYPE_RELAYED)


/* A PLINFO udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 * Payload:
 *   pl10k                       (uint32, be),  (packet_loss_perc * 10000)
 */
#define UDP_PACKET_TYPE_PLINFO         0
#define UDP_PACKET_FTYPE_PLINFO        (UDP_PACKET_FAMILY_TELEMETRY | UDP_PACKET_TYPE_PLINFO)


/* A RTTREQ udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 * Payload:
 *   sec                         (uint32, be)
 *   usec                        (uint32, be)
 */
#define UDP_PACKET_TYPE_RTTREQ         0
#define UDP_PACKET_FTYPE_RTTREQ        (UDP_PACKET_FAMILY_RTT | UDP_PACKET_TYPE_RTTREQ)

/* A RTTANS udp packet has the following structure:
 * Header:
 *   packet_header               (uint16, be)
 * Payload:
 *   sec                         (uint32, be)
 *   usec                        (uint32, be)
 */
#define UDP_PACKET_TYPE_RTTANS         1
#define UDP_PACKET_FTYPE_RTTANS        (UDP_PACKET_FAMILY_RTT | UDP_PACKET_TYPE_RTTANS)


/* A ENCRYPTED udp packet has the following structure:
 * Header:
 *   packet_header         (uint16, be)
 *   initialization_vector (2x uint32 or 2x uint64, be)
 * Payload:
 *   encrypted packet      (variable size)
 *
 * The payload is encrypted with XTEA, CAST-128, BLOWFISH or CAMELLIA.
 * Its size must be a multiple of the blocksize of the used cipher (16 bytes for
 * CAMELLIA, 8 bytes otherwise). To obtain this, a padding at the end of the
 * packet is added, which consists of exactly n bytes all with value n.
 *
 * Note: Considering a blocksize of 8 bytes, if the size of the packet is already
 * multiple of 8, another 8 bytes will be added, all with value 8. This means
 * that n>0 always and (packetlen + n) % 8 = 0.
 */
#define UDP_PACKET_TYPE_XTEA           0
#define UDP_PACKET_TYPE_CAST128        1
#define UDP_PACKET_TYPE_BLOWFISH       2
#define UDP_PACKET_TYPE_CAMELLIA       3
#define UDP_PACKET_TYPE_TWOFISH        4

#define UDP_PACKET_FTYPE_XTEA          (UDP_PACKET_FAMILY_ENCRYPTED | UDP_PACKET_TYPE_XTEA)
#define UDP_PACKET_FTYPE_CAST128       (UDP_PACKET_FAMILY_ENCRYPTED | UDP_PACKET_TYPE_CAST128)
#define UDP_PACKET_FTYPE_BLOWFISH      (UDP_PACKET_FAMILY_ENCRYPTED | UDP_PACKET_TYPE_BLOWFISH)
#define UDP_PACKET_FTYPE_CAMELLIA      (UDP_PACKET_FAMILY_ENCRYPTED | UDP_PACKET_TYPE_CAMELLIA)
#define UDP_PACKET_FTYPE_TWOFISH       (UDP_PACKET_FAMILY_ENCRYPTED | UDP_PACKET_TYPE_TWOFISH)

/* node status */
#define STATUS_CONNECTING     0
#define STATUS_CONNECTING_END 20
#define STATUS_CALLING        100
#define STATUS_OK             200

#endif
