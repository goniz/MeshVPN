/*
 * MeshVPN - A open source peer-to-peer VPN (forked from PeerVPN)
 *
 * Copyright (C) 2012-2016  Tobias Volk <mail@tobiasvolk.de>
 * Copyright (C) 2016       Hideman Developer <company@hideman.net>
 * Copyright (C) 2017       Benjamin Kübler <b.kuebler@kuebler-it.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef F_PACKET_C
#define F_PACKET_C


#include "crypto.h"
#include "p2p.h"
#include "util.h"

// return the peer ID
int packetGetPeerID(const unsigned char *pbuf) {
	int32_t *scr_peerid = ((int32_t *)pbuf);
	int32_t ne_peerid = (scr_peerid[0] ^ (scr_peerid[1] ^ scr_peerid[2]));
	return utilReadInt32((unsigned char *)&ne_peerid);
}


// encode packet
int packetEncode(unsigned char *pbuf, const int pbuf_size, const struct s_packet_data *data, struct s_crypto *ctx) {
	unsigned char dec_buf[packet_CRHDR_SIZE + data->pl_buf_size];
	int32_t *scr_peerid = ((int32_t *)pbuf);
	int32_t ne_peerid;
	int len;

	// check if enough space is available for the operation
	if(data->pl_length > data->pl_buf_size) { return 0; }

	// prepare buffer
	utilWriteInt64(&dec_buf[packet_CRHDR_SEQ_START], data->seq);
	utilWriteInt16(&dec_buf[packet_CRHDR_PLLEN_START], data->pl_length);
	dec_buf[packet_CRHDR_PLTYPE_START] = data->pl_type;
	dec_buf[packet_CRHDR_PLOPT_START] = data->pl_options;
	memcpy(&dec_buf[packet_CRHDR_SIZE], data->pl_buf, data->pl_length);

	// encrypt buffer
	len = cryptoEnc(ctx, &pbuf[packet_PEERID_SIZE], (pbuf_size - packet_PEERID_SIZE), dec_buf, (packet_CRHDR_SIZE + data->pl_length), packet_HMAC_SIZE, packet_IV_SIZE);
	if(len < (packet_HMAC_SIZE + packet_IV_SIZE + packet_CRHDR_SIZE)) { return 0; }

	// write the scrambled peer ID
	utilWriteInt32((unsigned char *)&ne_peerid, data->peerid);
	scr_peerid[0] = (ne_peerid ^ (scr_peerid[1] ^ scr_peerid[2]));

	// return length of encoded packet
	return (packet_PEERID_SIZE + len);
}

int packetVerifyPacket(const unsigned char* pbuf, const int pbuf_size, struct s_crypto* ctx)
{
	unsigned char dec_buf[pbuf_size];

	// decrypt packet
	if(pbuf_size < (packet_PEERID_SIZE + packet_HMAC_SIZE + packet_IV_SIZE)) {
		return -1;
	}

	int len = cryptoDec(ctx, dec_buf, pbuf_size, &pbuf[packet_PEERID_SIZE], (pbuf_size - packet_PEERID_SIZE), packet_HMAC_SIZE, packet_IV_SIZE);
	if (len < packet_CRHDR_SIZE) {
		return -1;
	}

	// get packet data
	return packetGetPeerID(pbuf);
}

// decode packet
int packetDecode(struct s_packet_data *data, const unsigned char *pbuf, const int pbuf_size, struct s_crypto *ctx, struct s_seq_state *seqstate) {
	unsigned char dec_buf[pbuf_size];
	int len;

	// decrypt packet
	if(pbuf_size < (packet_PEERID_SIZE + packet_HMAC_SIZE + packet_IV_SIZE)) { return 0; }
	len = cryptoDec(ctx, dec_buf, pbuf_size, &pbuf[packet_PEERID_SIZE], (pbuf_size - packet_PEERID_SIZE), packet_HMAC_SIZE, packet_IV_SIZE);
	if(len < packet_CRHDR_SIZE) { return 0; };

	// get packet data
	data->peerid = packetGetPeerID(pbuf);
	data->seq = utilReadInt64(&dec_buf[packet_CRHDR_SEQ_START]);
	if(seqstate != NULL) if(!seqVerify(seqstate, data->seq)) { return 0; }
	data->pl_options = dec_buf[packet_CRHDR_PLOPT_START];
	data->pl_type = dec_buf[packet_CRHDR_PLTYPE_START];
	data->pl_length = utilReadInt16(&dec_buf[packet_CRHDR_PLLEN_START]);
	if(!(data->pl_length > 0)) {
		data->pl_length = 0;
		return 0;
	}
	if(len < (packet_CRHDR_SIZE + data->pl_length)) { return 0; }
	if(data->pl_length > data->pl_buf_size) { return 0; }
	memcpy(data->pl_buf, &dec_buf[packet_CRHDR_SIZE], data->pl_length);

	// return length of decoded payload
	return (data->pl_length);
}


#endif // F_PACKET_C
