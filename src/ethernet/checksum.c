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

#ifndef F_CHECKSUM_C
#define F_CHECKSUM_C

#include "ethernet.h"

// Zeroes the checksum.
void checksumZero(struct s_checksum *cs) {
	cs->checksum = 0;
}


// Adds 16 bit to the checksum.
void checksumAdd(struct s_checksum *cs, const uint16_t x) {
	cs->checksum += x;
}


// Get checksum
uint16_t checksumGet(struct s_checksum *cs) {
	uint16_t ret;
	cs->checksum = ((cs->checksum & 0xFFFF) + (cs->checksum >> 16));
	cs->checksum = ((cs->checksum & 0xFFFF) + (cs->checksum >> 16));
	ret = ~(cs->checksum);
	return ret;
}


#endif // F_CHECKSUM_C
