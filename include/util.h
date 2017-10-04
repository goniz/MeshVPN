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

#ifndef H_UTIL
#define H_UTIL

#include <string.h>
#include <stdint.h>
#include <time.h>


// Convert a 4 bit number to a hexchar.
char util4BitToHexchar(const int n);

// Convert a byte array to a hexstring.
int utilByteArrayToHexstring(char *str, const int strlen, const unsigned char *arr, const int arrlen);

// Convert a string to uppercase and change all non-alphanumeric characters to '_'.
void utilStringFilter(char *strout, const char *strin, const int strlen);

// Determine endianness
int utilIsLittleEndian();

// Read 16 bit integer
int16_t utilReadInt16(const unsigned char *buf);

// Write 16 bit integer
void utilWriteInt16(unsigned char *buf, int16_t i);

// Read 32 bit integer
int32_t utilReadInt32(const unsigned char *buf);

// Write 32 bit integer
void utilWriteInt32(unsigned char *buf, int32_t i);

// Read 64 bit integer
int64_t utilReadInt64(const unsigned char *buf);

// Write 64 bit integer
void utilWriteInt64(unsigned char *buf, int64_t i);

// Get clock value in seconds
int utilGetClock();

int isWhitespaceChar(char c);

#endif // H_UTIL
