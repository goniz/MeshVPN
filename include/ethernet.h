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

#ifndef H_ETHERNET
#define H_ETHERNET

#include <stdint.h>
#include "p2p.h"

// The checksum structure.
struct s_checksum {
        uint32_t checksum;
};


// Constants.
#define virtserv_LISTENADDR_COUNT 8
#define virtserv_ADDR_SIZE 16
#define virtserv_MAC_SIZE 6
#define virtserv_MAC "\x00\x22\x00\xed\x13\x37"


// Constraints.
#if virtserv_ADDR_SIZE != 16
#error virtserv_ADDR_SIZE != 16
#endif
#if virtserv_MAC_SIZE != 6
#error virtserv_MAC_SIZE != 6
#endif


// The virtual service structure.
struct s_virtserv_state {
        struct s_map listenaddrs;
        unsigned char mac[virtserv_MAC_SIZE];
};



// Constants.
#define switch_FRAME_TYPE_INVALID 0
#define switch_FRAME_TYPE_BROADCAST 1
#define switch_FRAME_TYPE_UNICAST 2
#define switch_FRAME_MINSIZE 14
#define switch_MACADDR_SIZE 6
#define switch_MACMAP_SIZE 8192
#define switch_TIMEOUT 86400


// Constraints.
#if switch_FRAME_MINSIZE < switch_MACADDR_SIZE + switch_MACADDR_SIZE
#error switch_FRAME_MINSIZE too small
#endif
#if switch_MACADDR_SIZE != 6
#error switch_MACADDR_SIZE is not 6
#endif


// Switchstate structures.
struct s_switch_mactable_entry {
        int portid;
        int portts;
        int ents;
};
struct s_switch_state {
        struct s_map mactable;
};



// Constants.
#define ndp6_TABLE_SIZE 1024
#define ndp6_ADDR_SIZE 16
#define ndp6_MAC_SIZE 6
#define ndp6_TIMEOUT 86400


// Constraints.
#if ndp6_ADDR_SIZE != 16
#error ndp6_ADDR_SIZE != 16
#endif
#if ndp6_MAC_SIZE != 6
#error ndp6_MAC_SIZE != 6
#endif


// NDP6 structures.
struct s_ndp6_ndptable_entry {
        unsigned char mac[ndp6_MAC_SIZE];
        int portid;
        int portts;
        int ents;
};

struct s_ndp6_state {
        struct s_map ndptable;
};

// Zeroes the checksum.
void checksumZero(struct s_checksum *cs);

// Adds 16 bit to the checksum.
void checksumAdd(struct s_checksum *cs, const uint16_t x);

// Get checksum
uint16_t checksumGet(struct s_checksum *cs);


// Learn MAC+PortID+PortTS of incoming IPv6 packet.
void ndp6PacketIn(struct s_ndp6_state *ndpstate, const unsigned char *frame, const int frame_len, const int portid, const int portts);

// Generate neighbor advertisement. Returns length of generated answer.
int ndp6GenAdvFrame(unsigned char *outbuf, const int outbuf_len, const unsigned char *src_addr, const unsigned char *dest_addr, const unsigned char *src_mac, const unsigned char *dest_mac);

// Scan Ethernet frame for neighbour solicitation and generate answer neighbor advertisement. Returns length of generated answer.
int ndp6GenAdv(struct s_ndp6_state *ndpstate, const unsigned char *frame, const int frame_len, unsigned char *advbuf, const int advbuf_len, int *portid, int *portts);

// Generate NDP table status report.
void ndp6Status(struct s_ndp6_state *ndpstate, char *report, const int report_len);

// Create NDP6 structure.
int ndp6Create(struct s_ndp6_state *ndpstate);

// Destroy NDP6 structure.
void ndp6Destroy(struct s_ndp6_state *ndpstate);

// Get type of outgoing frame. If it is an unicast frame, also returns PortID and PortTS.
int switchFrameOut(struct s_switch_state *switchstate, const unsigned char *frame, const int frame_len, int *portid, int *portts);

// Learn PortID+PortTS of incoming frame.
void switchFrameIn(struct s_switch_state *switchstate, const unsigned char *frame, const int frame_len, const int portid, const int portts);

// Generate MAC table status report.
void switchStatus(struct s_switch_state *switchstate, char *report, const int report_len);

// Create switchstate structure.
int switchCreate(struct s_switch_state *switchstate);

// Destroy switchstate structure.
void switchDestroy(struct s_switch_state *switchstate);

// Add address to virtual service
int virtservAddAddress(struct s_virtserv_state *virtserv, const unsigned char *ipv6address);

// Returns 1 if mac address is the mac address of the virtual service.
int virtservCheckMac(struct s_virtserv_state *virtserv, const unsigned char *macaddress);

// Returns 1 if address is a listen address of the virtual service.
int virtservCheckAddress(struct s_virtserv_state *virtserv, const unsigned char *ipv6address);

// Decode Echo message.
int virtservDecodeEcho(struct s_virtserv_state *virtserv, unsigned char *outbuf, const int outbuf_len, const unsigned char *inbuf, const int inbuf_len);

// Decode UDP message.
int virtservDecodeUDPv6(struct s_virtserv_state *virtserv, unsigned char *outbuf, const int outbuf_len, const unsigned char *inbuf, const int inbuf_len);

// Decode ICMPv6 message.
int virtservDecodeICMPv6(struct s_virtserv_state *virtserv, unsigned char *outbuf, const int outbuf_len, const unsigned char *inbuf, const int inbuf_len);

// Decode frame for virtual service. Returns length of the response.
int virtservDecodeFrame(struct s_virtserv_state *virtserv, unsigned char *outframe, const int outframe_len, const unsigned char *inframe, const int inframe_len);


// Send frame to the virtual service. Returns length of the response.
int virtservFrame(struct s_virtserv_state *virtserv, unsigned char *outframe, const int outframe_len, const unsigned char *inframe, const int inframe_len);

// Create virtual service.
int virtservCreate(struct s_virtserv_state *virtserv);

// Destroy virtual service.
void virtservDestroy(struct s_virtserv_state *virtserv);

#endif
