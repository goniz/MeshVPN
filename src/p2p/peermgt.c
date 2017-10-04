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

#ifndef F_PEERMGT_C
#define F_PEERMGT_C

#include <time.h>
#include "p2p.h"


// Return number of connected peers.
int peermgtPeerCount(struct s_peermgt *mgt) {
	int n;
	n = (mapGetKeyCount(&mgt->map) - 1);
	return n;
}


// Check if PeerID is valid.
int peermgtIsValidID(struct s_peermgt *mgt, const int peerid) {
	if(!(peerid < 0)) {
		if(peerid < mapGetMapSize(&mgt->map)) {
			if(mapIsValidID(&mgt->map, peerid)) {
				return 1;
			}
		}
	}
	return 0;
}


// Check if PeerID is active (ready to send/recv data).
int peermgtIsActiveID(struct s_peermgt *mgt, const int peerid) {
	if(peermgtIsValidID(mgt, peerid)) {
		if(mgt->data[peerid].state == peermgt_STATE_COMPLETE) {
			return 1;
		}
	}
	return 0;
}


// Check if PeerID is active and matches the specified connection time.
int peermgtIsActiveIDCT(struct s_peermgt *mgt, const int peerid, const int conntime) {
	if(peermgtIsActiveID(mgt, peerid)) {
		if(mgt->data[peerid].conntime == conntime) {
			return 1;
		}
		else {
			return 0;
		}
	}
	else {
		return 0;
	}
}


// Check if PeerID is active and remote (> 0).
int peermgtIsActiveRemoteID(struct s_peermgt *mgt, const int peerid) {
	return ((peerid > 0) && (peermgtIsActiveID(mgt, peerid)));
}


// Check if PeerID is active, remote (> 0) and matches the specified connection time.
int peermgtIsActiveRemoteIDCT(struct s_peermgt *mgt, const int peerid, const int conntime) {
	return ((peerid > 0) && (peermgtIsActiveIDCT(mgt, peerid, conntime)));
}


// Check if indirect PeerAddr is valid.
int peermgtIsValidIndirectPeerAddr(struct s_peermgt *mgt, const struct s_peeraddr *addr) {
	int relayid;
	int relayct;
	if(peeraddrGetIndirect(addr, &relayid, &relayct, NULL)) {
		if(peermgtIsActiveRemoteIDCT(mgt, relayid, relayct)) {
			return 1;
		}
		else {
			return 0;
		}
	}
	else {
		return 0;
	}
}


// Return the next valid PeerID.
int peermgtGetNextID(struct s_peermgt *mgt) {
	return mapGetNextKeyID(&mgt->map);
}


// Return the next valid PeerID, starting from specified ID.
int peermgtGetNextIDN(struct s_peermgt *mgt, const int start) {
	return mapGetNextKeyIDN(&mgt->map, start);
}


// Get PeerID of NodeID. Returns -1 if it is not found.
int peermgtGetID(struct s_peermgt *mgt, const struct s_nodeid *nodeid) {
	return mapGetKeyID(&mgt->map, nodeid->id);
}


// Returns PeerID if active PeerID + PeerCT or NodeID is specified. Returns -1 if it is not found or both IDs are specified and don't match the same node.
int peermgtGetActiveID(struct s_peermgt *mgt, const struct s_nodeid *nodeid, const int peerid, const int peerct) {
	int outpeerid = -1;

	if(nodeid != NULL) {
		outpeerid = peermgtGetID(mgt, nodeid);
		if(outpeerid < 0) return -1;
	}
	if(!(peerid < 0)) {
		if(outpeerid < 0) {
			outpeerid = peerid;
		}
		else {
			if(peerid != outpeerid) return -1;
		}
	}
	if(!(outpeerid < 0)) {
		if(peermgtIsActiveIDCT(mgt, outpeerid, peerct)) {
			return outpeerid;
		}
	}

	return -1;
}


// Get NodeID of PeerID. Returns 1 on success.
int peermgtGetNodeID(struct s_peermgt *mgt, struct s_nodeid *nodeid, const int peerid) {
	unsigned char *ret;
	if(peermgtIsValidID(mgt, peerid)) {
		ret = mapGetKeyByID(&mgt->map, peerid);
		memcpy(nodeid->id, ret, nodeid_SIZE);
		return 1;
	}
	else {
		return 0;
	}
}


// Reset the data for an ID.
void peermgtResetID(struct s_peermgt *mgt, const int peerid) {
	mgt->data[peerid].state = peermgt_STATE_INVALID;
	memset(mgt->data[peerid].remoteaddr.addr, 0, peeraddr_SIZE);
	cryptoSetKeysRandom(&mgt->ctx[peerid], 1);
}


// Register new peer.
int peermgtNew(struct s_peermgt *mgt, const struct s_nodeid *nodeid, const struct s_peeraddr *addr) {
	int tnow = utilGetClock();
	int peerid = mapAddReturnID(&mgt->map, nodeid->id, &tnow);
	if(!(peerid < 0)) {
		mgt->data[peerid].state = peermgt_STATE_AUTHED;
		mgt->data[peerid].remoteaddr = *addr;
		mgt->data[peerid].conntime = tnow;
		mgt->data[peerid].lastrecv = tnow;
		mgt->data[peerid].lastsend = tnow;
		mgt->data[peerid].lastpeerinfo = tnow;
		mgt->data[peerid].lastpeerinfosendpeerid = peermgtGetNextID(mgt);
		seqInit(&mgt->data[peerid].seq, cryptoRand64());
		mgt->data[peerid].remoteflags = 0;
		return peerid;
	}
	return -1;
}


// Unregister a peer using its NodeID.
void peermgtDelete(struct s_peermgt *mgt, const struct s_nodeid *nodeid) {
	int peerid = peermgtGetID(mgt, nodeid);
	if(peerid > 0) { // don't allow special ID 0 to be deleted.
		mapRemove(&mgt->map, nodeid->id);
		peermgtResetID(mgt, peerid);
	}
}


// Unregister a peer using its ID.
void peermgtDeleteID(struct s_peermgt *mgt, const int peerid) {
	struct s_nodeid nodeid;
	if(peerid > 0 && peermgtGetNodeID(mgt, &nodeid, peerid)) {
		peermgtDelete(mgt, &nodeid);
	}
}


// Connect to a new peer.
int peermgtConnect(struct s_peermgt *mgt, const struct s_peeraddr *remote_addr) {
	if(remote_addr == NULL) {
        debug("failed to connect tot peer, remote_addr is NULL");
        return 0;
    }

    if(peeraddrIsInternal(remote_addr) && !peermgtIsValidIndirectPeerAddr(mgt, remote_addr)) {
        debug("failed to connect to peer because remote_addr is internal or not valid");
        return 0;
    }


    if(!authmgtStart(&mgt->authmgt, remote_addr)) {
        debug("failed to start AUTH connection");
        return 0;
    }

    CREATE_HUMAN_IP(remote_addr);
    debugf("New connection initiated to %s", humanIp);

    return 1;
}


// Enable/Disable loopback messages.
void peermgtSetLoopback(struct s_peermgt *mgt, const int enable) {
	if(enable) {
		mgt->loopback = 1;
	}
	else {
		mgt->loopback = 0;
	}
}


// Enable/disable fastauth (ignore send delay after auth status change).
void peermgtSetFastauth(struct s_peermgt *mgt, const int enable) {
	authmgtSetFastauth(&mgt->authmgt, enable);
}


// Enable/disable packet fragmentation.
void peermgtSetFragmentation(struct s_peermgt *mgt, const int enable) {
	mgt->fragmentation = (enable) ? 1 : 0;
}


// Set flags.
void peermgtSetFlags(struct s_peermgt *mgt, const int flags) {
	mgt->localflags = flags;
}


// Get single flag.
int peermgtGetFlag(struct s_peermgt *mgt, const int flag) {
	int f;
	f = (mgt->localflags & flag);
	return (f != 0);
}


// Get single remote flag.
int peermgtGetRemoteFlag(struct s_peermgt *mgt, const int peerid, const int flag) {
	int f;
	f = (mgt->data[peerid].remoteflags & flag);
	return (f != 0);
}


// Generate peerinfo packet.
void peermgtGenPacketPeerinfo(struct s_packet_data *data, struct s_peermgt *mgt, const int peerid) {
	const int peerinfo_size = (packet_PEERID_SIZE + nodeid_SIZE + peeraddr_SIZE);
	int peerinfo_max = mapGetKeyCount(&mgt->map);
	int peerinfo_count;
	int peerinfo_limit;
	int pos = 4;
	int i = 0;
	int infoid;
	unsigned char infocid[packet_PEERID_SIZE];
	struct s_nodeid infonid;

	// randomize maximum length of peerinfo packet
	if((abs(cryptoRandInt()) % 2) == 1) { peerinfo_limit = 7; } else { peerinfo_limit = 5; }

	// generate peerinfo entries
	peerinfo_count = 0;
	while((i < peerinfo_max) && (peerinfo_count < peerinfo_limit) && (pos + peerinfo_size < data->pl_buf_size)) {
		infoid = peermgtGetNextIDN(mgt, mgt->data[peerid].lastpeerinfosendpeerid);
		mgt->data[peerid].lastpeerinfosendpeerid = infoid;
		if((infoid > 0) && (mgt->data[infoid].state == peermgt_STATE_COMPLETE) && (!peeraddrIsInternal(&mgt->data[infoid].remoteaddr))) {
			utilWriteInt32(infocid, infoid);
			memcpy(&data->pl_buf[pos], infocid, packet_PEERID_SIZE);
			peermgtGetNodeID(mgt, &infonid, infoid);
			memcpy(&data->pl_buf[(pos + packet_PEERID_SIZE)], infonid.id, nodeid_SIZE);
			memcpy(&data->pl_buf[(pos + packet_PEERID_SIZE + nodeid_SIZE)], &mgt->data[infoid].remoteaddr.addr, peeraddr_SIZE);
			pos = pos + peerinfo_size;
			peerinfo_count++;
		}
		i++;
	}

	// write peerinfo_count
	utilWriteInt32(data->pl_buf, peerinfo_count);

	// set packet metadata
	data->pl_length = (4 + (peerinfo_count * peerinfo_size));
	data->pl_type = packet_PLTYPE_PEERINFO;
	data->pl_options = 0;
}


// Send ping to PeerAddr. Return 1 if successful.
int peermgtSendPingToAddr(struct s_peermgt *mgt, const struct s_nodeid *tonodeid, const int topeerid, const int topeerct, const struct s_peeraddr *peeraddr) {
	int outpeerid;
	unsigned char pingbuf[peermgt_PINGBUF_SIZE];

	outpeerid = peermgtGetActiveID(mgt, tonodeid, topeerid, topeerct);

	if(!(outpeerid > 0)) {
		return 0;
	}

	cryptoRand(pingbuf, 64); // generate ping message
	memcpy(mgt->rrmsg.msg, pingbuf, peermgt_PINGBUF_SIZE);
	mgt->rrmsgpeerid = outpeerid;
	mgt->rrmsgtype = packet_PLTYPE_PING;
	mgt->rrmsg.len = peermgt_PINGBUF_SIZE;
	mgt->rrmsgusetargetaddr = 1;
	mgt->rrmsgtargetaddr = *peeraddr;

	return 1;
}


// Generate next peer manager packet. Returns length if successful.
int peermgtGetNextPacketGen(struct s_peermgt *mgt, unsigned char *pbuf, const int pbuf_size, const int tnow, struct s_peeraddr *target) {
	int used = mapGetKeyCount(&mgt->map);
	int len;
	int outlen;
	int fragoutlen;
	int peerid;
	int usetargetaddr;
	int i;
	int j;
	int fragcount;
	int fragpos;
	const int plbuf_size = peermgt_MSGSIZE_MIN;
	unsigned char plbuf[plbuf_size];
	struct s_msg authmsg;
	struct s_packet_data data;
	struct s_nodeid *nodeid;
	struct s_peeraddr *peeraddr;

    CREATE_HUMAN_IP(target);

	// send out user data
	outlen = mgt->outmsg.len;
	fragoutlen = mgt->fragoutsize;
	if(outlen > 0 && (!(fragoutlen > 0))) {
		if(mgt->outmsgbroadcast) { // get PeerID for broadcast message
			do {
				peerid = peermgtGetNextID(mgt);
				mgt->outmsgbroadcastcount++;
			}
			while((!(peermgtIsActiveRemoteID(mgt, peerid) && peermgtGetRemoteFlag(mgt, peerid, peermgt_FLAG_USERDATA))) && (mgt->outmsgbroadcastcount < used));
			if(mgt->outmsgbroadcastcount >= used) {
				mgt->outmsgbroadcast = 0;
				mgt->outmsg.len = 0;
			}
		}
		else { // get PeerID for unicast message
			peerid = mgt->outmsgpeerid;
			mgt->outmsg.len = 0;
		}
		if(peermgtIsActiveRemoteID(mgt, peerid)) {  // check if session is active
			if(peermgtGetRemoteFlag(mgt, peerid, peermgt_FLAG_USERDATA)) {
				if((mgt->fragmentation > 0) && (outlen > peermgt_MSGSIZE_MIN)) {
					// start generating fragmented userdata packets
					mgt->fragoutpeerid = peerid;
					mgt->fragoutcount = (((outlen - 1) / peermgt_MSGSIZE_MIN) + 1); // calculate number of fragments
					mgt->fragoutsize = outlen;
					fragoutlen = outlen;
					mgt->fragoutpos = 0;
				}
				else {
					// generate userdata packet
					data.pl_buf = mgt->outmsg.msg;
					data.pl_buf_size = outlen;
					data.peerid = mgt->data[peerid].remoteid;
					data.seq = ++mgt->data[peerid].remoteseq;
					data.pl_length = outlen;
					data.pl_type = packet_PLTYPE_USERDATA;
					data.pl_options = 0;
					len = packetEncode(pbuf, pbuf_size, &data, &mgt->ctx[peerid]);
					if(len > 0) {
						mgt->data[peerid].lastsend = tnow;
						*target = mgt->data[peerid].remoteaddr;
						return len;
					}
				}
			}
		}
	}

	// send out fragments
	if(fragoutlen > 0) {
		fragcount = mgt->fragoutcount;
		fragpos = mgt->fragoutpos;
		peerid = mgt->fragoutpeerid;
		if(peermgtIsActiveRemoteID(mgt, peerid)) {  // check if session is active
			// generate fragmented packet
			data.pl_buf = &mgt->outmsg.msg[(fragpos * peermgt_MSGSIZE_MIN)];
			if(fragoutlen > peermgt_MSGSIZE_MIN) {
				// start or middle fragment
				data.pl_buf_size = peermgt_MSGSIZE_MIN;
				data.pl_length = peermgt_MSGSIZE_MIN;
				mgt->fragoutsize = (fragoutlen - peermgt_MSGSIZE_MIN);
			}
			else {
				// end fragment
				data.pl_buf_size = fragoutlen;
				data.pl_length = fragoutlen;
				mgt->fragoutsize = 0;
			}
			data.peerid = mgt->data[peerid].remoteid;
			data.seq = ++mgt->data[peerid].remoteseq;
			data.pl_type = packet_PLTYPE_USERDATA_FRAGMENT;
			data.pl_options = (fragcount << 4) | (fragpos);
			len = packetEncode(pbuf, pbuf_size, &data, &mgt->ctx[peerid]);
			mgt->fragoutpos = (fragpos + 1);
			if(len > 0) {
				mgt->data[peerid].lastsend = tnow;
				*target = mgt->data[peerid].remoteaddr;
				return len;
			}
		}
		else {
			// session not active anymore, abort sending fragments
			mgt->fragoutsize = 0;
		}
	}

	// send out request-response packet
	outlen = mgt->rrmsg.len;
	if(outlen > 0) {
		peerid = mgt->rrmsgpeerid;
		usetargetaddr = mgt->rrmsgusetargetaddr;
		mgt->rrmsg.len = 0;
		mgt->rrmsgusetargetaddr = 0;
		if((outlen < peermgt_MSGSIZE_MAX) && (peermgtIsActiveRemoteID(mgt, peerid))) {  // check if session is active
			data.pl_buf = mgt->rrmsg.msg;
			data.pl_buf_size = peermgt_MSGSIZE_MAX;
			data.pl_length = outlen;
			data.pl_type = mgt->rrmsgtype;
			data.pl_options = 0;
			data.peerid = mgt->data[peerid].remoteid;
			data.seq = ++mgt->data[peerid].remoteseq;

			len = packetEncode(pbuf, pbuf_size, &data, &mgt->ctx[peerid]);
			if(len > 0) {
				if(usetargetaddr > 0) {
					*target = mgt->rrmsgtargetaddr;
				}
				else {
					mgt->data[peerid].lastsend = tnow;
					*target = mgt->data[peerid].remoteaddr;
				}
				return len;
			}
		}
	}

	// send peerinfo to peers
	for(i=0; i<used; i++) {
		peerid = peermgtGetNextID(mgt);
		if(peerid > 0) {
			if((tnow - mgt->data[peerid].lastrecv) < peermgt_RECV_TIMEOUT) { // check if session has expired
				if(mgt->data[peerid].state == peermgt_STATE_COMPLETE) {  // check if session is active
					if(((tnow - mgt->data[peerid].lastsend) > peermgt_KEEPALIVE_INTERVAL) || ((tnow - mgt->data[peerid].lastpeerinfo) > peermgt_PEERINFO_INTERVAL)) { // check if we should send peerinfo packet
						data.pl_buf = plbuf;
						data.pl_buf_size = plbuf_size;
						data.peerid = mgt->data[peerid].remoteid;
						data.seq = ++mgt->data[peerid].remoteseq;
						peermgtGenPacketPeerinfo(&data, mgt, peerid);
						len = packetEncode(pbuf, pbuf_size, &data, &mgt->ctx[peerid]);
						if(len > 0) {
							mgt->data[peerid].lastsend = tnow;
							mgt->data[peerid].lastpeerinfo = tnow;
							*target = mgt->data[peerid].remoteaddr;
							return len;
						}
					}
				}
			}
			else {
				peermgtDeleteID(mgt, peerid);
			}
		}
	}

	// send auth manager message
	if(authmgtGetNextMsg(&mgt->authmgt, &authmsg, target)) {
		data.pl_buf = authmsg.msg;
		data.pl_buf_size = authmsg.len;
		data.peerid = 0;
		data.seq = 0;
		data.pl_length = authmsg.len;
		if(data.pl_length > 0) {
			data.pl_type = packet_PLTYPE_AUTH;
			data.pl_options = 0;
			len = packetEncode(pbuf, pbuf_size, &data, &mgt->ctx[0]);
			if(len > 0) {
				mgt->data[0].lastsend = tnow;
				return len;
			}
		}
	}

	// connect new peer
	if((tnow - mgt->lastconntry) > 0) { // limit to one per second
		mgt->lastconntry = tnow;
		i = -1;

		// find a NodeID and PeerAddr pair in NodeDB
		if(authmgtUsedSlotCount(&mgt->authmgt) <= (authmgtSlotCount(&mgt->authmgt) / 2)) {
			i = nodedbGetDBID(&mgt->nodedb, NULL, peermgt_NEWCONNECT_MAX_LASTSEEN, -1, peermgt_NEWCONNECT_MIN_LASTCONNTRY);
			if((i < 0) && (authmgtUsedSlotCount(&mgt->authmgt) <= (authmgtSlotCount(&mgt->authmgt) / 8))) {
				i = nodedbGetDBID(&mgt->nodedb, NULL, peermgt_NEWCONNECT_MAX_LASTSEEN, -1, -1);
				if((i < 0) && (authmgtUsedSlotCount(&mgt->authmgt) <= (authmgtSlotCount(&mgt->authmgt) / 16))) {
					i = nodedbGetDBID(&mgt->nodedb, NULL, -1, -1, -1);
				}
			}
		}

		// start connection attempt if a node is found
		if(!(i < 0)) {
			nodeid = nodedbGetNodeID(&mgt->nodedb, i);
			peerid = peermgtGetID(mgt, nodeid);
			peeraddr = nodedbGetNodeAddress(&mgt->nodedb, i);
			nodedbUpdate(&mgt->nodedb, nodeid, peeraddr, 0, 0, 1);
			if(peerid < 0) { // node is not connected yet
				if(peermgtConnect(mgt, peeraddr)) { // try to connect
                    debugf("Trying to connect with %s", humanIp);

					j = nodedbGetDBID(&mgt->relaydb, nodeid, peermgt_NEWCONNECT_RELAY_MAX_LASTSEEN, -1, peermgt_NEWCONNECT_MIN_LASTCONNTRY);
					if(!(j < 0)) {
						peermgtConnect(mgt, nodedbGetNodeAddress(&mgt->relaydb, j)); // try to connect via relay
						nodedbUpdate(&mgt->relaydb, nodeid, nodedbGetNodeAddress(&mgt->relaydb, j), 0, 0, 1);
					}
				}
			}
			else { // node is already connected
				if(peermgtIsActiveRemoteID(mgt, peerid)) {
					if(peeraddrIsInternal(&mgt->data[peerid].remoteaddr)) { // node connection is indirect
						peermgtSendPingToAddr(mgt, NULL, peerid, mgt->data[peerid].conntime, peeraddr); // try to switch peer to a direct connection
					}
				}
			}
		}

	}

	return 0;
}


// Get next peer manager packet. Also encapsulates packets for relaying if necessary. Returns length if successful.
int peermgtGetNextPacket(struct s_peermgt *mgt, unsigned char *pbuf, const int pbuf_size, struct s_peeraddr *target) {
	int tnow;
	int outlen;
	int relayid;
	int relayct;
	int relaypeerid;
	int depth;
	struct s_packet_data data;
	tnow = utilGetClock();
	while((outlen = (peermgtGetNextPacketGen(mgt, pbuf, pbuf_size, tnow, target))) > 0) {
		depth = 0;
		while(outlen > 0) {
			if(depth < peermgt_DECODE_RECURSION_MAX_DEPTH) { // limit encapsulation depth
				if(!peeraddrIsInternal(target)) {
					// address is external, packet is ready for sending
					return outlen;
				}
				else {
					if(((packet_PEERID_SIZE + outlen) < peermgt_MSGSIZE_MAX) && (peeraddrGetIndirect(target, &relayid, &relayct, &relaypeerid))) {
						// address is indirect, encapsulate packet for relaying
						if(peermgtIsActiveRemoteIDCT(mgt, relayid, relayct)) {
							// generate relay-in packet
							utilWriteInt32(&mgt->relaymsgbuf[0], relaypeerid);
							memcpy(&mgt->relaymsgbuf[packet_PEERID_SIZE], pbuf, outlen);
							data.pl_buf = mgt->relaymsgbuf;
							data.pl_buf_size = packet_PEERID_SIZE + outlen;
							data.peerid = mgt->data[relayid].remoteid;
							data.seq = ++mgt->data[relayid].remoteseq;
							data.pl_length = packet_PEERID_SIZE + outlen;
							data.pl_type = packet_PLTYPE_RELAY_IN;
							data.pl_options = 0;

							// encode relay-in packet
							outlen = packetEncode(pbuf, pbuf_size, &data, &mgt->ctx[relayid]);
							if(outlen > 0) {
								mgt->data[relayid].lastsend = tnow;
								*target = mgt->data[relayid].remoteaddr;
							}
							else {
								outlen = 0;
							}
						}
						else {
							outlen = 0;
						}
					}
					else {
						outlen = 0;
					}
				}
				depth++;
			}
			else {
				outlen = 0;
			}
		}
	}
	return 0;
}


// Decode auth packet
int peermgtDecodePacketAuth(struct s_peermgt *mgt, const struct s_packet_data *data, const struct s_peeraddr *source_addr) {
	int tnow = utilGetClock();
	struct s_authmgt *authmgt = &mgt->authmgt;
	struct s_nodeid peer_nodeid;
	int peerid;
	int dupid;
    char humanIp[60];
    peeraddrToHuman(humanIp, source_addr);

	int64_t remoteflags = 0;

    debugf("[%s] PeerID: %d AUTH message", humanIp, peerid);
	if(!authmgtDecodeMsg(authmgt, data->pl_buf, data->pl_length, source_addr)) {
        debugf("[%s] Wrong AUTH message", humanIp);
        return 0;
    }

    if(authmgtGetAuthedPeerNodeID(authmgt, &peer_nodeid)) {
        dupid = peermgtGetID(mgt, &peer_nodeid);
        if(dupid < 0) {
            // Create new PeerID.
            peerid = peermgtNew(mgt, &peer_nodeid, source_addr);
        }
        else {
            // Don't replace active existing session.
            peerid = -1;

            // Upgrade indirect connection to a direct one
            if((peeraddrIsInternal(&mgt->data[dupid].remoteaddr)) && (!peeraddrIsInternal(source_addr))) {
                mgt->data[dupid].remoteaddr = *source_addr;
                peermgtSendPingToAddr(mgt, NULL, dupid, mgt->data[dupid].conntime, source_addr); // send a ping using the new peer address
            }
        }
        if(peerid > 0) {
            // NodeID gets accepted here.
            authmgtAcceptAuthedPeer(authmgt, peerid, seqGet(&mgt->data[peerid].seq), mgt->localflags);
        }
        else {
            // Reject authentication attempt because local PeerID could not be generated.
            authmgtRejectAuthedPeer(authmgt);
        }
    }
    if(authmgtGetCompletedPeerNodeID(authmgt, &peer_nodeid)) {
        peerid = peermgtGetID(mgt, &peer_nodeid);
        if((peerid > 0) && (mgt->data[peerid].state >= peermgt_STATE_AUTHED) && (authmgtGetCompletedPeerLocalID(authmgt)) == peerid) {
            // Node data gets completed here.
            authmgtGetCompletedPeerAddress(authmgt, &mgt->data[peerid].remoteid, &mgt->data[peerid].remoteaddr);
            authmgtGetCompletedPeerSessionKeys(authmgt, &mgt->ctx[peerid]);
            authmgtGetCompletedPeerConnectionParams(authmgt, &mgt->data[peerid].remoteseq, &remoteflags);

            mgt->data[peerid].remoteflags = remoteflags;
            mgt->data[peerid].state = peermgt_STATE_COMPLETE;
            mgt->data[peerid].lastrecv = tnow;
        }
        authmgtFinishCompletedPeer(authmgt);
    }
    return 1;
}


// Decode peerinfo packet
int peermgtDecodePacketPeerinfo(struct s_peermgt *mgt, const struct s_packet_data *data) {
	const int peerinfo_size = (packet_PEERID_SIZE + nodeid_SIZE + peeraddr_SIZE);
	struct s_nodeid nodeid;
	struct s_peeraddr addr;
	int peerid;
	int peerinfo_count;
	int peerinfo_max;
	int pos;
	int relaypeerid;
	int i;
	int64_t r;

    debug("PEERINFO packet received");
	if(data->pl_length <= 4) {
        debugf("PEERINFO packet size is too small: %d bytes", data->pl_length);
        return 0;
    }

    peerid = data->peerid;
    if(!peermgtIsActiveRemoteID(mgt, peerid)) {
        debugf("PeerID %d is not active, failed to proceed PEERINFO", peerid);
        return 0;
    }

    peerinfo_max = ((data->pl_length - 4) / peerinfo_size);
    peerinfo_count = utilReadInt32(data->pl_buf);
    if(peerinfo_count > 0 && peerinfo_count <= peerinfo_max) {
        r = (abs(cryptoRandInt()) % peerinfo_count); // randomly select a peer
        for(i=0; i<peerinfo_count; i++) {
            pos = (4 + (r * peerinfo_size));
            relaypeerid = utilReadInt32(&data->pl_buf[pos]);
            memcpy(nodeid.id, &data->pl_buf[(pos + (packet_PEERID_SIZE))], nodeid_SIZE);
            memcpy(addr.addr, &data->pl_buf[(pos + (packet_PEERID_SIZE + nodeid_SIZE))], peeraddr_SIZE);
            if(!peeraddrIsInternal(&addr)) { // only accept external PeerAddr
                nodedbUpdate(&mgt->nodedb, &nodeid, &addr, 1, 0, 0);
                if(peermgtGetRemoteFlag(mgt, peerid, peermgt_FLAG_RELAY)) { // add relay data
                    peeraddrSetIndirect(&addr, peerid, mgt->data[peerid].conntime, relaypeerid);
                    nodedbUpdate(&mgt->relaydb, &nodeid, &addr, 1, 0, 0);
                }
            }
            r = ((r + 1) % peerinfo_count);
        }
        return 1;
    }

	return 0;
}


// Decode ping packet
int peermgtDecodePacketPing(struct s_peermgt *mgt, const struct s_packet_data *data) {
	int len = data->pl_length;
	if(len != peermgt_PINGBUF_SIZE) {
        debug("wrong PEERPING packet");
        return 0;
    }

    memcpy(mgt->rrmsg.msg, data->pl_buf, peermgt_PINGBUF_SIZE);
    mgt->rrmsgpeerid = data->peerid;
    mgt->rrmsgtype = packet_PLTYPE_PONG;
    mgt->rrmsg.len = peermgt_PINGBUF_SIZE;
    mgt->rrmsgusetargetaddr = 0;
    debugf("PEERPING packet decoded from %d", data->peerid);
    return 1;
}


// Decode pong packet
int peermgtDecodePacketPong(struct s_peermgt *mgt, const struct s_packet_data *data) {
	int len = data->pl_length;
	if(len != peermgt_PINGBUF_SIZE) {
        debugf("wrong size of PEERPONG packet, got %d bytes", data->pl_length);
        return 0;
    }

    // content is not checked, any response is acceptable
    return 1;
}


// Decode relay-in packet
int peermgtDecodePacketRelayIn(struct s_peermgt *mgt, const struct s_packet_data *data) {
	int targetpeerid;
	int len = data->pl_length;

	if((len > 4) && (len < (peermgt_MSGSIZE_MAX - 4))) {
		targetpeerid = utilReadInt32(data->pl_buf);
		if(peermgtIsActiveRemoteID(mgt, targetpeerid)) {
			utilWriteInt32(&mgt->rrmsg.msg[0], data->peerid);
			memcpy(&mgt->rrmsg.msg[4], &data->pl_buf[4], (len - 4));
			mgt->rrmsgpeerid = targetpeerid;
			mgt->rrmsgtype = packet_PLTYPE_RELAY_OUT;
			mgt->rrmsg.len = len;
			mgt->rrmsgusetargetaddr = 0;
			return 1;
		}
	}

	return 0;
}


// Decode fragmented packet
int peermgtDecodeUserdataFragment(struct s_peermgt *mgt, struct s_packet_data *data) {
	int fragcount = (data->pl_options >> 4);
	int fragpos = (data->pl_options & 0x0F);
	int64_t fragseq = (data->seq - (int64_t)fragpos);
	int peerid = data->peerid;
	int id = dfragAssemble(&mgt->dfrag, mgt->data[peerid].conntime, peerid, fragseq, data->pl_buf, data->pl_length, fragpos, fragcount);
	int len;
	if(!(id < 0)) {
		len = dfragLength(&mgt->dfrag, id);
		if(len > 0 && len <= data->pl_buf_size) {
			memcpy(data->pl_buf, dfragGet(&mgt->dfrag, id), len);
			dfragClear(&mgt->dfrag, id);
			data->pl_length = len;
			return 1;
		}
		else {
			dfragClear(&mgt->dfrag, id);
			data->pl_length = 0;
			return 0;
		}
	}
	else {
		return 0;
	}
}


// Decode input packet recursively. Decapsulates relayed packets if necessary.
int peermgtDecodePacketRecursive(struct s_peermgt *mgt, const unsigned char *packet, const int packet_len, const struct s_peeraddr *source_addr, const int tnow, const int depth) {
	int ret;
	int peerid;
	struct s_packet_data data = { .pl_buf_size = peermgt_MSGSIZE_MAX, .pl_buf = mgt->msgbuf };
	struct s_peeraddr indirect_addr;
	struct s_nodeid peer_nodeid;

    CREATE_HUMAN_IP(source_addr);

	ret = 0;

	if(packet_len <= (packet_PEERID_SIZE + packet_HMAC_SIZE) || (depth >= peermgt_DECODE_RECURSION_MAX_DEPTH)) {
        debugf("Wrong packets size (%d) or recursion depth (%d) from %s", packet_len, depth, humanIp);
        return 0;
    }

    peerid = packetGetPeerID(packet);

    // proceed inactive peers
    if(!peermgtIsActiveID(mgt, peerid)) {
        debugf("failed to proceed packet for inactive peerid: %d, IP: %s", peerid, humanIp);
        return 0;
    }

    if(peerid == 0) {
        // packet has an anonymous PeerID
        if(packetDecode(&data, packet, packet_len, &mgt->ctx[0], NULL) <= 0) {
            debugf("failed to decode packet from anonymous peer, IP: %s", humanIp);
            return 0;
        }

        switch(data.pl_type) {
            case packet_PLTYPE_AUTH:
                return peermgtDecodePacketAuth(mgt, &data, source_addr);
            default:
                return 0;
        }
    }

    if(peerid <= 0) {
        debugf("denied packet from invalid PeerID: %d", peerid);
        return 0;
    }

    // packet has an active PeerID
    mgt->msgsize = 0;
    if(packetDecode(&data, packet, packet_len, &mgt->ctx[peerid], &mgt->data[peerid].seq) <= 0) {
        debugf("failed to decode packet from PeerID: %d, size: %d, IP: %s", peerid, packet_len, humanIp);
        return 0;
    }

    if(!((data.pl_length > 0) && (data.pl_length < peermgt_MSGSIZE_MAX))) {
        debugf("bad packet from PeerID: %d", peerid);
        return 0;
    }

    switch(data.pl_type) {
        case PACKET_PLTYPE_USERDATA:
            if(!peermgtGetFlag(mgt, peermgt_FLAG_USERDATA)) {
                return 0;
            }
            ret = 1;
            mgt->msgsize = data.pl_length;
            mgt->msgpeerid = data.peerid;
            break;
        case PACKET_PLTYPE_USERDATA_FRAGMENT:
            if(!peermgtGetFlag(mgt, peermgt_FLAG_USERDATA)) {
                return 0;
            }
            ret = peermgtDecodeUserdataFragment(mgt, &data);
            if(ret > 0) {
                mgt->msgsize = data.pl_length;
                mgt->msgpeerid = data.peerid;
            }

            break;
        case PACKET_PLTYPE_PEERINFO:
            ret = peermgtDecodePacketPeerinfo(mgt, &data);
            break;
        case PACKET_PLTYPE_PING:
            debugf("ping packet from %s", humanIp);
            ret = peermgtDecodePacketPing(mgt, &data);
            break;
        case PACKET_PLTYPE_PONG:
            debugf("pong packet from %s", humanIp);
            ret = peermgtDecodePacketPong(mgt, &data);
            break;
        case PACKET_PLTYPE_RELAY_IN:
            if(!peermgtGetFlag(mgt, peermgt_FLAG_RELAY)) {
                return 0;
            }
            ret = peermgtDecodePacketRelayIn(mgt, &data);
            break;
        case PACKET_PLTYPE_RELAY_OUT:
            if(data.pl_length > packet_PEERID_SIZE) {
                memcpy(mgt->relaymsgbuf, &data.pl_buf[4], (data.pl_length - packet_PEERID_SIZE));
                peeraddrSetIndirect(&indirect_addr, peerid, mgt->data[peerid].conntime, utilReadInt32(&data.pl_buf[0])); // generate indirect PeerAddr
                ret = peermgtDecodePacketRecursive(mgt, mgt->relaymsgbuf, (data.pl_length - packet_PEERID_SIZE), &indirect_addr, tnow, (depth + 1)); // decode decapsulated packet
            }
            break;
        default:
            return 0;
            break;
    }

    if(ret <= 0) {
        return 0;
    }

    if(mgt->data[peerid].lastrecv != tnow) { // Update NodeDB (maximum once per second).
        if(!peeraddrIsInternal(&mgt->data[peerid].remoteaddr)) { // do not pollute NodeDB with internal addresses
            if(peermgtGetNodeID(mgt, &peer_nodeid, peerid)) {
                nodedbUpdate(&mgt->nodedb, &peer_nodeid, &mgt->data[peerid].remoteaddr, 1, 1, 0);
            }
        }
    }
    mgt->data[peerid].lastrecv = tnow;
    mgt->data[peerid].remoteaddr = *source_addr;
    return 1;
}


// Decode input packet. Returns 1 on success.
int peermgtDecodePacket(struct s_peermgt *mgt, const unsigned char *packet, const int packet_len, const struct s_peeraddr *source_addr) {
	int tnow;
	tnow = utilGetClock();
	return peermgtDecodePacketRecursive(mgt, packet, packet_len, source_addr, tnow, 0);
}


// Return received user data. Return 1 if successful.
int peermgtRecvUserdata(struct s_peermgt *mgt, struct s_msg *recvmsg, struct s_nodeid *fromnodeid, int *frompeerid, int *frompeerct) {
	if((mgt->msgsize > 0) && (recvmsg != NULL)) {
		recvmsg->msg = mgt->msgbuf;
		recvmsg->len = mgt->msgsize;
		if(fromnodeid != NULL) peermgtGetNodeID(mgt, fromnodeid, mgt->msgpeerid);
		if(frompeerid != NULL) *frompeerid = mgt->msgpeerid;
		if(frompeerct != NULL) {
			if(peermgtIsActiveID(mgt, mgt->msgpeerid)) {
				*frompeerct = mgt->data[mgt->msgpeerid].conntime;
			}
			else {
				*frompeerct = 0;
			}
		}
		mgt->msgsize = 0;
		return 1;
	}
	else {
		return 0;
	}
}


// Send user data. Return 1 if successful.
int peermgtSendUserdata(struct s_peermgt *mgt, const struct s_msg *sendmsg, const struct s_nodeid *tonodeid, const int topeerid, const int topeerct) {
	int outpeerid;

	mgt->outmsgbroadcast = 0;
	mgt->outmsg.len = 0;
	if(sendmsg != NULL) {
		if((sendmsg->len > 0) && (sendmsg->len <= peermgt_MSGSIZE_MAX)) {
			outpeerid = peermgtGetActiveID(mgt, tonodeid, topeerid, topeerct);
			if(outpeerid >= 0) {
				if(outpeerid > 0) {
					// message goes out
					mgt->outmsg.msg = sendmsg->msg;
					mgt->outmsg.len = sendmsg->len;
					mgt->outmsgpeerid = outpeerid;
					return 1;
				}
				else {
					// message goes to loopback
					if(mgt->loopback) {
						memcpy(mgt->msgbuf, sendmsg->msg, sendmsg->len);
						mgt->msgsize = sendmsg->len;
						mgt->msgpeerid = outpeerid;
						return 1;
					}
				}
			}
		}
	}
	return 0;
}


// Send user data to all connected peers. Return 1 if successful.
int peermgtSendBroadcastUserdata(struct s_peermgt *mgt, const struct s_msg *sendmsg) {
	mgt->outmsgbroadcast = 0;
	mgt->outmsg.len = 0;
	if(sendmsg != NULL) {
		if((sendmsg->len > 0) && (sendmsg->len <= peermgt_MSGSIZE_MAX)) {
			mgt->outmsg.msg = sendmsg->msg;
			mgt->outmsg.len = sendmsg->len;
			mgt->outmsgpeerid = -1;
			mgt->outmsgbroadcast = 1;
			mgt->outmsgbroadcastcount = 0;
			return 1;
		}
	}
	return 0;
}


// Set NetID from network name.
int peermgtSetNetID(struct s_peermgt *mgt, const char *netname, const int netname_len) {
	return netidSet(&mgt->netid, netname, netname_len);
}


// Set shared group password.
int peermgtSetPassword(struct s_peermgt *mgt, const char *password, const int password_len) {
	return cryptoSetSessionKeysFromPassword(&mgt->ctx[0], (const unsigned char *)password, password_len, crypto_AES256, crypto_SHA256);
}


// Initialize peer manager object.
int peermgtInit(struct s_peermgt *mgt) {
	const char *defaultpw = "default";
	int tnow;
	int i;
	int s = mapGetMapSize(&mgt->map);
	struct s_peeraddr empty_addr;
	struct s_nodeid *local_nodeid = &mgt->nodekey->nodeid;

	mgt->msgsize = 0;
	mgt->loopback = 0;
	mgt->outmsg.len = 0;
	mgt->outmsgbroadcast = 0;
	mgt->outmsgbroadcastcount = 0;
	mgt->rrmsg.len = 0;
	mgt->rrmsgpeerid = 0;
	mgt->rrmsgusetargetaddr = 0;
	mgt->fragoutpeerid = 0;
	mgt->fragoutcount = 0;
	mgt->fragoutsize = 0;
	mgt->fragoutpos = 0;
	mgt->localflags = 0;

	for(i=0; i<s; i++) {
		mgt->data[i].state = peermgt_STATE_INVALID;
	}

	memset(empty_addr.addr, 0, peeraddr_SIZE);
	mapInit(&mgt->map);
	authmgtReset(&mgt->authmgt);
	nodedbInit(&mgt->nodedb);
	nodedbInit(&mgt->relaydb);

	if(peermgtNew(mgt, local_nodeid, &empty_addr) == 0) { // ID 0 should always represent local NodeID
		if(peermgtGetID(mgt, local_nodeid) == 0) {
			if(peermgtSetNetID(mgt, defaultpw, 7) && peermgtSetPassword(mgt, defaultpw, 7)) {
				mgt->data[0].state = peermgt_STATE_COMPLETE;
				tnow = utilGetClock();
				mgt->tinit = tnow;
				mgt->lastconntry = tnow;

				return 1;
			}
		}
	}

	return 0;
}


// Return peer manager uptime in seconds.
int peermgtUptime(struct s_peermgt *mgt) {
	int uptime = utilGetClock() - mgt->tinit;
	return uptime;
}


// Generate peer manager status report.
void peermgtStatus(struct s_peermgt *mgt, char *report, const int report_len) {
	int tnow = utilGetClock();
	int pos = 0;
	int size = mapGetMapSize(&mgt->map);
	int maxpos = (((size + 2) * (160)) + 1);
	unsigned char infoid[packet_PEERID_SIZE];
	unsigned char infostate[1];
	unsigned char infoflags[2];
	unsigned char inforq[1];
	unsigned char timediff[4];
	struct s_nodeid nodeid;
	int i = 0;

	if(maxpos > report_len) { maxpos = report_len; }

	memcpy(&report[pos], "PeerID    NodeID                                                            Address                                       Status  LastPkt   SessAge   Flag  RQ", 158);
	pos = pos + 158;
	report[pos++] = '\n';

	while(i < size && pos < maxpos) {
		if(peermgtGetNodeID(mgt, &nodeid, i)) {
			utilWriteInt32(infoid, i);
			utilByteArrayToHexstring(&report[pos], ((packet_PEERID_SIZE * 2) + 2), infoid, packet_PEERID_SIZE);
			pos = pos + (packet_PEERID_SIZE * 2);
			report[pos++] = ' ';
			report[pos++] = ' ';
			utilByteArrayToHexstring(&report[pos], ((nodeid_SIZE * 2) + 2), nodeid.id, nodeid_SIZE);
			pos = pos + (nodeid_SIZE * 2);
			report[pos++] = ' ';
			report[pos++] = ' ';
			utilByteArrayToHexstring(&report[pos], ((peeraddr_SIZE * 2) + 2), mgt->data[i].remoteaddr.addr, peeraddr_SIZE);
			pos = pos + (peeraddr_SIZE * 2);
			report[pos++] = ' ';
			report[pos++] = ' ';
			infostate[0] = mgt->data[i].state;
			utilByteArrayToHexstring(&report[pos], 4, infostate, 1);
			pos = pos + 2;
			report[pos++] = ' ';
			report[pos++] = ' ';
			utilWriteInt32(timediff, (tnow - mgt->data[i].lastrecv));
			utilByteArrayToHexstring(&report[pos], 10, timediff, 4);
			pos = pos + 8;
			report[pos++] = ' ';
			report[pos++] = ' ';
			utilWriteInt32(timediff, (tnow - mgt->data[i].conntime));
			utilByteArrayToHexstring(&report[pos], 10, timediff, 4);
			pos = pos + 8;
			report[pos++] = ' ';
			report[pos++] = ' ';
			utilWriteInt16(infoflags, mgt->data[i].remoteflags);
			utilByteArrayToHexstring(&report[pos], 6, infoflags, 2);
			pos = pos + 4;
			report[pos++] = ' ';
			report[pos++] = ' ';
			inforq[0] = seqRQ(&mgt->data[i].seq);
			utilByteArrayToHexstring(&report[pos], 4, inforq, 1);
			pos = pos + 2;
			report[pos++] = '\n';
		}
		i++;
	}
	report[pos++] = '\0';
}


// Create peer manager object.
// @NOTE: i'm not going to clean resources during failed init because whole app will break down if something goes wrong
int peermgtCreate(struct s_peermgt *mgt, const int peer_slots, const int auth_slots, struct s_nodekey *local_nodekey, struct s_dh_state *dhstate) {
	const char *defaultid = "default";
	struct s_peermgt_data *data_mem;
	struct s_crypto *ctx_mem;

	if(peer_slots <= 0 || auth_slots <= 0  || !peermgtSetNetID(mgt, defaultid, 7)) {
        debugf("Failed to create PeerMgr, peer_slots: %d, auth_slots: %d", peer_slots, auth_slots);
        return 0;
    }

    data_mem = malloc(sizeof(struct s_peermgt_data) * (peer_slots + 1));
    if(data_mem == NULL) {
        debug("failed to allocate memory for s_peermgt_data");
        return 0;
    }

    ctx_mem = malloc(sizeof(struct s_crypto) * (peer_slots + 1));
    if(ctx_mem == NULL) {
        debug("failed to allocate memory for s_crypto");
    }

    if(!cryptoCreate(ctx_mem, (peer_slots + 1))) {
        debug("failed to create crypto engine");
        return 0;
    }

    if(!dfragCreate(&mgt->dfrag, peermgt_MSGSIZE_MIN, peermgt_FRAGBUF_COUNT)) {
        debug("failed to create defrag");
        return 0;
    }

    if(!authmgtCreate(&mgt->authmgt, &mgt->netid, auth_slots, local_nodekey, dhstate)) {
        debug("failed to create authmgt");
        return 0;
    }

    if(!nodedbCreate(&mgt->relaydb, (peer_slots + 1), peermgt_RELAYDB_NUM_PEERADDRS)) {
        debug("failed to create NodeDB for relays");
        return 0;
    }

    if(!nodedbCreate(&mgt->nodedb, ((peer_slots * 8) + 1), peermgt_NODEDB_NUM_PEERADDRS)) {
        debug("failed to create NodeDB for peers");
        return 0;
    }

    if(!mapCreate(&mgt->map, (peer_slots + 1), NODEID_SIZE, 1)) {
        debug("failed to create map");
        return 0;
    }


    mgt->nodekey = local_nodekey;
    mgt->data = data_mem;
    mgt->ctx = ctx_mem;
    mgt->rrmsg.msg = mgt->rrmsgbuf;


    return peermgtInit(mgt);
}


// Destroy peer manager object.
void peermgtDestroy(struct s_peermgt *mgt) {
	int size = mapGetMapSize(&mgt->map);
	mapDestroy(&mgt->map);
	nodedbDestroy(&mgt->nodedb);
	nodedbDestroy(&mgt->relaydb);
	authmgtDestroy(&mgt->authmgt);
	dfragDestroy(&mgt->dfrag);
	cryptoDestroy(mgt->ctx, size);
	free(mgt->ctx);
	free(mgt->data);
}


#endif // F_PEERMGT_C
