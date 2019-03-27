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

#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "logging.h"
#include "globals.h"
#include "io.h"
#include "p2p.h"
#include "map.h"
#include "console.h"
#include "platform.h"

extern struct s_p2psec *g_p2psec;

static int isEtherMeshVPNFrame(unsigned char* msg_buf, int msg_len);

// Connect initpeers.
void connectInitpeers(struct s_initpeers * peers) {
	char *hostname = NULL;
	char *port = NULL;
	struct s_io_addrinfo new_peeraddrs;

    int i = 0;
    for(i = 0; i < peers->count; i++) {
        debugf("connecting new peer %d", i );
        if(p2psecConnect(g_p2psec,peers->addresses[i].addr)) {
            msgf("initiated new connection");
        } else {
            msgf("failed to initiate connection");
        }
    }
}


// the mainloop
void mainLoop(struct s_initpeers * peers) {
	int fd;
	int tnow;
	unsigned char sockdata_buf[4096];
	int sockdata_len;
	int sockdata_lastlen;
	unsigned char tapmsg_buf[1024];
	int tapmsg_len;
	unsigned char *msg;
	unsigned char *msg_buf;
	int msg_len;
	int msg_offset;
	int msg_ok;
	int lastinit = 0;
	int laststatus = 0;
	int lastconnectcount = -1;
	int connectcount = 0;
	int do_broadcast = 0;
	int ndp_peerid = 0;
	int ndp_peerct = 0;
	int frametype;
	int source_peerid;
	int source_peerct;
	struct s_io_addr new_peeraddr;

	msg_len = 0;
	sockdata_len = 0;
	sockdata_lastlen = 0;
	tapmsg_len = 0;

	while(g_mainloop) {
		tnow = utilGetClock();

		// read all fds
		ioReadAll(&iostate);

		// check udp sockets
		while(!((fd = (ioGetGroup(&iostate, IOGRP_SOCKET))) < 0)) {
			if(p2psecInputPacket(g_p2psec, ioGetData(&iostate, fd), ioGetDataLen(&iostate, fd), ioGetAddr(&iostate, fd)->addr)) {
				// output frames to tap device
				msg = p2psecRecvMSGFromPeerID(g_p2psec, &source_peerid, &source_peerct, &msg_len);
				if(msg != NULL && msg_len > 12 && g_enableeth > 0) {
					switchFrameIn(&g_switchstate, msg, msg_len, source_peerid, source_peerct);
					ndp6PacketIn(&g_ndpstate, msg, msg_len, source_peerid, source_peerct);
					if(!(ioWriteGroup(&iostate, IOGRP_TAP, msg, msg_len, NULL) > 0)) {
						debug("could not write to tap device!");
					}
				}

				// output packets
				while((sockdata_len = (p2psecOutputPacket(g_p2psec, sockdata_buf, 4096, new_peeraddr.addr))) > 0) {
					sockdata_lastlen = sockdata_len;
					if(!(ioWriteGroup(&iostate, IOGRP_SOCKET, sockdata_buf, sockdata_len, &new_peeraddr) > 0)) {
						debug("could not send packet!");
					}
				}
			}
			ioGetClear(&iostate, fd);
		}

		// check for ethernet frames on tap device
		if(g_enableeth > 0) {
			while(!((fd = (ioGetGroup(&iostate, IOGRP_TAP))) < 0)) {
				msg_buf = ioGetData(&iostate, fd);
				msg_len = ioGetDataLen(&iostate, fd);
				msg_ok = 1;

				// check frame
				if((sockdata_lastlen > 0) && (msg_len > sockdata_lastlen)) {
					msg_offset = msg_len - sockdata_lastlen;
					if(memcmp(&msg_buf[msg_offset], sockdata_buf, sockdata_lastlen) == 0) {
						// drop packets which have been sent out via MeshVPN's socket before to avoid loops
						msgf("recursive packet filtered!\n");
						msg_ok = 0;
					}
				}

				if (isEtherMeshVPNFrame(msg_buf, msg_len)) {
                    msgf("meshvpn packet found in TAP, filtering.\n");
					msg_ok = 0;
				}

				// process frame
				if(msg_ok) {
					if((g_enablevirtserv) && ((tapmsg_len = (virtservFrame(&g_virtserv, tapmsg_buf, 1024, msg_buf, msg_len))) > 0)) {
						// virtual service frame
						if(!(ioWriteGroup(&iostate, IOGRP_TAP, tapmsg_buf, tapmsg_len, NULL) > 0)) {
							debug("could not write to tap device!");
						}
					}
					else {
						// regular frame
						frametype = switchFrameOut(&g_switchstate, msg_buf, msg_len, &source_peerid, &source_peerct);
						switch(frametype) {
							case switch_FRAME_TYPE_UNICAST:
								if(peermgtIsActiveIDCT(&g_p2psec->mgt, source_peerid, source_peerct)) {
									do_broadcast = 0;
									p2psecSendMSGToPeerID(g_p2psec, source_peerid, source_peerct, msg_buf, msg_len);
								}
								else {
									do_broadcast = 1;
								}
								break;
							case(switch_FRAME_TYPE_BROADCAST):
								do_broadcast = 1;
								break;
							default:
								do_broadcast = 0;
								break;
						}
						if(do_broadcast) {
							if(g_enablendpcache) {
								// ndp cache enabled, check whether we can avoid the broadcast and answer from the cache instead
								tapmsg_len = ndp6GenAdv(&g_ndpstate, msg_buf, msg_len, tapmsg_buf, 128, &ndp_peerid, &ndp_peerct);
								if(tapmsg_len > 0) {
									if(peermgtIsActiveIDCT(&g_p2psec->mgt, ndp_peerid, ndp_peerct)) {
										// answer from cache
										if(!(ioWriteGroup(&iostate, IOGRP_TAP, tapmsg_buf, tapmsg_len, NULL) > 0)) {
											debug("could not write to tap device!");
										}
									}
									else {
										// cache entry is outdated, send broadcast
										p2psecSendBroadcastMSG(g_p2psec, msg_buf, msg_len);
									}
								}
								else {
									// no cache entry or message not a neighbour solicitation, send broadcast
									p2psecSendBroadcastMSG(g_p2psec, msg_buf, msg_len);
								}
							}
							else {
								// ndp cache disabled, send broadcast
								p2psecSendBroadcastMSG(g_p2psec, msg_buf, msg_len);
							}
						}

						// output packets
						while((sockdata_len = (p2psecOutputPacket(g_p2psec, sockdata_buf, 4096, new_peeraddr.addr))) > 0) {
							sockdata_lastlen = sockdata_len;
							if(!(ioWriteGroup(&iostate, IOGRP_SOCKET, sockdata_buf, sockdata_len, &new_peeraddr) > 0)) {
								debug("could not send packet!");
							}
						}
					}
				}

				// clear frame
				ioGetClear(&iostate, fd);
			}
		}

		// output packets
		while((sockdata_len = (p2psecOutputPacket(g_p2psec, sockdata_buf, 4096, new_peeraddr.addr))) > 0) {
			sockdata_lastlen = sockdata_len;
			if(!(ioWriteGroup(&iostate, IOGRP_SOCKET, sockdata_buf, sockdata_len, &new_peeraddr) > 0)) {
				debug("could not send packet!");
			}
		}

		// show status
		if((tnow - laststatus) > 10) {
			laststatus = tnow;
			connectcount = p2psecPeerCount(g_p2psec);
			if(lastconnectcount != connectcount) {
				msgf("Uptime, %d secs, %d peers connected", p2psecUptime(g_p2psec), connectcount);
				lastconnectcount = connectcount;
			}
		}

        // connect initpeers
		if(((tnow - lastinit) > 30) && (!(mapGetKeyCount(&g_p2psec->mgt.map) > 1))) {
			lastinit = tnow;
			connectInitpeers(peers);
		}

		// check console
		if(g_enableconsole > 0) {
			if(!((fd = (ioGetGroup(&iostate, IOGRP_CONSOLE))) < 0)) {
				decodeConsole((char *)ioGetData(&iostate, fd), ioGetDataLen(&iostate, fd));
				ioGetClear(&iostate, fd);
			}
		}
	}
}

static int isEtherMeshVPNFrame(unsigned char* msg_buf, int msg_len) {
    const struct ethhdr* ether = (struct ethhdr*)msg_buf;
    if (ether->h_proto != htons(ETH_P_IP)) {
        return 0;
    }

    const struct ip* ip = (struct ip*)(ether+1);
    if (ip->ip_p != IPPROTO_UDP) {
        return 0;
    }

    const struct udphdr* udp = (struct udphdr*)(((char*)ip) + ip->ip_hl*4);

//    msgf("src %s:%d dst %s:%d\n",
//        strdup(inet_ntoa(ip->ip_src)),
//        ntohs(udp->uh_sport),
//        strdup(inet_ntoa(ip->ip_dst)),
//         ntohs(udp->uh_dport)
//    );

    struct s_peeraddr peeraddr;
    memset(&peeraddr.addr, 0, sizeof(peeraddr));
    memcpy(&peeraddr.addr[0], IO_ADDRTYPE_UDP4, 4); // set address type
    memcpy(&peeraddr.addr[4], &ip->ip_dst, 4); // copy source IPv4 address
    memcpy(&peeraddr.addr[8], &udp->uh_dport, 2); // copy source port

    if (nodedbNodeAddrExists(&g_p2psec->mgt.nodedb, &peeraddr)) {
		return 1;
    }

    return 0;
}
