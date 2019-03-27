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

#include "logging.h"
#include "globals.h"
#include "nodeid.h"
#include "util.h"
#include "io.h"
#include "app.h"
#include "p2p.h"
#include "platform.h"

#include <string.h>
#include <signal.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

extern struct s_p2psec * g_p2psec;


void initTapDevice(const struct s_initconfig* initconfig, char* tapname);
void initAttachToInterface(char* interface);

// handle termination signals
void sighandler(int sig) {
	g_mainloop = 0;
}


// load named OpenSSL engine
int loadengine(const char *engine_name) {
	const char **pre_cmds = NULL;
	const char **post_cmds = NULL;
	int pre_num = 0;
	int post_num = 0;
	ENGINE *e = ENGINE_by_id(engine_name);
	if(!e) {
		return 0;
	}
	while(pre_num--) {
		if(!ENGINE_ctrl_cmd_string(e, pre_cmds[0], pre_cmds[1], 0)) {
			ENGINE_free(e);
			return 0;
		}
		pre_cmds += 2;
	}
	if(!ENGINE_init(e)) {
		ENGINE_free(e);
		return 0;
	}
	ENGINE_free(e);
	while(post_num--) {
		if(!ENGINE_ctrl_cmd_string(e, post_cmds[0], post_cmds[1], 0)) {
			ENGINE_finish(e);
			return 0;
		}
		post_cmds += 2;
	}
	ENGINE_set_default(e, ENGINE_METHOD_ALL & ~ENGINE_METHOD_RAND);
	return 1;
}

/**
 * Resolve addresses of initial peers
 */
int proceedInitPeers(const struct s_initconfig * cfg, struct s_initpeers * peers) {
    debug("processing init peers");

    peers->addresses = malloc(sizeof(struct s_io_addr) * INITPEER_STORAGE);
    peers->count = 0;

    int i;
    for(i = 0; i < cfg->initpeerscount; i++) {
        char * peer = cfg->initpeers[i];

        char hostname[256];
        char port[6];

        strcpy(hostname,"");
        strcpy(port, "");

        int c;
        for(c = 0; c < strlen(peer); c++) {
            if(isWhitespaceChar(peer[c]) || peer[c] == '\0') {
                memcpy(hostname, peer, c);
                hostname[c] = '\0';

                int port_len = ((strlen(peer) - c) > 5 ) ? 5 : strlen(peer) - c;
                memcpy(port, &peer[c+1], port_len);
                port[port_len] = '\0';

                break;
            }
        }

        if(strlen(hostname) == 0 || strlen(port) == 0) {
            msgf("skipping bad initpeer: %s", peer );
            continue;
        }

        struct s_io_addrinfo new_peeraddrs;
        if(!ioResolveName(&new_peeraddrs, hostname, port)) {
            debugf("hostname %s is not resolvable, continue", hostname);
        }

        debugf("hostname %s, port: %s, total addresses: %d", hostname, port, new_peeraddrs.count);

        int d;
        for(d = 0; d < new_peeraddrs.count; d++) {
            if(peers->count >= INITPEER_STORAGE) {
                debug("Init peers is full. Exiting");
                return 1;
            }

            memcpy(&peers->addresses[peers->count], &new_peeraddrs.item[d], sizeof(struct s_io_addr));
            peers->count++;
        }
    }

    msgf("Total %d initial peers found", peers->count);

    return 1;
}

// initialization sequence
void init(struct s_initconfig *initconfig) {
	int c,i,j,k,l,m;
	char str[256];
	char tapname[256];
    struct s_initpeers peers;

    if(!proceedInitPeers(initconfig, &peers)) {
        throwError("No init peers found or wrong configuration");
    }

	// create data structures
	if(!ioCreate(&iostate, 4096, 4)) {
		throwError("Could not initialize I/O backend!\n");
	}
	ioSetTimeout(&iostate, 1);

	// enable console
	if(initconfig->enableconsole) {
		if(!((j = (ioOpenSTDIN(&iostate))) < 0)) {
			ioSetGroup(&iostate, j, IOGRP_CONSOLE);
			g_enableconsole = 1;
		}
		else {
			throwError("Could not initialize console!");
		}
	}
	else {
		g_enableconsole = 0;
	}

	// open udp sockets
	msg("Openning sockets...");
	i = 0;
	ioSetNat64Clat(&iostate, initconfig->enablenat64clat);
	ioSetSockmark(&iostate, initconfig->sockmark);
	if(initconfig->enableipv4) {
		if(!((j = (ioOpenSocketV4(&iostate, initconfig->sourceip, initconfig->sourceport))) < 0)) {
			ioSetGroup(&iostate, j, IOGRP_SOCKET);
                        msg("IPv4/UDP initialization successfull");
			i++;
		}
		else {
			printf("   IPv4/UDP: failed.\n");
		}
	}
	if(initconfig->enableipv6) {
		if(!((j = (ioOpenSocketV6(&iostate, initconfig->sourceip, initconfig->sourceport))) < 0)) {
			ioSetGroup(&iostate, j, IOGRP_SOCKET);
			msg("IPv6/UDP initialization successfull");
			i++;
		}
		else {
			printf("   IPv6/UDP: failed.\n");
		}
	}
	if(i < 1) {
		throwError("Could not open any sockets! This might be caused by:\n- another open socket on the same port\n- invalid port number and/or local IP address\n- insufficient privileges");
	}

    // open tap device
    if(initconfig->enableeth) {
    	if (initconfig->enablerawsockets) {
			initAttachToInterface(initconfig->tapname);
    	} else {
			initTapDevice(initconfig, tapname);
		}
	}
    else {
        g_enableeth = 0;
    }

	// enable ndp cache
	if(initconfig->enablendpcache) {
		g_enablendpcache = 1;
	}
	else {
		g_enablendpcache = 0;
	}

	// enable virtual service
	if(initconfig->enablevirtserv) {
		g_enablevirtserv = 1;
	}
	else {
		g_enablevirtserv = 0;
	}

	// load OpenSSL engines
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
	i=0;j=0;k=0;l=0;m=0;
	str[0] = '\0';
	for(;;) {
		c = initconfig->engines[i];
		if(isWhitespaceChar(c) || c == '\0') {
			m=i-j;
			if(m>0) {
				if(m > 254) m = 254;
				memcpy(str,&initconfig->engines[j],m);
				str[m] = '\0';
				l = l+2+m;
				j = i+1;
				if(k < 1) {
					msg("Loading OpenSSL engines...\n");
					ENGINE_load_builtin_engines();
					ENGINE_register_all_complete();
					k = 1;
				}
				if(loadengine(str)) {
					msgf("Initialized OpenSSL engine %s", str);
				} else {
					msgf("Failed to initialize OpenSSL engine %s", str);
				}
			}
			m=0;
		}
		if(c == '\0') break;
		i++;
	}


	// initialize p2p core
	msg("Initializing P2P core");
	g_p2psec = p2psecCreate();
	if(!p2psecLoadDefaults(g_p2psec)) throwError("Failed to load defaults!");

	if(!p2psecInitPrivateKey(g_p2psec, 1024, initconfig->privatekey)) throwError("Failed to generate private key!");

    p2psecSetNetname(g_p2psec, initconfig->networkname, strlen(initconfig->networkname));
	p2psecSetPassword(g_p2psec, initconfig->password, initconfig->password_len);
	p2psecEnableFragmentation(g_p2psec);

    if(g_enableeth > 0) {
		p2psecEnableUserdata(g_p2psec);
	}
	else {
		p2psecDisableUserdata(g_p2psec);
	}
	if(initconfig->enablerelay) {
		p2psecEnableRelay(g_p2psec);
	}
	else {
		p2psecDisableRelay(g_p2psec);
	}
	if(!p2psecStart(g_p2psec)) throwError("Failed to start p2p core!");
        msg("P2P core successfully initialized");
	// initialize mac table
	if(!switchCreate(&g_switchstate)) throwError("Failed to setup mactable!\n");

	// initialize ndp table
	if(!ndp6Create(&g_ndpstate)) throwError("Failed to setup ndptable!\n");

	// initialize virtual service
	if(!virtservCreate(&g_virtserv)) throwError("Failed to setup virtserv!\n");

	// initialize signal handlers
	g_mainloop = 1;
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	// show client & network id
	utilByteArrayToHexstring(str, 256, mapGetKeyByID(&g_p2psec->mgt.map, 0), NODEID_SIZE);
	msgf("Client ID: %s", str);

	utilByteArrayToHexstring(str, 256, g_p2psec->mgt.netid.id, netid_SIZE);
	msgf("Network ID: %s", str);

	// drop privileges
	dropPrivileges(initconfig->userstr, initconfig->groupstr, initconfig->chrootstr);
	if(initconfig->enableprivdrop) {
		dropPrivilegesAuto();
	}

	// enable seccomp syscall filtering
	i = 0;
	if(initconfig->enableseccomp) {
		i = seccompEnable();
        msgf("Seccomp activation status %d", i);
	}
	if(initconfig->forceseccomp) {
		if(!i) throwError("Failed to enable seccomp sandboxing!\nTo ignore this, set the \"forceseccomp\" option to \"no\".");
	}

	// enter main loop
	msg("Initialization finished, starting main loop");
    mainLoop(&peers);
    msg("Mainloop finished, closing down");

	// shut down
	virtservDestroy(&g_virtserv);
	ndp6Destroy(&g_ndpstate);
	switchDestroy(&g_switchstate);
	p2psecStop(g_p2psec);
	p2psecDestroy(g_p2psec);
	ioDestroy(&iostate);

	// exit
	printf("exit.\n");
}

void initAttachToInterface(char* interface)
{
	msgf("Trying to attach to an existing interface: %s", interface);

	int id = ioAttachToInterface(&iostate, interface);
	if (0 > id) {
		g_enableeth = 0;
		printf("   failed.\n");
		throwError("Could not attach to the network interface specified.");
	}

	ioSetGroup(&iostate, id, IOGRP_TAP);
	g_enableeth = 1;
	msgf("Interface successfully attached: %s", interface);
}

void initTapDevice(const struct s_initconfig* initconfig, char* tapname) {
	msg("Trying to open TAP device");

	int id = 0;
	if ((id = (ioOpenTAP(&iostate, tapname, initconfig->tapname))) < 0) {
		g_enableeth = 0;
		printf("   failed.\n");
		throwError("The TAP device could not be opened! This might be caused by:\n"
	               "- a missing TAP device driver,\n"
				   "- a blocked TAP device (try a different name),\n"
	               "- insufficient privileges (try running as the root/administrator user).");
	} else {
		ioSetGroup(&iostate, id, IOGRP_TAP);
		g_enableeth = 1;
		msgf("TAP device successfully opened: %s", tapname);

		if (strlen(initconfig->ifconfig4) > 0) {
			// configure IPv4 address
			if (!(ifconfig4(tapname, strlen(tapname), initconfig->ifconfig4, strlen(initconfig->ifconfig4)))) {
				debug("Could not automatically configure IPv4 address!");
			}
		}

		if (strlen(initconfig->ifconfig6) > 0) {
			// configure IPv6 address
			if (!(ifconfig6(tapname, strlen(tapname), initconfig->ifconfig6, strlen(initconfig->ifconfig6)))) {
				debug("Could not automatically configure IPv6 address!");
			}
		}

		if (strlen(initconfig->upcmd) > 0) {
			msgf("running upcmd: %s", initconfig->upcmd);

			// execute shell command
			if ((ifconfigExec(initconfig->upcmd)) < 0) {
				msg("The command specified in the \"upcmd\" option returned an error!");
			} else {
				msgf("command %s executed successfully", initconfig->upcmd);
			}
		}
	}

	msg("Address configuration completed");
}
