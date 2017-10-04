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

#ifndef H_APP
#define H_APP

#include "logging.h"
#include "globals.h"
#include "util.h"
#include "io.h"

#include <string.h>


#define INITPEERS_MAX 256

struct s_initconfig {
        char sourceip[CONFPARSER_NAMEBUF_SIZE+1];
        char sourceport[CONFPARSER_NAMEBUF_SIZE+1];
        char tapname[CONFPARSER_NAMEBUF_SIZE+1];
        char userstr[CONFPARSER_NAMEBUF_SIZE+1];
        char groupstr[CONFPARSER_NAMEBUF_SIZE+1];
        char chrootstr[CONFPARSER_NAMEBUF_SIZE+1];
        char networkname[CONFPARSER_NAMEBUF_SIZE+1];
        char ifconfig4[CONFPARSER_NAMEBUF_SIZE+1];
        char ifconfig6[CONFPARSER_NAMEBUF_SIZE+1];
        char upcmd[CONFPARSER_NAMEBUF_SIZE+1];

        // list of inital peers, we can have several of them active
        char * initpeers[INITPEERS_MAX];
        // counter of initial peers
        int initpeerscount;

        char engines[CONFPARSER_NAMEBUF_SIZE+1];
        char password[CONFPARSER_NAMEBUF_SIZE+1];
        char pidfile[CONFPARSER_NAMEBUF_SIZE+1];
        char privatekey[CONFPARSER_NAMEBUF_SIZE+1];

        int password_len;
        int enablepidfile;
        int enableindirect;
        int enablerelay;
        int enableeth;
        int enablendpcache;
        int enablevirtserv;
        int enableipv4;
        int enableipv6;
        int enablenat64clat;
        int enableprivdrop;
        int enableseccomp;
        int enablesyslog;
        int forceseccomp;
        int daemonize;
        int enableconsole;
        int sockmark;
};

// handle termination signals
void sighandler(int sig);

// load named OpenSSL engine
int loadengine(const char *engine_name);
/**
 * Resolve addresses of initial peers
 */
int proceedInitPeers(const struct s_initconfig * cfg, struct s_initpeers * peers);

// initialization sequence
void init(struct s_initconfig *initconfig);

// Connect initpeers.
void connectInitpeers(struct s_initpeers * peers);

// the mainloop
void mainLoop(struct s_initpeers * peers);

void throwError(char *msg);

int parseConfigInt(char *str);

int parseConfigBoolean(char *str);

int parseConfigIsEOLChar(char c);

int parseConfigLineCheckCommand(char *line, int linelen, const char *cmd, int *vpos);

int parseConfigLine(char *line, int len, struct s_initconfig *cs);

void parseConfigFile(int fd, struct s_initconfig *cs);

#endif
