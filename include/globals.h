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

#ifndef H_GLOBALS
#define H_GLOBALS

#include "io.h"
#include "p2p.h"
#include "ethernet.h"

// compile time options & timing parameters
#define INITPEER_STORAGE 1024


// config parser options
#define CONFPARSER_LINEBUF_SIZE 4096
#define CONFPARSER_NAMEBUF_SIZE 512

// encryption options
#define ENCRYPTION_ASYM

// iogrps
#define IOGRP_DEFAULT 0
#define IOGRP_SOCKET 1
#define IOGRP_TAP 2
#define IOGRP_CONSOLE 3

struct s_initpeers {
        struct s_io_addr * addresses;
        int count;
};
// global variables
struct s_io_state iostate;
struct s_p2psec * g_p2psec;
int g_mainloop;

struct s_switch_state g_switchstate;
struct s_ndp6_state g_ndpstate;
struct s_virtserv_state g_virtserv;

int g_enableconsole;
int g_enableeth;
int g_enablendpcache;
int g_enablevirtserv;
int g_enableengines;

#endif
