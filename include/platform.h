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

#ifndef H_PLATFORM
#define H_PLATFORM


// Enables seccomp filtering. Returns 1 on success.
int seccompEnable();

// No seccomp support.
int seccompEnable();

// drop privileges
void dropPrivileges(char *username, char *groupname, char *chrootdir);

// drop privileges (automatic version, without specified user and group name)
void dropPrivilegesAuto();

// Execute command.
int ifconfigExec(const char *cmd);

// Check & copy input.
int ifconfigCheckCopyInput(char *out, const int out_len, const char *in, const int in_len);

// Split input.
int ifconfigSplit(char *a_out, const int a_len, char *b_out, const int b_len, const char *in, const int in_len, const char split_char);

// Calculate netmask from prefixlen.
void ifconfig4Netmask(char *out, const int prefixlen);

// Configure IPv4 address on specified interface.
int ifconfig4(const char *ifname, const int ifname_len, const char *addr, const int addr_len);

// Configure IPv6 address on specified interface.
int ifconfig6(const char *ifname, const int ifname_len, const char *addr, const int addr_len);


#endif
