/***************************************************************************
 *   Copyright (C) 2016 by Tobias Volk                                     *
 *   mail@tobiasvolk.de                                                    *
 *                                                                         *
 *   This program is free software: you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifndef H_IO
#define H_IO

#if defined(__FreeBSD__)
#define IO_BSD
#elif defined(__APPLE__)
#define IO_BSD
#elif defined(WIN32)
#define IO_WINDOWS
#ifdef WINVER
#if WINVER < 0x0501
#undef WINVER
#endif
#endif
#ifndef WINVER
#define WINVER 0x0501
#endif
#else
#define IO_LINUX
#endif


#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


#if defined(IO_LINUX) || defined(IO_BSD)
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#if defined(IO_LINUX)
#include <linux/if_tun.h>
#endif

#if defined(IO_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winioctl.h>
#endif


#define IO_TYPE_NULL 0
#define IO_TYPE_SOCKET_V6 1
#define IO_TYPE_SOCKET_V4 2
#define IO_TYPE_FILE 3

#define IO_ADDRTYPE_NULL "\x00\x00\x00\x00"
#define IO_ADDRTYPE_UDP6 "\x01\x06\x01\x00"
#define IO_ADDRTYPE_UDP4 "\x01\x04\x01\x00"



// The IO addr structure.
struct s_io_addr {
    unsigned char addr[24];
};


// The IO addrinfo structure.
struct s_io_addrinfo {
    struct s_io_addr item[16];
    int count;
};


// The IO handle structure.
struct s_io_handle {
    int enabled;
    int fd;
    struct sockaddr_storage source_sockaddr;
    struct s_io_addr source_addr;
    int group_id;
    int content_len;
    int type;
    int open;
#if defined(IO_WINDOWS)
    HANDLE fd_h;
    int open_h;
    OVERLAPPED ovlr;
    int ovlr_used;
    OVERLAPPED ovlw;
    int ovlw_used;
#endif
};


// The IO state structure.
struct s_io_state {
    unsigned char *mem;
    struct s_io_handle *handle;
    int bufsize;
    int max;
    int count;
    int timeout;
    int sockmark;
    int nat64clat;
    unsigned char nat64_prefix[12];
    int debug;
};

#endif