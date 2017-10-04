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
#include "stdio.h"
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

int logging_mode = LOGGING_NONE;

/**
 * Initialize logger. Create connection to syslog and specify application name
 */
static int loggerInitSyslog() {
 	openlog("meshvpn", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	syslog(LOG_INFO, "MeshVPN daemon started");

	return 1;
}

int loggerSetMode(int mode) {
	if(mode == LOGGING_SYSLOG) {
		loggerInitSyslog();
	}

	logging_mode = mode;
	return 1;
}

void msg(char * msg) {

	if(logging_mode == LOGGING_NONE) {
        time_t t = time(NULL);
      	printf("[%ld] %s\n", t, msg);
	} else if(logging_mode == LOGGING_SYSLOG) {
		syslog(LOG_INFO, "%s", msg);
	}
}

void msgf(char * fmt, ...) {
	va_list ap;
	char buffer[250];

	va_start(ap, fmt);
	int ret = vsprintf(buffer, fmt, ap);
	va_end(ap);

	return msg(buffer);
}

void debugMsg(const char * format, const char * file, const int line, ...) {
    char prepend[128];
    char msg_res[256];
    char res[384];

    snprintf(prepend, 128, "[DEBUG] [%s:%d] ", file, line);

    va_list ap;
    va_start(ap, line);
    int ret = vsnprintf(msg_res, 256, format, ap);
    va_end(ap);

    strcpy(res, prepend);
    strcat(res, msg_res);

    msg(res);
}
