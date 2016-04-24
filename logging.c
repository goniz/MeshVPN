#include "include/logging.h"
#include "stdio.h"
#include <syslog.h>
#include <stdarg.h>

int logging_mode = LOGGING_NONE;

/**
 * Initialize logger. Create connection to syslog and specify application name
 */
int logger_init_syslog() {
 	openlog("peervpn", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	syslog(LOG_INFO, "PeerVPN daemon started");    

	return 1;
}

int logger_set_mode(int mode) {
	if(mode == LOGGING_SYSLOG) {
		logger_init_syslog();
	}

	logging_mode = mode;
	return 1;
}

void msg(char * msg) {
	if(logging_mode == LOGGING_NONE) {
		printf(msg);
	} else if(logging_mode == LOGGING_SYSLOG) {
		syslog(LOG_INFO, msg);
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
