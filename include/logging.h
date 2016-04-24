#ifndef H_LOGGING
#define H_LOGGING

#include <stdarg.h>

#define LOGGING_NONE 0
#define LOGGGIN_FILE 1
#define LOGGING_SYSLOG 2

extern int logging_mode;

int logger_init_syslog();

int logger_set_mode(int);

void msg(char *);

void msgf(char *,...);

#endif
