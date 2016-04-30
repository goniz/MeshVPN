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

void debugMsg(const char *format,const char *file,const int line, ...);

#ifdef DEBUG
	#define debug(format) debugMsg(format, __FILE__, __LINE__)
    #define debugf(format, ...) debugMsg(format, __FILE__, __LINE__, __VA_ARGS__)

#else
	#define debug(format)
    #define debugf(format, ...)
#endif /** DEBUG BLOCK */

#endif /** HEADER GUARD */
