#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include "log.h"

static int cm_log_level = 0;
static enum cm_log_method cm_log_method;

int
cm_log_set_level(int level)
{
	int old_level;
	old_level = cm_log_level;
	cm_log_level = level;
	return old_level;
}

enum cm_log_method
cm_log_set_method(enum cm_log_method method)
{
	enum cm_log_method old_method;
	old_method = cm_log_method;
	cm_log_method = method;
	return old_method;
}

void
cm_log(int level, const char *fmt, ...)
{
	va_list args;
	int slevel;
	char *p;
	struct tm lt;
	time_t now;
	if (level <= cm_log_level) {
		switch (cm_log_method) {
		case cm_log_stderr:
			now = time(NULL);
			localtime_r(&now, &lt);
			now = time(NULL);
			p = talloc_asprintf(NULL,
					    "%04d-%02d-%02d %d:%02d:%02d "
					    "[%lu] %s",
					    lt.tm_year + 1900,
					    lt.tm_mon + 1,
					    lt.tm_mday,
					    lt.tm_hour, lt.tm_min, lt.tm_sec,
					    (unsigned long) getpid(), fmt);
			if (p != NULL) {
				va_start(args, fmt);
				vfprintf(stderr, p ?: fmt, args);
				va_end(args);
				talloc_free(p);
			}
			fflush(stderr);
			break;
		case cm_log_syslog:
			va_start(args, fmt);
			switch (level) {
			case 0:
				slevel = LOG_INFO;
				break;
			default:
				slevel = LOG_DEBUG;
				break;
			}
			vsyslog(LOG_DAEMON | slevel, fmt, args);
			va_end(args);
			break;
		}
	}
}
