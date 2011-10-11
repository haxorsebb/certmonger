/*
 * Copyright (C) 2009,2011 Red Hat, Inc.
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
#include "tm.h"

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
	FILE *stream;
	va_list args;
	int slevel;
	char *p;
	struct tm lt;
	time_t now;
	if (level <= cm_log_level) {
		stream = stderr;
		switch (cm_log_method) {
		case cm_log_none:
			break;
		case cm_log_stdout:
			stream = stdout;
			/* fall through */
		case cm_log_stderr:
			now = cm_time(NULL);
			localtime_r(&now, &lt);
			p = talloc_asprintf(NULL,
					    "%04d-%02d-%02d %02d:%02d:%02d "
					    "[%lu] %s",
					    lt.tm_year + 1900,
					    lt.tm_mon + 1,
					    lt.tm_mday,
					    lt.tm_hour, lt.tm_min, lt.tm_sec,
					    (unsigned long) getpid(), fmt);
			if (p != NULL) {
				va_start(args, fmt);
				vfprintf(stream, p, args);
				va_end(args);
				talloc_free(p);
			}
			fflush(NULL);
			break;
		case cm_log_syslog:
			va_start(args, fmt);
			switch (level) {
			case -2:
				slevel = LOG_CRIT;
				break;
			case -1:
				slevel = LOG_WARNING;
				break;
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
