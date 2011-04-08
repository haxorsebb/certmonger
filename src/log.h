/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#ifndef cmlog_h
#define cmlog_h

enum cm_log_method {
	cm_log_none = 0,
	cm_log_syslog,
	cm_log_stderr,
	cm_log_stdout,
};

int cm_log_set_level(int level);
enum cm_log_method cm_log_set_method(enum cm_log_method method);
void cm_log(int level, const char *fmt, ...)
#ifdef __GNUC__
__attribute__((format(printf,2,3)))
#endif
;

#endif
