/*
 * Copyright (C) 2010 Red Hat, Inc.
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

#include "../../src/config.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <krb5.h>

#include "../../src/submit.h"
#include "../../src/submit-u.h"

int cm_submit_delta_from_string(const char *deltas, time_t now, time_t *delta);
int
main(int argc, char **argv)
{
	struct tm when;
	time_t now, later, delta;
	int i;
	if (argc > 1) {
		for (i = 2; i < argc; i++) {
			memset(&when, 0, sizeof(when));
			when.tm_mday = 1;
			when.tm_mon = 0;
			when.tm_year = atoi(argv[1]) - 1900;
			if (cm_submit_u_delta_from_string(argv[i],
							  now = mktime(&when),
							  &delta) != 0) {
				printf("Error at \"%s\".\n", argv[i]);
				delta = 0;
			}
			printf("%04d-%02d-%02d %02d:%02d:%02d",
			       when.tm_year + 1900,
			       when.tm_mon + 1,
			       when.tm_mday,
			       when.tm_hour,
			       when.tm_min,
			       when.tm_sec);
			printf(" + \"%s\" = ", argv[i]);
			later = now + delta;
			localtime_r(&later, &when);
			printf("%04d-%02d-%02d %02d:%02d:%02d",
			       when.tm_year + 1900,
			       when.tm_mon + 1,
			       when.tm_mday,
			       when.tm_hour,
			       when.tm_min,
			       when.tm_sec);
			printf("\n");
		}
	}
	return 0;
}
