/*
 * Copyright (C) 2014,2015 Red Hat, Inc.
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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <krb5.h>

#include <talloc.h>

#include "../../src/srvloc.h"

int
main(int argc, char **argv)
{
	int i;
	struct cm_srvloc *results;

	for (i = 2; i < argc; i++) {
		if (cm_srvloc_resolve(NULL, argv[i], argv[1], &results) != 0) {
			printf("Error resolving \"%s.%s\".\n", argv[i],
			       argv[1]);
			continue;
		}
		while (results != NULL) {
			printf("%s.%s: %s:%d (%d,%d)\n", argv[i], argv[1],
			       results->host, results->port,
			       results->priority, results->weight);
			results = results->next;
		}
	}
	return 0;
}
