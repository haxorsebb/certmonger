/*
 * Copyright (C) 2014 Red Hat, Inc.
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
#include <time.h>

#include <talloc.h>

#include "../../src/store.h"

int
main(int argc, char **argv)
{
	int i;
	char *result;

	for (i = 1; i < argc; i++) {
		result = cm_store_canonicalize_path(NULL, argv[i]);
		if (result == NULL) {
			printf("\"%s\": (null)\n", argv[i]);
			return 1;
		} else {
			printf("\"%s\": \"%s\"\n", argv[i], result);
		}
	}
	return 0;
}
