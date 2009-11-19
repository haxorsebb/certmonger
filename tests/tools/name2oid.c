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

#include "../../src/config.h"

#include <stdio.h>

#include <talloc.h>

#include "../../src/log.h"
#include "../../src/oiddict.h"

int
main(int argc, char **argv)
{
	int i;
	const char *oid;
	void *parent;
	parent = talloc_new(NULL);
	for (i = 1; i < argc; i++) {
		oid = cm_oid_from_name(parent, argv[i]);
		if (oid != NULL) {
			printf("%s\n", oid);
		} else {
			return 1;
		}
	}
	talloc_free(parent);
	return 0;
}
