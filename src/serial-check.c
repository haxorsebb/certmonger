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

#include "config.h"

#include <stdio.h>

#include <talloc.h>

#include "store.h"
int
main(int argc, char **argv)
{
	int i;
	void *parent;
	char *serial;
	parent = talloc_new(NULL);
	serial = cm_store_increment_serial(parent, NULL);
	printf("Starting value = %s\n", serial);
	for (i = 0; i < 1024; i++) {
		serial = cm_store_increment_serial(parent, serial);
		printf("%s\n", serial);
	}
	return 0;
}
