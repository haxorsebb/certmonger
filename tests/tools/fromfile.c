/*
 * Copyright (C) 2020 Red Hat, Inc.
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
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include <krb5.h>

#include "../../src/submit-u.h"
#include "../../src/submit-u.c"

int
main(int argc, char **argv)
{
	int i, result = 0;
	char *cert;

	for (i = 1; i < argc; i++) {
		printf("[%s]\n", argv[i]);
		cert = cm_submit_u_from_file(argv[i]);
		if (cert == NULL) {
			printf("OOM error\n");
			result = 1;
		}
		else if (cert[strlen(cert) - 1] != '\n') {
			printf("Missing trailing newline\n");
			result = 1;
		} else {
			printf("Ok\n");
		}
		free(cert);
	}
	return result;
}
