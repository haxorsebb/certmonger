/*
 * Copyright (C) 2009,2010 Red Hat, Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "submit-u.h"

static char *
my_stpcpy(char *dest, char *src)
{
	size_t len;
	len = strlen(src);
	memcpy(dest, src, len);
	dest[len] = '\0';
	return dest + len;
}

/* Read a CSR from a file. */
char *
cm_submit_u_from_file(const char *filename)
{
	FILE *fp;
	char *csr, *p, buf[BUFSIZ];
	if ((filename == NULL) || (strcmp(filename, "-") == 0)) {
		fp = stdin;
	} else {
		fp = fopen(filename, "r");
		if (fp == NULL) {
			fprintf(stderr, "Error opening \"%s\": %s.\n",
				filename, strerror(errno));
			return NULL;
		}
	}
	csr = NULL;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (csr == NULL) {
			csr = strdup(buf);
			if (csr == NULL) {
				if (fp != stdin) {
					fclose(fp);
				}
				return NULL;
			}
		} else {
			p = malloc(strlen(csr) + sizeof(buf));
			if (p == NULL) {
				if (fp != stdin) {
					fclose(fp);
				}
				return NULL;
			}
			memcpy(my_stpcpy(p, csr), buf, sizeof(buf));
			free(csr);
			csr = p;
		}
	}
	if (fp != stdin) {
		fclose(fp);
	}
	if (csr == NULL) {
		csr = strdup("");
	}
	return csr;
}
