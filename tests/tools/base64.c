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
#include <sys/param.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include "../../src/store.h"

int
main(int argc, char **argv)
{
	unsigned char buf[LINE_MAX], *p = NULL, *q;
	unsigned int length, decode = 0, encode = 0, hex = 0, i, j;
	const char *s;
	int c, l;

	while ((c = getopt(argc, argv, "deh")) != -1) {
		switch (c) {
		case 'd':
			decode = 1;
			encode = 0;
			break;
		case 'e':
			encode = 1;
			decode = 0;
			break;
		case 'h':
			hex++;
			break;
		}
	}
	length = 0;
	while ((l = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		q = realloc(p, length + l + 1);
		if (q == NULL) {
			perror("realloc");
			free(p);
			return 1;
		}
		memcpy(q + length, buf, l);
		q[length + l] = '\0';
		p = q;
		length += l;
	}
	if (decode) {
		j = 3 * howmany(length, 4) + 1;
		q = malloc(j);
		i = cm_store_base64_to_bin((const char *) p, -1, q, j);
		if (hex) {
			s = cm_store_hex_from_bin(NULL, q, i);
			printf("%s\n", s);
		} else {
			length = i;
			i = 0;
			while (i < length) {
				j = write(STDOUT_FILENO, q + i, length - i);
				if (j <= 0) {
					break;
				}
				i += j;
			}
		}
	} else {
		if (encode) {
			if (hex) {
				s = cm_store_base64_from_hex(NULL, (const char *) p);
				printf("%s\n", s);
			} else {
				s = cm_store_base64_from_bin(NULL, p, length);
				printf("%s\n", s);
			}
		}
	}
	free(p);
	return 0;
}
