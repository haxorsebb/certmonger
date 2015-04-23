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
#include <sys/param.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include <popt.h>

#include "../../src/store.h"

int
main(int argc, const char **argv)
{
	unsigned char buf[LINE_MAX], *p = NULL, *q;
	unsigned int length, i, j;
	int decode = 0, encode = 0, hex = 0;
	const char *s;
	int c, l;
	poptContext pctx;
	struct poptOption popts[] = {
		{"decode", 'd', POPT_ARG_NONE, &decode, 'd', NULL, NULL},
		{"encode", 'e', POPT_ARG_NONE, &encode, 'e', NULL, NULL},
		{"hex", 'h', POPT_ARG_NONE, &hex, 'h', "encode from hex / decode to hex", NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	pctx = poptGetContext("base64", argc, argv, popts, 0);
	if (pctx == NULL) {
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		continue;
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}
	if ((decode && encode) || (!decode && !encode)) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
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
