/*
 * Copyright (C) 2011,2015 Red Hat, Inc.
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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <krb5.h>

#include <talloc.h>

#include <popt.h>

#include "../../src/submit-u.h"

int
main(int argc, const char **argv)
{
	char buf[LINE_MAX], *p = NULL, *q, *type = "CERTIFICATE";
	int dos = 1, c;
	poptContext pctx;
	struct poptOption popts[] = {
		{"dos", 'd', POPT_ARG_NONE, NULL, 'd', "output using DOS-style end-of-lines", NULL},
		{"unix", 'u', POPT_ARG_NONE, NULL, 'u', "output using Unix-style end-of-lines", NULL},
		{"type", 't', POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &type, 0, "data type to claim", NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	pctx = poptGetContext("base2pem", argc, argv, popts, 0);
	if (pctx == NULL) {
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 'd':
			dos = 1;
			break;
		case 'u':
			dos = 0;
			break;
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}
	while (fgets(buf, sizeof(buf), stdin) != NULL) {
		if (p == NULL) {
			p = strdup(buf);
		} else {
			q = malloc(strlen(p) + strlen(buf) + 1);
			if (q != NULL) {
				stpcpy(stpcpy(q, p), buf);
				free(p);
				p = q;
			}
		}
	}
	printf("%s", cm_submit_u_pem_from_base64(type, dos, p));
	return 0;
}
