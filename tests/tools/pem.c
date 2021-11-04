/*
 * Copyright (C) 2021 Red Hat, Inc.
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
#include <fcntl.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <popt.h>

#include <talloc.h>

#include "../../src/util-o.h"

int
main(int argc, const char **argv)
{
	const char *filename;
	void *parent;
	int i, ret = 0;
	poptContext pctx;
	struct poptOption popts[] = {
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	parent = talloc_new(NULL);
	pctx = poptGetContext("pem", argc, argv, popts, 0);
	while ((i = poptGetNextOpt(pctx)) > 0) {
		continue;
	}
	if (i != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}
	while ((filename = poptGetArg(pctx)) != NULL) {
        if (validate_pem(parent, (char *)filename) == 0) {
			printf("OK\n");
		} else {
			ret = 1;
		}
	}
	talloc_free(parent);
	poptFreeContext(pctx);
	return ret;
}
