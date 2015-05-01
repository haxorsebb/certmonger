/*
 * Copyright (C) 2015 Red Hat, Inc.
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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <popt.h>

#include <talloc.h>

#include "../../src/json.h"

int
main(int argc, const char **argv)
{
	struct stat st;
	char *e, *e2, *e3, *e4, *path = NULL;
	const char *left, *filename;
	struct cm_json *j, *j2, *j3;
	void *parent;
	int i, n, r, fd, ret = 0, quiet = 0;
	poptContext pctx;
	struct poptOption popts[] = {
		{"quiet", 'q', POPT_ARG_NONE, &quiet, 0, NULL, NULL},
		{"path", 'p', POPT_ARG_STRING, &path, 0, NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	parent = talloc_new(NULL);
	pctx = poptGetContext("json", argc, argv, popts, 0);
	while ((i = poptGetNextOpt(pctx)) > 0) {
		continue;
	}
	if (i != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}
	while ((filename = poptGetArg(pctx)) != NULL) {
		fd = open(filename, O_RDONLY);
		if (fd == -1) {
			ret = errno;
			fprintf(stderr, "open(\"%s\"): %s\n", filename,
				strerror(errno));
			continue;
		}
		if (fstat(fd, &st) == -1) {
			ret = errno;
			fprintf(stderr, "stat(\"%s\"): %s\n", filename,
				strerror(errno));
			continue;
		}
		e = talloc_size(parent, st.st_size);
		if (e == NULL) {
			ret = errno;
			fprintf(stderr, "malloc(): %s\n", strerror(errno));
			continue;
		}
		r = 0;
		while (r < st.st_size) {
			n = read(fd, e + r, st.st_size - r);
			if (n <= 0) {
				ret = errno;
				break;
			}
			r += n;
		}
		if (r < st.st_size) {
			fprintf(stderr, "read(): %s\n", strerror(errno));
			close(fd);
			break;
		}
		close(fd);
		i = cm_json_decode(parent, e, st.st_size, &j, &left);
		if (i != 0) {
			ret = -1;
			fprintf(stderr, "decode(\"%.*s\"): %s\n",
				(int) (st.st_size - (left - e)),
				left, cm_json_decode_strerror(i));
			continue;
		}
		if (left - e != st.st_size) {
			if (left - e < st.st_size) {
				fprintf(stderr, "decode(%.*s) has %lld bytes leftover:\n%.*s\n",
					(int) st.st_size, filename,
					(long long) (st.st_size - (left - e)),
					(int) (st.st_size - (left - e)),
					left);
			} else {
				fprintf(stderr, "decode(%.*s) overran by %lld\n",
					(int) st.st_size, filename,
					(long long) (left - e - st.st_size));
			}
			ret = -1;
			continue;
		}
		e2 = cm_json_encode(parent, j);
		if (e2 == NULL) {
			ret = -1;
			fprintf(stderr, "encode(1) failed\n");
			continue;
		}
		i = cm_json_decode(parent, e2, -1, &j2, &left);
		if (i != 0) {
			ret = -1;
			fprintf(stderr, "decode(\"%s\"): %s\n", left,
				cm_json_decode_strerror(i));
			continue;
		}
		st.st_size = strlen(e2);
		if (left - e2 != st.st_size) {
			ret = -1;
			if (left - e2 < st.st_size) {
				fprintf(stderr, "decode() has %lld bytes leftover:\n%s\n",
					(long long) (st.st_size - (left - e2)), left);
			} else {
				fprintf(stderr, "decode() overran by %lld\n",
					(long long) (left - e2 - st.st_size));
			}
			continue;
		}
		e3 = cm_json_encode(parent, j2);
		if (e3 == NULL) {
			ret = -1;
			fprintf(stderr, "encode(2) failed\n");
			continue;
		}
		if (strcmp(e2, e3) != 0) {
			ret = -1;
			fprintf(stderr, "encode() round-trip failed: \"%s\" != \"%s\"\n",
				e2, e3);
			continue;
		}
		if (path != NULL) {
			j3 = cm_json_find(j2, path);
			if (j3 == NULL) {
				ret = -1;
				fprintf(stderr, "unable to find \"%s\"\n", path);
				continue;
			}
			e4 = cm_json_encode(parent, j3);
			if (e4 == NULL) {
				ret = -1;
				fprintf(stderr, "encode(3) failed\n");
				continue;
			}
		} else {
			j3 = NULL;
			e4 = NULL;
		}
		if (!quiet) {
			if (strchr(filename, '/') != NULL) {
				filename = strrchr(filename, '/') + 1;
			}
			if (path != NULL) {
				printf("[%s]\n%s\n", filename, e4);
			} else {
				printf("[%s]\n%s\n", filename, e3);
			}
		}
	}
	talloc_free(parent);
	return ret;
}
