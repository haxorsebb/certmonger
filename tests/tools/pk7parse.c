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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include "../../src/log.h"
#include "../../src/pkcs7.h"

int
main(int argc, char **argv)
{
	struct stat st;
	int fd, i, j;
	ssize_t len;
	void *parent;
	unsigned char *p;
	char *leaf, *top, **certs;

	parent = talloc_new(NULL);
	for (i = 1; i < argc; i++) {
		fd = open(argv[i], O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Error opening \"%s\": %s.\n",
				argv[i], strerror(errno));
			return 1;
		}
		if (fstat(fd, &st) == -1) {
			fprintf(stderr, "Error statting \"%s\": %s.\n",
				argv[i], strerror(errno));
			return 1;
		}
		p = talloc_size(parent, st.st_size);
		if (p == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return 1;
		}
		memset(p, 0, st.st_size);
		len = 0;
		while (len < st.st_size) {
			j = read(fd, p + len, st.st_size - len);
			if (j <= 0) {
				fprintf(stderr, "Read error on \"%s\": %s.\n",
					argv[i], strerror(errno));
				return 1;
			}
			len += j;
		}
		if (cm_pkcs7_parse(CM_PKCS7_LEAF_PREFER_ENCRYPT,
				   parent, &leaf, &top, &certs,
				   p, len, NULL) != 0) {
			fprintf(stderr, "\"%s\": parse error.\n", argv[i]);
			return 1;
		}
		printf("[%s]\nTOP:\n%sLEAF:\n%s", argv[i],
		       top ? top : "", leaf ? leaf : "");
		for (j = 0; (certs != NULL) && (certs[j] != NULL); j++) {
			printf("%d:\n%s", j + 1, certs[j]);
		}
		close(fd);
	}
	talloc_free(parent);
	return 0;
}
