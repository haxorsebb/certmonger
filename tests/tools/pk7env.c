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
#include "../../src/store.h"

#define CSR1 "-----BEGIN CERTIFICATE REQUEST-----"
#define CSR2 "-----BEGIN NEW CERTIFICATE REQUEST-----"
#define CERT "-----BEGIN CERTIFICATE-----"

int
main(int argc, char **argv)
{
	struct stat st;
	int fd, i, j;
	ssize_t len;
	size_t length;
	void *parent;
	char *p[3];
	unsigned char *enveloped;

	parent = talloc_new(NULL);
	i = 1;
	while (i < argc) {
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
		p[0] = talloc_size(parent, st.st_size + 1);
		if (p[0] == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return 1;
		}
		memset(p[0], 0, st.st_size + 1);
		len = 0;
		while (len < st.st_size) {
			j = read(fd, p[0] + len, st.st_size - len);
			if (j <= 0) {
				fprintf(stderr, "Read error on \"%s\": %s.\n",
					argv[i], strerror(errno));
				return 1;
			}
			len += j;
		}
		close(fd);
		i++;

		if (i >= argc) {
			return 1;
		}
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
		p[1] = talloc_size(parent, st.st_size + 1);
		if (p[1] == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return 1;
		}
		memset(p[1], 0, st.st_size + 1);
		len = 0;
		while (len < st.st_size) {
			j = read(fd, p[1] + len, st.st_size - len);
			if (j <= 0) {
				fprintf(stderr, "Read error on \"%s\": %s.\n",
					argv[i], strerror(errno));
				return 1;
			}
			len += j;
		}
		close(fd);
		i++;

		if ((strncmp(p[1], CSR1, strlen(CSR1)) == 0) ||
		    (strncmp(p[1], CSR2, strlen(CSR2)) == 0)) {
			if (cm_pkcs7_envelope_csr(p[0], cm_prefs_des3, p[1],
						  &enveloped, &length) != 0) {
				fprintf(stderr, "\"%s\"(\"%s\"): enveloping error.\n",
					argv[i - 2], argv[i - 1]);
				return 1;
			}
			printf("%s\n", cm_store_base64_from_bin(NULL, enveloped, length));
			free(enveloped);
			continue;
		}

		if (i >= argc) {
			return 1;
		}
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
		p[2] = talloc_size(parent, st.st_size + 1);
		if (p[2] == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return 1;
		}
		memset(p[2], 0, st.st_size + 1);
		len = 0;
		while (len < st.st_size) {
			j = read(fd, p[2] + len, st.st_size - len);
			if (j <= 0) {
				fprintf(stderr, "Read error on \"%s\": %s.\n",
					argv[i], strerror(errno));
				return 1;
			}
			len += j;
		}
		close(fd);
		i++;

		if ((strncmp(p[1], CERT, strlen(CERT)) == 0) &&
		    (strncmp(p[2], CERT, strlen(CERT)) == 0)) {
			if (cm_pkcs7_generate_ias(p[1], p[2], &enveloped, &length) != 0) {
				fprintf(stderr, "\"%s\",\"%s\": generating error.\n",
					argv[i - 2], argv[i - 1]);
				return 1;
			}
			printf("%s\n", cm_store_base64_from_bin(NULL, enveloped, length));
			free(enveloped);
			if (cm_pkcs7_envelope_ias(p[0], cm_prefs_des3, p[1],
						  p[2], &enveloped, &length) != 0) {
				fprintf(stderr, "\"%s\"(\"%s\",\"%s\"): enveloping error.\n",
					argv[i - 3], argv[i - 2], argv[i - 1]);
				return 1;
			}
			printf("%s\n", cm_store_base64_from_bin(NULL, enveloped, length));
			free(enveloped);
			continue;
		}
	}
	return 0;
}
