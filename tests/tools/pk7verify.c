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

#include <openssl/err.h>
#include <openssl/objects.h>

#include "../../src/log.h"
#include "../../src/pkcs7.h"
#include "../../src/store.h"
#include "../../src/util-o.h"

int
main(int argc, char **argv)
{
	struct stat st;
	int fd, i, j, root = 0, n_roots = 0, n_others = 0;
	ssize_t len;
	void *parent;
	char **roots, **others, *p, *digest = NULL;
	char *tx = NULL, *msgtype = NULL, *pkistatus = NULL, *failinfo = NULL;
	unsigned char *snonce = NULL, *rnonce = NULL, *payload = NULL;
	size_t snonce_length = 0, rnonce_length = 0, payload_length = 0;
	unsigned char *data, buf[BUFSIZ];

	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	util_o_init();
	ERR_load_crypto_strings();
	parent = talloc_new(NULL);
	roots = talloc_array_ptrtype(parent, roots, argc);
	others = talloc_array_ptrtype(parent, others, argc);
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0) {
			root = 1;
			continue;
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
		p = talloc_size(parent, st.st_size + 1);
		if (p == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return 1;
		}
		memset(p, '\0', st.st_size + 1);
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
		close(fd);
		if (root) {
			roots[n_roots++] = p;
			root = 0;
		} else {
			others[n_others++] = p;
		}
	}
	roots[n_roots] = NULL;
	others[n_others] = NULL;

	len = 0;
	data = NULL;
	while ((i = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		data = talloc_realloc_size(parent, data, len + i);
		if (data == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return 1;
		}
		memcpy(data + len, buf, i);
		len += i;
	}
	if (len == 0) {
		fprintf(stderr, "No data to verify.\n");
		return 1;
	}
	i = cm_pkcs7_verify_signed(data, len,
				   (const char **) roots,
				   (const char **) others,
				   NID_pkcs7_data, parent, &digest,
				   &tx, &msgtype, &pkistatus, &failinfo,
				   &snonce, &snonce_length,
				   &rnonce, &rnonce_length,
				   &payload, &payload_length);
	if (i == 0) {
		printf("verify passed\n");
	} else {
		printf("verify failed\n");
	}
	if (digest != NULL) {
		printf("digest:%s\n", digest);
	}
	if (tx != NULL) {
		printf("tx:%s\n", tx);
	}
	if (msgtype != NULL) {
		printf("msgtype:%s\n", msgtype);
	}
	if (pkistatus != NULL) {
		printf("pkistatus:%s\n", pkistatus);
	}
	if (failinfo != NULL) {
		printf("failinfo:%s\n", failinfo);
	}
	if (snonce != NULL) {
		printf("snonce:%s\n", cm_store_base64_from_bin(parent, snonce,
							       snonce_length));
	}
	if (rnonce != NULL) {
		printf("rnonce:%s\n", cm_store_base64_from_bin(parent, rnonce,
							       rnonce_length));
	}
	if (payload != NULL) {
		printf("payload:%s\n", cm_store_base64_from_bin(parent, payload,
								payload_length));
	}
	talloc_free(parent);
	return i;
}
