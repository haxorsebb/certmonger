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
#include "../../src/store-int.h"
#include "../../src/submit-int.h"
#include "../../src/util-o.h"

int
main(int argc, char **argv)
{
	unsigned char *payload = NULL, *data, buf[BUFSIZ];
	size_t payload_length = 0;
	struct cm_submit_decrypt_envelope_args args;
	void *parent;
	ssize_t len;
	int i;
	void (*decrypt)(const unsigned char *envelope, size_t length,
			void *decrypt_userdata,
			unsigned char **payload, size_t *payload_length) = NULL;


	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	parent = talloc_new(NULL);

	if (argc < 2) {
		fprintf(stderr, "Name of entry file required.\n");
		return 1;
	}
	memset(&args, 0, sizeof(args));
	args.entry = cm_store_files_entry_read(parent, argv[1]);
	if (args.entry == NULL) {
		fprintf(stderr, "Error reading entry from \"%s\".\n", argv[1]);
		return 1;
	}

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
	switch (args.entry->cm_key_storage_type) {
	case cm_key_storage_none:
		break;
	case cm_key_storage_nssdb:
		decrypt = cm_submit_n_decrypt_envelope;
		break;
	case cm_key_storage_file:
		decrypt = cm_submit_o_decrypt_envelope;
		break;
	}
	if (decrypt != NULL) {
		(*decrypt)(data, len, &args, &payload, &payload_length);
	}
	if ((payload != NULL) && (payload_length > 0)) {
		printf("payload:%s\n", cm_store_base64_from_bin(parent, payload,
								payload_length));
	} else {
		printf("decrypt error\n");
	}
	talloc_free(parent);
	return ((payload != NULL) && (payload_length > 0)) ? 0 : 1;
}
