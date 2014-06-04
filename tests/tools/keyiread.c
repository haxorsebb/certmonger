/*
 * Copyright (C) 2009,2011,2014 Red Hat, Inc.
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
#include <sys/select.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include "../../src/keyiread.h"
#include "../../src/log.h"
#include "../../src/store.h"
#include "../../src/store-int.h"
#include "tools.h"

static void
wait_to_read(int fd)
{
	fd_set rfds;
	struct timeval tv;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	select(fd + 1, &rfds, NULL, NULL, &tv);
}

static const char *
type_name(enum cm_key_algorithm alg)
{
	switch (alg) {
	case cm_key_rsa:
		return "RSA";
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		return "DSA";
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		return "EC";
		break;
#endif
	default:
		assert(0);
		break;
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	struct cm_keyiread_state *state;
	struct cm_store_entry *entry;
	int fd, ret, need_pin;
	void *parent;
	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	cm_set_fips_from_env();
	parent = talloc_new(NULL);
	if (argc > 1) {
		entry = cm_store_files_entry_read(parent, argv[1]);
		if (entry == NULL) {
			printf("Error reading %s: %s.\n", argv[1],
			       strerror(errno));
			return 1;
		}
	} else {
		printf("Specify an entry file as the single argument.\n");
		return 1;
	}
	entry->cm_key_type.cm_key_size = 0;
	state = cm_keyiread_start(entry);
	if (state != NULL) {
		for (;;) {
			fd = cm_keyiread_get_fd(state);
			if (fd != -1) {
				wait_to_read(fd);
			} else {
				sleep(1);
			}
			if (cm_keyiread_ready(state) == 0) {
				break;
			}
		}
		need_pin = cm_keyiread_need_pin(state);
		cm_keyiread_done(state);
		if (entry->cm_key_type.cm_key_size != 0) {
			printf("OK (%s:%d).\n",
			       type_name(entry->cm_key_type.cm_key_algorithm),
			       entry->cm_key_type.cm_key_size);
			ret = 0;
		} else {
			switch (entry->cm_key_storage_type) {
			case cm_key_storage_none:
				printf("No key to read.\n");
				break;
			case cm_key_storage_file:
				printf("Failed to read key \"%s\".\n",
				       entry->cm_key_storage_location);
				break;
			case cm_key_storage_nssdb:
				printf("Failed to read key \"%s\":\"%s\".\n",
				       entry->cm_key_storage_location,
				       entry->cm_key_nickname);
				break;
			}
			if (need_pin == 0) {
				printf("(Need PIN.)\n");
			}
			ret = 1;
		}
	} else {
		printf("Failed to start.\n");
		ret = 1;
	}
	cm_store_entry_save(entry);
	talloc_free(parent);
	return ret;
}
