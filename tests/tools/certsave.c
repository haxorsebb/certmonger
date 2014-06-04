/*
 * Copyright (C) 2009,2011,2013 Red Hat, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include "../../src/certsave.h"
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

int
main(int argc, char **argv)
{
	struct cm_certsave_state *state;
	struct cm_store_entry *entry;
	int fd, ret;
	void *parent;
	const char *ctype;
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
	state = cm_certsave_start(entry);
	if (state != NULL) {
		for (;;) {
			fd = cm_certsave_get_fd(state);
			if (fd != -1) {
				wait_to_read(fd);
			} else {
				sleep(1);
			}
			if (cm_certsave_ready(state) == 0) {
				break;
			}
		}
		if (cm_certsave_saved(state) == 0) {
			ret = 0;
		} else {
			ctype = "unknown";
			switch (entry->cm_cert_storage_type) {
			case cm_cert_storage_file:
				ctype = "FILE";
				break;
			case cm_cert_storage_nssdb:
				ctype = "NSS";
				break;
			}
			if (cm_certsave_conflict_subject(state) == 0) {
				printf("Failed to save (%s:%s), "
				       "subject name conflict.\n",
				       ctype, entry->cm_cert_storage_location);
			} else
			if (cm_certsave_conflict_nickname(state) == 0) {
				printf("Failed to save (%s:%s), "
				       "certificate nickname conflict.\n",
				       ctype, entry->cm_cert_storage_location);
			} else
			if (cm_certsave_permissions_error(state) == 0) {
				printf("Failed to save (%s:%s), "
				       "filesystem permissions error.\n",
				       ctype, entry->cm_cert_storage_location);
			} else {
				printf("Failed to save (%s:%s), "
				       "don't know why.\n",
				       ctype, entry->cm_cert_storage_location);
			}
			ret = 1;
		}
		cm_certsave_done(state);
	} else {
		printf("Failed to start.\n");
		ret = 1;
	}
	cm_store_entry_save(entry);
	talloc_free(parent);
	return ret;
}
