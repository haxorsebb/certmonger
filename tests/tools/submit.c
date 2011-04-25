/*
 * Copyright (C) 2009,2011 Red Hat, Inc.
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
#include <unistd.h>

#include <krb5.h>

#include <talloc.h>

#include "../../src/log.h"
#include "../../src/store-int.h"
#include "../../src/store.h"
#include "../../src/submit.h"
#include "../../src/submit-u.h"

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
	struct cm_submit_state *state;
	struct cm_store_ca *ca;
	struct cm_store_entry *entry;
	int fd, ret, i;
	void *parent;
	char *p;
	cm_submit_uuid_fixed_for_testing = 1; /* use fixed UUIDs */
	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	parent = talloc_new(NULL);
	if (argc > 2) {
		ca = cm_store_files_ca_read(parent, argv[1]);
		if (ca == NULL) {
			printf("Error reading %s: %s.\n", argv[1],
			       strerror(errno));
			return -1;
		}
		entry = cm_store_files_entry_read(parent, argv[2]);
		if (entry == NULL) {
			printf("Error reading %s: %s.\n", argv[2],
			       strerror(errno));
			return -1;
		}
	} else {
		printf("Specify a CA file and an entry file as the two "
		       "arguments.\n");
		return -1;
	}
	state = cm_submit_start(ca, entry);
	if (state != NULL) {
		for (;;) {
			fd = cm_submit_get_fd(entry, state);
			if (fd != -1) {
				wait_to_read(fd);
			} else {
				sleep(1);
			}
			if (cm_submit_ready(entry, state) == 0) {
				break;
			}
		}
		if (cm_submit_issued(entry, state) == 0) {
			while (strlen(entry->cm_cert) > 0) {
				i = strlen(entry->cm_cert) - 1;
				if (entry->cm_cert[i] == '\n') {
					entry->cm_cert[i] = '\0';
				} else {
					break;
				}
			}
			p = talloc_asprintf(entry, "%s\n", entry->cm_cert);
			talloc_free(entry->cm_cert);
			entry->cm_cert = p;
			printf("%s", entry->cm_cert);
			ret = 0;
		} else
		if (cm_submit_save_ca_cookie(entry, state) == 0) {
			printf("Certificate not issued, saved a cookie.\n");
			ret = 1;
		} else
		if (cm_submit_rejected(entry, state) == 0) {
			if (entry->cm_ca_error != NULL) {
				printf("Request rejected: %s.\n",
				       entry->cm_ca_error);
			} else {
				printf("Request rejected.\n");
			}
			ret = 2;
		} else
		if (cm_submit_unreachable(entry, state) == 0) {
			if (entry->cm_ca_error != NULL) {
				printf("CA was unreachable: %s.\n",
				       entry->cm_ca_error);
			} else {
				printf("CA was unreachable.\n");
			}
			ret = 3;
		} else
		if (cm_submit_unconfigured(entry, state) == 0) {
			if (entry->cm_ca_error != NULL) {
				printf("CA helper was un- or "
				       "under-configured: %s.\n",
				       entry->cm_ca_error);
			} else {
				printf("CA helper was un- or "
				       "under-configured.\n");
			}
			ret = 4;
		} else {
			printf("Can't explain what happened.\n");
			ret = -1;
		}
		cm_submit_done(entry, state);
	} else {
		printf("Failed to start.\n");
		ret = -1;
	}
	cm_store_entry_save(entry);
	talloc_free(parent);
	return ret;
}
