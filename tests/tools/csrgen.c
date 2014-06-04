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
#include <talloc.h>
#include <unistd.h>

#include "../../src/csrgen.h"
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
	struct cm_csrgen_state *state;
	struct cm_store_entry *entry;
	int fd, ret, i;
	void *parent;
	char *p;
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
	state = cm_csrgen_start(entry);
	if (state != NULL) {
		for (;;) {
			fd = cm_csrgen_get_fd(state);
			if (fd != -1) {
				wait_to_read(fd);
			} else {
				sleep(1);
			}
			if (cm_csrgen_ready(state) == 0) {
				break;
			}
		}
		if (cm_csrgen_save_csr(state) == 0) {
			while (strlen(entry->cm_csr) > 0) {
				i = strlen(entry->cm_csr) - 1;
				if (entry->cm_csr[i] == '\n') {
					entry->cm_csr[i] = '\0';
				} else {
					break;
				}
			}
			p = talloc_asprintf(entry, "%s\n", entry->cm_csr);
			talloc_free(entry->cm_csr);
			entry->cm_csr = p;
			printf("%s", entry->cm_csr);
			ret = 0;
		} else {
			printf("Failed to save.\n");
			if (cm_csrgen_need_token(state) == 0) {
				printf("(Need token.)\n");
			} else
			if (cm_csrgen_need_pin(state) == 0) {
				printf("(Need PIN.)\n");
			}
			ret = 1;
		}
		cm_csrgen_done(state);
	} else {
		printf("Failed to start.\n");
		ret = 1;
	}
	cm_store_entry_save(entry);
	talloc_free(parent);
	return ret;
}
