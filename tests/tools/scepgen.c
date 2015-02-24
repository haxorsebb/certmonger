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
#include <sys/select.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include <krb5.h>

#include "../../src/log.h"
#include "../../src/scepgen.h"
#include "../../src/store.h"
#include "../../src/store-int.h"
#include "../../src/submit-u.h"
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
	struct cm_scepgen_state *state;
	struct cm_store_ca *ca;
	struct cm_store_entry *entry;
	int fd, ret;
	void *parent;

	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	cm_set_fips_from_env();
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
			return 1;
		}
	} else {
		printf("Specify a CA file and an entry file as the two "
		       "arguments.\n");
		return 1;
	}
	state = cm_scepgen_start(ca, entry);
	if (state != NULL) {
		for (;;) {
			fd = cm_scepgen_get_fd(state);
			if (fd != -1) {
				wait_to_read(fd);
			} else {
				sleep(1);
			}
			if (cm_scepgen_ready(state) == 0) {
				break;
			}
		}
		if (cm_scepgen_save_scep(state) == 0) {
			if (entry->cm_minicert != NULL) {
				printf("minicert:%s\n", entry->cm_minicert);
			}
			if (entry->cm_scep_tx != NULL) {
				printf("tx:%s\n", entry->cm_scep_tx);
			}
			if (entry->cm_scep_nonce != NULL) {
				printf("nonce:%s\n", entry->cm_scep_nonce);
			}
			if (entry->cm_scep_req != NULL) {
				printf("req:%s\n",
				       cm_submit_u_base64_from_text(entry->cm_scep_req));
			}
			if (entry->cm_scep_gic != NULL) {
				printf("gic:%s\n",
				       cm_submit_u_base64_from_text(entry->cm_scep_gic));
			}
			if (entry->cm_scep_req_next != NULL) {
				printf("req(next):%s\n",
				       cm_submit_u_base64_from_text(entry->cm_scep_req_next));
			}
			if (entry->cm_scep_gic_next != NULL) {
				printf("gic(next):%s\n",
				       cm_submit_u_base64_from_text(entry->cm_scep_gic_next));
			}
			ret = 0;
		} else {
			printf("Failed to save.\n");
			if (cm_scepgen_need_token(state) == 0) {
				printf("(Need token.)\n");
			} else
			if (cm_scepgen_need_pin(state) == 0) {
				printf("(Need PIN.)\n");
			} else
			if (cm_scepgen_need_encryption_certs(state) == 0) {
				printf("(Need server certificates.)\n");
			}
			ret = 1;
		}
		cm_scepgen_done(state);
	} else {
		printf("Failed to start.\n");
		ret = 1;
	}
	cm_store_entry_save(entry);
	talloc_free(parent);
	return ret;
}
