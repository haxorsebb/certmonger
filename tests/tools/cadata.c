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
#include <sys/select.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <krb5.h>

#include <talloc.h>

#include "../../src/cadata.h"
#include "../../src/log.h"
#include "../../src/store-int.h"
#include "../../src/store.h"
#include "../../src/submit-e.h"
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
	struct cm_cadata_state *state;
	struct cm_store_ca *ca;
	int c, fd, ret = CM_SUBMIT_STATUS_REJECTED;
	int iflag = 0, cflag = 0, pflag = 0, dflag = 0, eflag = 0, rflag = 0;
	int Cflag = 0, sflag = 0;
	unsigned i;
	void *parent;
	struct {
		struct cm_cadata_state * (*start)(struct cm_store_ca *);
		int *flag;
	} flags[] = {
		{cm_cadata_start_identify, &iflag},
		{cm_cadata_start_certs, &cflag},
		{cm_cadata_start_profiles, &pflag},
		{cm_cadata_start_default_profile, &dflag},
		{cm_cadata_start_enroll_reqs, &eflag},
		{cm_cadata_start_renew_reqs, &rflag},
		{cm_cadata_start_capabilities, &Cflag},
		{cm_cadata_start_encryption_certs, &sflag},
	};

	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	cm_set_fips_from_env();
	parent = talloc_new(NULL);
	while ((c = getopt(argc, argv, "icpderCs")) != -1) {
		switch (c) {
		case 'i':
			iflag++;
			break;
		case 'c':
			cflag++;
			break;
		case 'p':
			pflag++;
			break;
		case 'd':
			dflag++;
			break;
		case 'e':
			eflag++;
			break;
		case 'r':
			rflag++;
			break;
		case 'C':
			Cflag++;
			break;
		case 's':
			sflag++;
			break;
		}
	}
	if (argc - optind > 0) {
		ca = cm_store_files_ca_read(parent, argv[optind]);
		if (ca == NULL) {
			printf("Error reading %s: %s.\n", argv[optind],
			       strerror(errno));
			return -1;
		}
	} else {
		printf("Specify a CA file as the argument.\n");
		return -1;
	}
	for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		if (*(flags[i].flag) == 0) {
			continue;
		}
		state = (*(flags[i].start))(ca);
		if (state != NULL) {
			for (;;) {
				fd = cm_cadata_get_fd(state);
				if (fd != -1) {
					wait_to_read(fd);
				} else {
					sleep(1);
				}
				if (cm_cadata_ready(state) == 0) {
					break;
				}
			}
			if (cm_cadata_unsupported(state) == 0) {
				printf("Helper doesn't implement.\n");
				ret = CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
			} else
			if (cm_cadata_unreachable(state) == 0) {
				printf("CA was unreachable.\n");
				ret = CM_SUBMIT_STATUS_UNREACHABLE;
			} else
			if (cm_cadata_unconfigured(state) == 0) {
				printf("CA helper was un- or "
				       "under-configured.\n");
				ret = CM_SUBMIT_STATUS_UNCONFIGURED;
			} else
			if (cm_cadata_modified(state) == 0) {
				ret = CM_SUBMIT_STATUS_ISSUED;
			} else {
				printf("CA helper provided data.\n");
				ret = -1;
			}
			cm_cadata_done(state);
		} else {
			printf("Failed to start.\n");
			ret = -1;
		}
	}
	cm_store_ca_save(ca);
	talloc_free(parent);
	return ret;
}
