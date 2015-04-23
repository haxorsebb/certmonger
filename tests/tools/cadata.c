/*
 * Copyright (C) 2014,2015 Red Hat, Inc.
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

#include <popt.h>

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
main(int argc, const char **argv)
{
	struct cm_cadata_state *state;
	struct cm_store_ca *ca;
	int c, fd, ret = CM_SUBMIT_STATUS_REJECTED;
	int iflag = 0, cflag = 0, pflag = 0, dflag = 0, eflag = 0, rflag = 0;
	int Cflag = 0, sflag = 0, verbose = 0;
	const char *cafile;
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
	poptContext pctx;
	struct poptOption popts[] = {
		{"identity", 'i', POPT_ARG_NONE, &iflag, 0, NULL, NULL},
		{"root-certs", 'c', POPT_ARG_NONE, &cflag, 0, NULL, NULL},
		{"profiles", 'p', POPT_ARG_NONE, &pflag, 0, NULL, NULL},
		{"default-profile", 'd', POPT_ARG_NONE, &dflag, 0, NULL, NULL},
		{"enroll-reqs", 'e', POPT_ARG_NONE, &eflag, 0, NULL, NULL},
		{"renew-reqs", 'r', POPT_ARG_NONE, &rflag, 0, NULL, NULL},
		{"capabilities", 'C', POPT_ARG_NONE, &Cflag, 0, NULL, NULL},
		{"encryption-certs", 's', POPT_ARG_NONE, &sflag, 0, NULL, NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	pctx = poptGetContext("cadata", argc, argv, popts, 0);
	if (pctx == NULL) {
		return 1;
	}
	poptSetOtherOptionHelp(pctx, "[options...] cafile");
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}
	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(verbose);
	cm_set_fips_from_env();
	parent = talloc_new(NULL);
	cafile = poptGetArg(pctx);
	if (cafile != NULL) {
		ca = cm_store_files_ca_read(parent, cafile);
		if (ca == NULL) {
			printf("Error reading %s: %s.\n", cafile,
			       strerror(errno));
			return -1;
		}
	} else {
		printf("Specify a CA file as an argument.\n");
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
