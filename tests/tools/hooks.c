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

#include "../../src/hook.h"
#include "../../src/log.h"
#include "../../src/store-int.h"
#include "../../src/store.h"
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

static struct cm_store_ca **ca;
static struct cm_store_entry **entry;
static int n_cas, n_entries;

static int
get_n_cas(struct cm_context *ctx)
{
	return n_cas;
}
static struct cm_store_ca *
get_ca_by_index(struct cm_context *ctx, int n)
{
	return ca[n];
}
static int
get_n_entries(struct cm_context *ctx)
{
	return n_entries;
}
static struct cm_store_entry *
get_entry_by_index(struct cm_context *ctx, int n)
{
	return entry[n];
}

int
main(int argc, const char **argv)
{
	struct cm_hook_state *state;
	struct cm_store_ca *tmpca, **tmpcas;
	struct cm_store_entry *tmpentry, **tmpentries;
	int fd, i, c, verbose = 0;
	void *parent;
	const char *name;
	poptContext pctx;
	struct poptOption popts[] = {
		{"ca", 'c', POPT_ARG_STRING, NULL, 'c', NULL, "FILENAME"},
		{"entry", 'e', POPT_ARG_STRING, NULL, 'e', NULL, "FILENAME"},
		{"before-command", 'B', POPT_ARG_STRING, NULL, 'B', NULL, "NICKNAME"},
		{"after-command", 'C', POPT_ARG_STRING, NULL, 'C', NULL, "NICKNAME"},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	cm_log_set_method(cm_log_stderr);
	cm_set_fips_from_env();
	parent = talloc_new(NULL);
	pctx = poptGetContext("hooks", argc, argv, popts, 0);
	if (pctx == NULL) {
		return -1;
	}
	if (argc > 2) {
		while ((c = poptGetNextOpt(pctx)) > 0) {
			cm_log_set_level(verbose);
			switch (c) {
			case 'v':
				verbose++;
				break;
			case 'c':
				name = poptGetOptArg(pctx);
				tmpca = cm_store_files_ca_read(parent, name);
				if (tmpca == NULL) {
					printf("Error reading %s: %s.\n",
					       name, strerror(errno));
					return -1;
				}
				tmpcas = talloc_array_ptrtype(parent, tmpcas,
							      n_cas + 2);
				if (tmpcas == NULL) {
					printf("Out of memory.\n");
					return -1;
				}
				if (n_cas > 0) {
					memcpy(tmpcas, ca,
					       n_cas * sizeof(ca[0]));
				}
				tmpcas[n_cas++] = tmpca;
				tmpcas[n_cas] = NULL;
				ca = tmpcas;
				break;
			case 'e':
				name = poptGetOptArg(pctx);
				tmpentry = cm_store_files_entry_read(parent,
								     name);
				if (tmpentry == NULL) {
					printf("Error reading %s: %s.\n",
					       name, strerror(errno));
					return -1;
				}
				tmpentries = talloc_array_ptrtype(parent,
								  tmpentries,
								  n_entries + 2);
				if (tmpentries == NULL) {
					printf("Out of memory.\n");
					return -1;
				}
				if (n_entries > 0) {
					memcpy(tmpentries, entry,
					       n_entries * sizeof(entry[0]));
				}
				tmpentries[n_entries++] = tmpentry;
				tmpentries[n_entries] = NULL;
				entry = tmpentries;
				break;
			}
		}
		if (c != -1) {
			poptPrintUsage(pctx, stdout, 0);
			return 1;
		}
	} else {
		printf("Specify CA files (-c) and entry files (-e) as "
		       "arguments, and nicknames (-B/-C) for actions.\n");
		poptPrintUsage(pctx, stdout, 0);
		return -1;
	}
	poptResetContext(pctx);
	while ((c = poptGetNextOpt(pctx)) > 0) {
		state = NULL;
		switch (c) {
		case 'B':
			name = poptGetOptArg(pctx);
			for (i = 0; i < n_entries; i++) {
				if (strcmp(name, entry[i]->cm_nickname) == 0) {
					printf("Starting pre-save for entry %s.\n", name);
					state = cm_hook_start_presave(entry[i], NULL,
								      get_ca_by_index,
								      get_n_cas,
								      get_entry_by_index,
								      get_n_entries);
				}
			}
			for (i = 0; i < n_cas; i++) {
				if (strcmp(name, ca[i]->cm_nickname) == 0) {
					printf("Starting pre-save for CA %s.\n", name);
					state = cm_hook_start_ca_presave(ca[i], NULL,
									 get_ca_by_index,
									 get_n_cas,
									 get_entry_by_index,
									 get_n_entries);
				}
			}
			break;
		case 'C':
			name = poptGetOptArg(pctx);
			for (i = 0; i < n_entries; i++) {
				if (strcmp(name, entry[i]->cm_nickname) == 0) {
					printf("Starting post-save for entry %s.\n", name);
					state = cm_hook_start_postsave(entry[i], NULL,
								       get_ca_by_index,
								       get_n_cas,
								       get_entry_by_index,
								       get_n_entries);
				}
			}
			for (i = 0; i < n_cas; i++) {
				if (strcmp(name, ca[i]->cm_nickname) == 0) {
					printf("Starting post-save for CA %s.\n", name);
					state = cm_hook_start_ca_postsave(ca[i], NULL,
									  get_ca_by_index,
									  get_n_cas,
									  get_entry_by_index,
									  get_n_entries);
				}
			}
			break;
		}
		if (state != NULL) {
			for (;;) {
				if (cm_hook_ready(state) == 0) {
					break;
				}
				fd = cm_hook_get_fd(state);
				if (fd != -1) {
					wait_to_read(fd);
				} else {
					sleep(1);
				}
			}
			cm_hook_done(state);
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}
	talloc_free(parent);
	return 0;
}
