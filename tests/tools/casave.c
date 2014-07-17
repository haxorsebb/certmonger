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

#include "../../src/casave.h"
#include "../../src/log.h"
#include "../../src/store-int.h"
#include "../../src/store.h"
#include "tools.h"

struct cm_context {
	struct cm_store_ca **cas;
	size_t n_cas;
	struct cm_store_entry **entries;
	size_t n_entries;
};

static int
get_n_cas(struct cm_context *cm)
{
	return cm->n_cas;
}
static struct cm_store_ca *
get_ca_by_index(struct cm_context *cm, int i)
{
	return cm->cas[i];
}
static int
get_n_entries(struct cm_context *cm)
{
	return cm->n_entries;
}
static struct cm_store_entry *
get_entry_by_index(struct cm_context *cm, int i)
{
	return cm->entries[i];
}

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
	struct cm_casave_state *state;
	struct cm_store_ca *ca, *save_ca = NULL;
	struct cm_store_entry *entry, *save_entry = NULL;
	struct cm_context ctx;
	int c, fd, ret = -1, i;
	unsigned int j;
	void *parent;

	memset(&ctx, 0, sizeof(ctx));
	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	cm_set_fips_from_env();
	parent = talloc_new(NULL);
	while ((c = getopt(argc, argv, "c:e:")) != -1) {
		switch (c) {
		case 'c':
			ca = cm_store_files_ca_read(parent, optarg);
			if (ca == NULL) {
				printf("Error reading CA \"%s\".\n", optarg);
				return -1;
			}
			ctx.cas = talloc_realloc(parent, ctx.cas,
						 struct cm_store_ca *,
						 ctx.n_cas + 2);
			if (ctx.cas == NULL) {
				printf("Out of memory.\n");
				return -1;
			}
			ctx.cas[ctx.n_cas++] = ca;
			ctx.cas[ctx.n_cas] = NULL;
			break;
		case 'e':
			entry = cm_store_files_entry_read(parent, optarg);
			if (entry == NULL) {
				printf("Error reading entry \"%s\".\n", optarg);
				return -1;
			}
			ctx.entries = talloc_realloc(parent, ctx.entries,
						     struct cm_store_entry *,
						     ctx.n_entries + 2);
			if (ctx.entries == NULL) {
				printf("Out of memory.\n");
				return -1;
			}
			ctx.entries[ctx.n_entries++] = entry;
			ctx.entries[ctx.n_entries] = NULL;
			break;
		default:
			printf("Specify CA (-c) and entry (-e) files as "
			       "arguments.\n");
			return -1;
			break;
		}
	}
	if (optind == argc) {
		printf("No CA or entry names specified.\n");
		return -1;
	}
	for (i = optind; i < argc; i++) {
		for (j = 0; j < ctx.n_cas; j++) {
			if (strcmp(argv[i], ctx.cas[j]->cm_nickname) == 0) {
				save_ca = ctx.cas[j];
			}
		}
		for (j = 0; j < ctx.n_entries; j++) {
			if (strcmp(argv[i], ctx.entries[j]->cm_nickname) == 0) {
				save_entry = ctx.entries[j];
			}
		}
	}
	if ((save_ca == NULL) && (save_entry == NULL)) {
		printf("No known CA or entry names.\n");
		return -1;
	}
	state = cm_casave_start(save_entry, save_ca, &ctx,
				&get_ca_by_index,
				&get_n_cas,
				&get_entry_by_index,
				&get_n_entries);
	if (state != NULL) {
		for (;;) {
			if (cm_casave_ready(state) == 0) {
				break;
			}
			fd = cm_casave_get_fd(state);
			if (fd != -1) {
				wait_to_read(fd);
			} else {
				sleep(1);
			}
		}
		if (cm_casave_saved(state) == 0) {
			ret = 0;
		} else
		if (cm_casave_permissions_error(state) == 0) {
			printf("Permissions error.\n");
			ret = 1;
		} else
		if (cm_casave_conflict_nickname(state) == 0) {
			printf("Unresolvable nickname conflict.\n");
			ret = 2;
		} else
		if (cm_casave_conflict_subject(state) == 0) {
			printf("Unresolvable subject name conflict.\n");
			ret = 3;
		} else {
			printf("Unknown error.\n");
			ret = -1;
		}
		cm_casave_done(state);
	} else {
		printf("Failed to start.\n");
		ret = -1;
	}
	for (j = 0; j < ctx.n_cas; j++) {
		cm_store_ca_save(ctx.cas[j]);
	}
	for (j = 0; j < ctx.n_entries; j++) {
		cm_store_entry_save(ctx.entries[j]);
	}
	talloc_free(parent);
	return ret;
}
