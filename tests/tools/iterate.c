/*
 * Copyright (C) 2009,2010,2011 Red Hat, Inc.
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
#include <sys/param.h>
#include <sys/select.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include "../../src/iterate.h"
#include "../../src/log.h"
#include "../../src/store.h"
#include "../../src/store-int.h"

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

struct cm_context {
	struct cm_store_ca *ca;
};

static struct cm_store_ca *
get_ca_by_index(struct cm_context *cm, int i)
{
	if (i == 0) {
		return cm->ca;
	} else {
		return NULL;
	}
}

static int
get_n_cas(struct cm_context *cm)
{
	return (cm->ca != NULL) ? 1 : 0;
}

int
main(int argc, char **argv)
{
	struct cm_store_entry *entry;
	struct cm_context cm;
	enum cm_state old_state;
	int readfd, delay;
	void *parent, *istate;
	char *p, *q, *states, *tmp;
	enum cm_time when;
	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	parent = talloc_new(NULL);
	if (argc > 3) {
		cm.ca = cm_store_files_ca_read(parent, argv[1]);
		if (cm.ca == NULL) {
			printf("Error reading %s: %s.\n", argv[1],
			       strerror(errno));
			return 1;
		}
		entry = cm_store_files_entry_read(parent, argv[2]);
		if (entry == NULL) {
			printf("Error reading %s: %s.\n", argv[2],
			       strerror(errno));
			return 1;
		}
		if ((entry->cm_ca_nickname == NULL) ||
		    (cm.ca->cm_nickname == NULL) ||
		    (strcasecmp(entry->cm_ca_nickname,
				cm.ca->cm_nickname) != 0)) {
			talloc_free(cm.ca);
			cm.ca = NULL;
		}
		states = argv[3];
	} else {
		printf("Specify a CA file and an entry file as the first "
		       "two arguments, and a list of states as the third.\n");
		return 1;
	}
	if (cm_iterate_init(entry, &istate) != 0) {
		printf("Error initializing.\n");
		return 1;
	}
	old_state = entry->cm_state;
	printf("%s\n-START-\n",
	       cm_store_state_as_string(entry->cm_state));
	fflush(NULL);
	p = states;
	while (cm_iterate(entry, cm.ca, &cm, get_ca_by_index, get_n_cas,
			  NULL, NULL, istate, &when, &delay, &readfd) == 0) {
		/* Check if this state is in our continue-states list. */
		for (p = states; *p != '\0'; p = q + strspn(q, ",")) {
			q = p + strcspn(p, ",");
			tmp = talloc_strndup(parent, p, q - p);
			if (entry->cm_state ==
			    cm_store_state_from_string(tmp)) {
				if (entry->cm_state != old_state) {
					printf("%s\n", tmp);
				}
				fflush(NULL);
				talloc_free(tmp);
				break;
			}
			talloc_free(tmp);
		}
		if (when == cm_time_delay) {
			printf("delay=%ld\n", (long) delay);
		}
		/* If we didn't find a match, stop here. */
		if (*p == '\0') {
			printf("%s\n-STOP-\n",
			       cm_store_state_as_string(entry->cm_state));
			fflush(NULL);
			break;
		}
		/* Reset 'p' so that it's not an empty string. */
		p = states;
		old_state = entry->cm_state;
		/* Wait. */
		switch (when) {
		case cm_time_now:
			break;
		case cm_time_soon:
			sleep(CM_DELAY_SOON);
			break;
		case cm_time_soonish:
			sleep(CM_DELAY_SOONISH);
			break;
		case cm_time_delay:
			sleep(delay);
			break;
		case cm_time_no_time:
			wait_to_read(readfd);
			break;
		}
	}
	if (*p != '\0') {
		printf("%s\n-ERROR-\n",
		       cm_store_state_as_string(entry->cm_state));
		fflush(NULL);
	}
	cm_iterate_done(entry, istate);
	talloc_free(parent);
	return 0;
}
