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

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <talloc.h>
#include <tevent.h>

#include "casave.h"
struct cm_certsave_state;
#include "certsave-int.h"
#include "log.h"
#include "store-int.h"
#include "submit-e.h"
#include "subproc.h"
#include "tdbus.h"

struct cm_casave_state {
	struct cm_subproc_state *subproc;
	int error_fd;
};

static int
cm_casave_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *e,
	       void *data)
{
	struct cm_casave_state *state = data;

	return 0;
}

struct cm_casave_state *
cm_casave_start(struct cm_store_entry *entry, struct cm_store_ca *ca)
{
	struct cm_casave_state *ret;
	void *parent;

	if (entry != NULL) {
		parent = entry;
	} else {
		parent = ca;
	}
	ret = talloc_ptrtype(parent, ret);
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		ret->subproc = cm_subproc_start(cm_casave_main, ca, entry, ret);
		if (ret->subproc == NULL) {
			talloc_free(ret);
			return NULL;
		}
	}
	return ret;
}

int
cm_casave_ready(struct cm_store_entry *entry, struct cm_store_ca *ca,
		struct cm_casave_state *state)
{
	return cm_subproc_ready(NULL, state->subproc);
}

int
cm_casave_get_fd(struct cm_store_entry *entry, struct cm_store_ca *ca,
		 struct cm_casave_state *state)
{
	return cm_subproc_get_fd(NULL, state->subproc);
}

int
cm_casave_saved(struct cm_store_entry *entry, struct cm_store_ca *ca,
		struct cm_casave_state *state)
{
        int status;

	status = cm_subproc_get_exitstatus(NULL, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_CERTSAVE_STATUS_SAVED)) {
		return 0;
	}
	return -1;
}

int
cm_casave_conflict_subject(struct cm_store_entry *entry,
			   struct cm_store_ca *ca,
			   struct cm_casave_state *state)
{
        int status;

	status = cm_subproc_get_exitstatus(NULL, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_CERTSAVE_STATUS_SUBJECT_CONFLICT)) {
		return 0;
	}
	return -1;
}

int
cm_casave_conflict_nickname(struct cm_store_entry *entry,
			    struct cm_store_ca *ca,
			    struct cm_casave_state *state)
{
        int status;

	status = cm_subproc_get_exitstatus(NULL, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_CERTSAVE_STATUS_NICKNAME_CONFLICT)) {
		return 0;
	}
	return -1;
}

int
cm_casave_permissions_error(struct cm_store_entry *entry,
			    struct cm_store_ca *ca,
			    struct cm_casave_state *state)
{
        int status;

	status = cm_subproc_get_exitstatus(NULL, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_CERTSAVE_STATUS_PERMS)) {
		return 0;
	}
	return -1;
}

void
cm_casave_done(struct cm_store_entry *entry, struct cm_store_ca *ca,
	       struct cm_casave_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}
