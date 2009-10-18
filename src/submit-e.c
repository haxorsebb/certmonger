/*
 * Copyright (C) 2009 Red Hat, Inc.
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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include "log.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"
#include "submit-int.h"

struct cm_submit_state {
	struct cm_submit_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, count, status;
};

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_submit_e_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return state->fd;
}

/* Check if the CSR was received by the CA yet. */
static int
cm_submit_e_sent(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return 0;
}

/* Save CA-specific identifier for our submitted request. */
static int
cm_submit_e_save_ca_cookie(struct cm_store_entry *entry,
			   struct cm_submit_state *state)
{
	talloc_free(entry->cm_ca_cookie);
	entry->cm_ca_cookie = talloc_strdup(entry, state->msg);
	if (entry->cm_ca_cookie == NULL) {
		cm_log(1, "Out of memory.\n");
		return ENOMEM;
	}
	return 0;
}

/* Pick up after a CSR has been "submitted", in case we haven't yet gotten a
 * decision about it. */
struct cm_submit_state *
cm_submit_e_resume(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	struct cm_submit_state *state = NULL;
	return state;
}

/* Check if an attempt to get status has succeeded. */
static int
cm_submit_e_status_ready(struct cm_store_entry *entry,
		         struct cm_submit_state *state)
{
	ssize_t i, remainder;
	int status;
	do {
		remainder = (sizeof(state->msg) - state->count) - 1;
		i = read(state->fd, state->msg + state->count, remainder);
		switch (i) {
		case -1:
		case 0:
			break;
		default:
			state->count += i;
			break;
		}
	} while (i > 0);
	if ((i == -1) && ((errno == EAGAIN) || (errno == EINTR))) {
		status = -1;
	} else {
		state->msg[state->count] = '\0';
		close(state->fd);
		state->fd = -1;
		waitpid(state->pid, &state->status, 0);
		state->pid = -1;
		status = 0;
	}
	return status;
}

/* Check if the certificate was issued. */
static int
cm_submit_e_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->pid == -1) {
		if (!WIFEXITED(state->status) ||
		    (WEXITSTATUS(state->status) != 0)) {
			return -1;
		}
	}
	if ((strstr(state->msg, "-----BEGIN CERTIFICATE-----") != NULL) &&
	    (strstr(state->msg, "-----END CERTIFICATE-----") != NULL)) {
		talloc_free(entry->cm_cert);
		entry->cm_cert = talloc_strdup(entry, state->msg);
		return 0;
	}
	return -1;
}

/* Check if we need to make another request to actually retrieve the cert. */
static int
cm_submit_e_needs_retrieval(struct cm_store_entry *entry,
			    struct cm_submit_state *state)
{
	return -1;
}

/* Done talking to the CA; clean up. */
static void
cm_submit_e_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_e_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_submit_state *state;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.get_fd = cm_submit_e_get_fd;
		state->pvt.sent = cm_submit_e_sent;
		state->pvt.save_ca_cookie = cm_submit_e_save_ca_cookie;
		state->pvt.status_ready = cm_submit_e_status_ready;
		state->pvt.issued = cm_submit_e_issued;
		state->pvt.needs_retrieval = cm_submit_e_needs_retrieval;
		state->pvt.done = cm_submit_e_done;
		state->fd = -1;
		if (pipe(fds) != -1) {
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(fds[0]);
				close(fds[1]);
				talloc_free(state);
				state = NULL;
				break;
			case 0:
				close(fds[0]);
				execl(ca->cm_ca_external_helper,
				      ca->cm_ca_external_helper,
				      NULL);
				_exit(0);
				break;
			default:
				state->fd = fds[0];
				close(fds[1]);
				break;
			}
		}
	}
	return state;
}
