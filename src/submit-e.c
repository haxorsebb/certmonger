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
#include <fcntl.h>
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

enum cm_external_status {
	STATUS_ISSUED = 0,
	STATUS_WAIT = 1,
	STATUS_REJECTED = 2,
	STATUS_UNREACHABLE = 3,
};

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

/* Check if we're done trying to send the CSR to the CA yet. */
static int
cm_submit_e_sent(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	ssize_t i, remainder;
	int status;
	if (state->pid == -1) {
		cm_log(1, "Certificate already sent.\n");
		return 0;
	} else {
		do {
			remainder = (sizeof(state->msg) - state->count) - 1;
			i = read(state->fd, state->msg + state->count,
				 remainder);
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
			cm_log(1, "Certificate not submitted yet.\n");
		} else {
			state->msg[state->count] = '\0';
			close(state->fd);
			state->fd = -1;
			waitpid(state->pid, &state->status, 0);
			cm_log(1, "Child status = %d.\n",
			       WEXITSTATUS(state->status));
			state->pid = -1;
			cm_log(1, "Certificate submitted.\n");
			status = 0;
		}
		return status;
	}
}

/* Try to save a CA-specific identifier for our submitted request.  That is, if
 * it even gave us one. */
static int
cm_submit_e_save_ca_cookie(struct cm_store_entry *entry,
			   struct cm_submit_state *state)
{
	talloc_free(entry->cm_ca_cookie);
	entry->cm_ca_cookie = NULL;
	if (state->pid == -1) {
		if (WIFEXITED(state->status) &&
		    (WEXITSTATUS(state->status) == STATUS_WAIT)) {
			entry->cm_ca_cookie = talloc_strdup(entry, state->msg);
			if (entry->cm_ca_cookie == NULL) {
				cm_log(1, "Out of memory.\n");
				return -ENOMEM;
			}
			cm_log(1, "Saved cookie.\n");
			return 0;
		} else {
			cm_log(1, "Helper still running; no cookie.\n");
		}
	}
	return -1;
}

/* Check if an attempt to get status has succeeded. */
static int
cm_submit_e_status_ready(struct cm_store_entry *entry,
		         struct cm_submit_state *state)
{
	ssize_t i, remainder;
	int status;
	if (state->pid == -1) {
		cm_log(1, "Certificate status ready.\n");
		return 0;
	} else {
		do {
			remainder = (sizeof(state->msg) - state->count) - 1;
			i = read(state->fd, state->msg + state->count,
				 remainder);
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
			cm_log(1, "Certificate status NOT ready yet.\n");
		} else {
			state->msg[state->count] = '\0';
			close(state->fd);
			state->fd = -1;
			waitpid(state->pid, &state->status, 0);
			cm_log(1, "Child status = %d.\n",
			       WEXITSTATUS(state->status));
			state->pid = -1;
			cm_log(1, "Certificate status ready.\n");
			status = 0;
		}
		return status;
	}
}

/* Check if the certificate was issued.  If the exit status was 0, it was
 * issued. */
static int
cm_submit_e_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->pid == -1) {
		if (!WIFEXITED(state->status) ||
		    (WEXITSTATUS(state->status) != STATUS_ISSUED)) {
			return -1;
		}
	}
	if ((strstr(state->msg, "-----BEGIN CERTIFICATE-----") != NULL) &&
	    (strstr(state->msg, "-----END CERTIFICATE-----") != NULL)) {
		talloc_free(entry->cm_cert);
		entry->cm_cert = talloc_strdup(entry, state->msg);
		cm_log(1, "Certificate issued.\n");
		return 0;
	} else {
		cm_log(1, "No issued certificate read.\n");
		return -1;
	}
}

/* Check if the certificate was issued.  If the exit status was 0, it was
 * issued. */
static int
cm_submit_e_rejected(struct cm_store_entry *entry,
		     struct cm_submit_state *state)
{
	if (state->pid == -1) {
		if (WIFEXITED(state->status) &&
		    (WEXITSTATUS(state->status) == STATUS_REJECTED)) {
			return 0;
		}
	}
	return -1;
}

/* Check if the CA was unreachable.  If the exit status was right, then we
 * never actually talked to the CA. */
static int
cm_submit_e_unreachable(struct cm_store_entry *entry,
			struct cm_submit_state *state)
{
	if (state->pid == -1) {
		if (WIFEXITED(state->status) &&
		    (WEXITSTATUS(state->status) == STATUS_UNREACHABLE)) {
			return 0;
		}
	}
	return -1;
}

/* Check if we need to make another request to actually retrieve the cert. */
static int
cm_submit_e_needs_retrieval(struct cm_store_entry *entry,
			    struct cm_submit_state *state)
{
	/* We never do. */
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
cm_submit_e_start_or_resume(struct cm_store_ca *ca,
			    struct cm_store_entry *entry,
			    const char *input,
			    const char *operation)
{
	int outfds[2], execfds[2], i;
	unsigned char u;
	struct cm_submit_state *state;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		outfds[0] = -1;
		outfds[1] = -1;
		execfds[0] = -1;
		execfds[1] = -1;
		memset(state, 0, sizeof(*state));
		state->pvt.get_fd = cm_submit_e_get_fd;
		state->pvt.sent = cm_submit_e_sent;
		state->pvt.save_ca_cookie = cm_submit_e_save_ca_cookie;
		state->pvt.status_ready = cm_submit_e_status_ready;
		state->pvt.issued = cm_submit_e_issued;
		state->pvt.rejected = cm_submit_e_rejected;
		state->pvt.unreachable = cm_submit_e_unreachable;
		state->pvt.needs_retrieval = cm_submit_e_needs_retrieval;
		state->pvt.done = cm_submit_e_done;
		state->fd = -1;
		if ((pipe(outfds) != -1) && (pipe(execfds) != -1)) {
			fcntl(execfds[0], F_SETFD, 1L);
			fcntl(execfds[1], F_SETFD, 1L);
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(outfds[0]);
				close(outfds[1]);
				close(execfds[0]);
				close(execfds[1]);
				talloc_free(state);
				state = NULL;
				break;
			case 0:
				if (dup2(outfds[1], STDOUT_FILENO) == -1) {
					u = errno;
					write(execfds[1], &u, 1);
					_exit(u);
				}
				close(outfds[0]);
				close(outfds[1]);
				setenv("CERTMONGER_OPERATION", operation, 1);
				setenv("CERTMONGER_INPUT", input, 1);
				cm_log(1, "Running helper \"%s\".\n",
				       ca->cm_ca_external_helper);
				for (i = sysconf(_SC_OPEN_MAX) - 1;
						 i >= 0;
						 i--) {
					if ((i != STDOUT_FILENO) &&
					    (i != STDERR_FILENO)) {
						close(i);
					}
				}
				execlp(ca->cm_ca_external_helper,
				       ca->cm_ca_external_helper,
				       NULL);
				u = errno;
				write(execfds[1], &u, 1);
				_exit(u);
				break;
			default:
				state->fd = outfds[0];
				close(outfds[1]);
				close(execfds[1]);
				switch (read(execfds[0], &u, 1)) {
				case 0:
					/* no data = kernel closed-on-exec, so
					 * the helper started */
					break;
				case -1:
					/* huh? */
					cm_log(1, "Unexpected error while "
					       "starting helper \"%s\".",
					       ca->cm_ca_external_helper);
					close(outfds[0]);
					close(outfds[1]);
					close(execfds[0]);
					close(execfds[1]);
					talloc_free(state);
					state = NULL;
					break;
				default:
					cm_log(1, "Error while starting helper "
					       "\"%s\": %s.",
					       ca->cm_ca_external_helper,
					       strerror(u));
					close(outfds[0]);
					close(outfds[1]);
					close(execfds[0]);
					close(execfds[1]);
					talloc_free(state);
					state = NULL;
					break;
				}
				break;
			}
		}
	}
	return state;
}

/* Pick up after a CSR has been "submitted", in case we haven't yet gotten a
 * decision about it. */
struct cm_submit_state *
cm_submit_e_resume(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	return cm_submit_e_start_or_resume(ca, entry, entry->cm_csr, "POLL");
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_e_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	return cm_submit_e_start_or_resume(ca, entry, entry->cm_csr, "SUBMIT");
}
