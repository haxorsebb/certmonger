/*
 * Copyright (C) 2009,2011,2012 Red Hat, Inc.
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
#include "submit-e.h"
#include "submit-int.h"
#include "subproc.h"

struct cm_submit_state {
	struct cm_submit_state_pvt pvt;
	struct cm_subproc_state *subproc;
};

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_submit_e_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Try to save a CA-specific identifier for our submitted request.  That is, if
 * it even gave us one. */
static int
cm_submit_e_save_ca_cookie(struct cm_store_entry *entry,
			   struct cm_submit_state *state)
{
	int status;
	long delay;
	const char *msg;
	char *p;
	talloc_free(entry->cm_ca_cookie);
	entry->cm_ca_cookie = NULL;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    ((WEXITSTATUS(status) == CM_STATUS_WAIT) ||
	     (WEXITSTATUS(status) == CM_STATUS_WAIT_WITH_DELAY))) {
		msg = cm_subproc_get_msg(entry, state->subproc, NULL);
		if ((msg != NULL) && (strlen(msg) > 0)) {
			if (WEXITSTATUS(status) == CM_STATUS_WAIT_WITH_DELAY) {
				delay = strtol(msg, &p, 10);
				if ((p == NULL) ||
				    (strchr("\r\n", *p) == NULL)) {
					cm_log(1, "Error parsing result: %s.\n",
					       msg);
					return -1;
				}
				state->pvt.delay = delay;
				msg = p + strspn(p, "\r\n");
			}
			entry->cm_ca_cookie = talloc_strdup(entry, msg);
			if (entry->cm_ca_cookie == NULL) {
				cm_log(1, "Out of memory.\n");
				return -ENOMEM;
			}
			cm_log(1, "Saved cookie.\n");
			return 0;
		} else {
			cm_log(1, "No cookie.\n");
			return -1;
		}
	}
	return -1;
}

/* Check if an attempt to submit the CSR has completed. */
static int
cm_submit_e_ready(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	int status, ready;
	const char *msg;
	ready = cm_subproc_ready(entry, state->subproc);
	switch (ready) {
	case 0:
		status = cm_subproc_get_exitstatus(entry, state->subproc);
		cm_log(1, "Certificate submission attempt complete.\n");
		if (WIFEXITED(status)) {
			cm_log(1, "Child status = %d.\n", WEXITSTATUS(status));
			msg = cm_subproc_get_msg(entry, state->subproc, NULL);
			if ((msg != NULL) && (strlen(msg) > 0)) {
				cm_log(1, "Child output:\n%s\n", msg);
				/* If it's a single line, assume it's
				 * log-worthy. */
				if (strcspn(msg, "\n") >= (strlen(msg) - 2)) {
					cm_log(0, "%s", msg);
				}
				/* If it was an error, save it. */
				if ((WEXITSTATUS(status) != CM_STATUS_ISSUED) &&
				    (WEXITSTATUS(status) != CM_STATUS_WAIT) &&
				    (WEXITSTATUS(status) != CM_STATUS_WAIT_WITH_DELAY)) {
					talloc_free(entry->cm_ca_error);
					entry->cm_ca_error =
						talloc_strndup(entry, msg,
							       strcspn(msg,
								       "\r\n"));
				}
			}
			return 0;
		} else {
			cm_log(1, "Child exited unexpectedly.\n");
			return 0;
		}
		break;
	default:
		cm_log(1, "Certificate submission still ongoing.\n");
		return -1;
		break;
	}
}

/* Check if the certificate was issued.  If the exit status was 0, it was
 * issued. */
static int
cm_submit_e_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	const char *msg;
	msg = cm_subproc_get_msg(entry, state->subproc, NULL);
	if ((strstr(msg, "-----BEGIN CERTIFICATE-----") != NULL) &&
	    (strstr(msg, "-----END CERTIFICATE-----") != NULL)) {
		talloc_free(entry->cm_cert);
		entry->cm_cert = talloc_strdup(entry, msg);
		cm_log(1, "Certificate issued.\n");
		return 0;
	} else {
		cm_log(1, "No issued certificate read.\n");
		return -1;
	}
}

/* Check if the submission helper is just unconfigured. */
static int
cm_submit_e_unconfigured(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_UNCONFIGURED)) {
		return 0;
	}
	return -1;
}

/* Check if the certificate was issued.  If the exit status was 0, it was
 * issued. */
static int
cm_submit_e_rejected(struct cm_store_entry *entry,
		     struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == CM_STATUS_REJECTED)) {
		return 0;
	}
	return -1;
}

/* Check if the CA was unreachable.  If the exit status was right, then we
 * never actually talked to the CA. */
static int
cm_submit_e_unreachable(struct cm_store_entry *entry,
			struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_UNREACHABLE)) {
		return 0;
	}
	return -1;
}

/* Done talking to the CA; clean up. */
static void
cm_submit_e_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}

/* Attempt to exec the helper. */
struct cm_submit_e_args {
	int error_fd;
	const char *csr, *cookie, *operation;
};

static int
cm_submit_e_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	struct cm_submit_e_args *args = userdata;
	char **argv;
	const char *error;
	unsigned char u;
	if (entry->cm_template_subject != NULL) {
		setenv(CM_SUBMIT_REQ_SUBJECT_ENV,
		       entry->cm_template_subject, 1);
	}
	if (entry->cm_template_email != NULL) {
		setenv(CM_SUBMIT_REQ_EMAIL_ENV,
		       cm_submit_maybe_joinv(NULL, "\n",
					     entry->cm_template_email),
		       1);
	}
	if (entry->cm_template_hostname != NULL) {
		setenv(CM_SUBMIT_REQ_HOSTNAME_ENV,
		       cm_submit_maybe_joinv(NULL, "\n",
					     entry->cm_template_hostname),
		       1);
	}
	if (entry->cm_template_principal != NULL) {
		setenv(CM_SUBMIT_REQ_PRINCIPAL_ENV,
		       cm_submit_maybe_joinv(NULL, "\n",
					     entry->cm_template_principal),
		       1);
	}
	if ((args->operation != NULL) && (strlen(args->operation) > 0)) {
		setenv(CM_SUBMIT_OPERATION_ENV, args->operation, 1);
	}
	if ((args->csr != NULL) && (strlen(args->csr) > 0)) {
		setenv(CM_SUBMIT_CSR_ENV, args->csr, 1);
	}
	if ((args->cookie != NULL) && (strlen(args->cookie) > 0)) {
		setenv(CM_SUBMIT_COOKIE_ENV, args->cookie, 1);
	}
	if ((entry->cm_ca_profile != NULL) &&
	    (strlen(entry->cm_ca_profile) > 0)) {
		setenv(CM_SUBMIT_PROFILE_ENV, entry->cm_ca_profile, 1);
	}
	if ((entry->cm_cert != NULL) && (strlen(entry->cm_cert) > 0)) {
		setenv(CM_SUBMIT_CERTIFICATE_ENV, entry->cm_cert, 1);
	}
	if (dup2(fd, STDOUT_FILENO) == -1) {
		u = errno;
		cm_log(1, "Error redirecting standard out for "
		       "enrollment helper: %s.\n",
		       strerror(errno));
		if (write(args->error_fd, &u, 1) != 1) {
			cm_log(1, "Error sending error result to parent.\n");
		}
		return u;
	}
	error = NULL;
	argv = cm_subproc_parse_args(ca, ca->cm_ca_external_helper, &error);
	if (argv == NULL) {
		if (error != NULL) {
			cm_log(0, "Error parsing \"%s\": %s.\n",
			       ca->cm_ca_external_helper, error);
		} else {
			cm_log(0, "Error parsing \"%s\".\n",
			       ca->cm_ca_external_helper);
		}
		return -1;
	}
	cm_subproc_mark_most_cloexec(entry, STDOUT_FILENO);
	cm_log(1, "Running enrollment helper \"%s\".\n", argv[0]);
	execvp(argv[0], argv);
	u = errno;
	if (write(args->error_fd, &u, 1) != 1) {
		cm_log(1, "Error sending error result to parent.\n");
	}
	return u;
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_e_start_or_resume(struct cm_store_ca *ca,
			    struct cm_store_entry *entry,
			    const char *csr,
			    const char *cookie,
			    const char *operation)
{
	int errorfds[2];
	unsigned char u;
	struct cm_submit_state *state;
	struct cm_submit_e_args args;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.get_fd = cm_submit_e_get_fd;
		state->pvt.save_ca_cookie = cm_submit_e_save_ca_cookie;
		state->pvt.ready = cm_submit_e_ready;
		state->pvt.issued = cm_submit_e_issued;
		state->pvt.rejected = cm_submit_e_rejected;
		state->pvt.unreachable = cm_submit_e_unreachable;
		state->pvt.unconfigured = cm_submit_e_unconfigured;
		state->pvt.done = cm_submit_e_done;
		state->pvt.delay = -1;
		if (pipe(errorfds) != -1) {
			fcntl(errorfds[1], F_SETFD, 1L);
			args.error_fd = errorfds[1];
			args.csr = csr;
			args.cookie = cookie;
			args.operation = operation;
			state->subproc = cm_subproc_start(cm_submit_e_main,
							  ca, entry, &args);
			close(errorfds[1]);
			if (state->subproc == NULL) {
				talloc_free(state);
				state = NULL;
			} else {
				switch (read(errorfds[0], &u, 1)) {
				case 0:
					/* no data = kernel closed-on-exec, so
					 * the helper started */
					break;
				case -1:
					/* huh? */
					cm_log(-1, "Unexpected error while "
					       "starting helper \"%s\".",
					       ca->cm_ca_external_helper);
					cm_subproc_done(entry, state->subproc);
					talloc_free(state);
					state = NULL;
					break;
				default:
					cm_log(-1,
					       "Error while starting helper "
					       "\"%s\": %s.",
					       ca->cm_ca_external_helper,
					       strerror(u));
					cm_subproc_done(entry, state->subproc);
					talloc_free(state);
					state = NULL;
					break;
				}
			}
			close(errorfds[0]);
		}
	}
	return state;
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_e_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	if ((entry->cm_ca_cookie != NULL) &&
	    (strlen(entry->cm_ca_cookie) > 0)) {
		return cm_submit_e_start_or_resume(ca, entry, entry->cm_csr,
						   entry->cm_ca_cookie, "POLL");
	} else {
		return cm_submit_e_start_or_resume(ca, entry, entry->cm_csr,
						   entry->cm_ca_cookie,
						   "SUBMIT");
	}
}

const char *
cm_submit_e_status_text(enum cm_external_status status)
{
	switch (status) {
	case CM_STATUS_ISSUED: return "ISSUED";
	case CM_STATUS_WAIT: return "WAIT";
	case CM_STATUS_REJECTED: return "REJECTED";
	case CM_STATUS_UNREACHABLE: return "UNREACHABLE";
	case CM_STATUS_UNCONFIGURED: return "UNCONFIGURED";
	case CM_STATUS_WAIT_WITH_DELAY: return "WAIT_WITH_DELAY";
	}
	return "(unknown)";
}
