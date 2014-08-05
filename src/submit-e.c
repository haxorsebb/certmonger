/*
 * Copyright (C) 2009,2011,2012,2013,2014 Red Hat, Inc.
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
#include <time.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include "env.h"
#include "log.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"
#include "submit-e.h"
#include "submit-int.h"
#include "subproc.h"

/* Clean up a cookie value in a way that's compatible with what happens when we
 * save and then reload an entry: if the value fits on a single line (whether
 * or not it ends with a newline), we strip the newline off of the end.
 * Otherwise we strip out blank lines and make sure they end with a single
 * character. */
static char *
sanitize(void *parent, const char *value)
{
	const char *p, *q;
	char *ret;

	p = value + strcspn(value, "\r\n");
	ret = talloc_strndup(parent, value, p - value);
	if (ret != NULL) {
		p += strspn(p, "\r\n");
		if (*p != '\0') {
			ret = talloc_strdup_append(ret, "\n");
		}
		while (*p != '\0') {
			q = p + strcspn(p, "\r\n");
			ret = talloc_asprintf_append(ret, "%.*s\n",
						     (int) (q - p), p);
			if (*q == '\r') {
				q++;
			}
			if (*q == '\n') {
				q++;
			}
			if (p == q) {
				break;
			}
			p = q;
		}
	}
	return ret;
}

/* Try to save a CA-specific identifier for our submitted request.  That is, if
 * it even gave us one. */
static int
cm_submit_e_save_ca_cookie(struct cm_submit_state *state)
{
	int status;
	long delay;
	const char *msg;
	char *p;

	talloc_free(state->entry->cm_ca_cookie);
	state->entry->cm_ca_cookie = NULL;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    ((WEXITSTATUS(status) == CM_SUBMIT_STATUS_WAIT) ||
	     (WEXITSTATUS(status) == CM_SUBMIT_STATUS_WAIT_WITH_DELAY))) {
		msg = cm_subproc_get_msg(state->subproc, NULL);
		if ((msg != NULL) && (strlen(msg) > 0)) {
			if (WEXITSTATUS(status) ==
			    CM_SUBMIT_STATUS_WAIT_WITH_DELAY) {
				delay = strtol(msg, &p, 10);
				if ((p == NULL) ||
				    (strchr("\r\n", *p) == NULL)) {
					cm_log(1, "Error parsing result: %s.\n",
					       msg);
					return -1;
				}
				state->delay = delay;
				msg = p + strspn(p, "\r\n");
			}
			state->entry->cm_ca_cookie = sanitize(state->entry,
							      msg);
			if (state->entry->cm_ca_cookie == NULL) {
				cm_log(1, "Out of memory.\n");
				return -ENOMEM;
			}
			cm_log(1, "Saved cookie \"%s\".\n",
			       state->entry->cm_ca_cookie);
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
cm_submit_e_ready(struct cm_submit_state *state)
{
	int status, ready;
	const char *msg;

	ready = cm_subproc_ready(state->subproc);
	switch (ready) {
	case 0:
		status = cm_subproc_get_exitstatus(state->subproc);
		cm_log(1, "Certificate submission attempt complete.\n");
		if (WIFEXITED(status)) {
			cm_log(1, "Child status = %d.\n", WEXITSTATUS(status));
			msg = cm_subproc_get_msg(state->subproc, NULL);
			if ((msg != NULL) && (strlen(msg) > 0)) {
				cm_log(1, "Child output:\n%s\n", msg);
				/* If it's a single line, assume it's
				 * log-worthy. */
				if (strcspn(msg, "\n") >= (strlen(msg) - 2)) {
					cm_log(0, "%s", msg);
				}
				/* If it was an error, save it. */
				if ((WEXITSTATUS(status) ==
				     CM_SUBMIT_STATUS_ISSUED) ||
				    (WEXITSTATUS(status) ==
				     CM_SUBMIT_STATUS_WAIT) ||
				    (WEXITSTATUS(status) ==
				     CM_SUBMIT_STATUS_WAIT_WITH_DELAY)) {
					talloc_free(state->entry->cm_ca_error);
					state->entry->cm_ca_error = NULL;
				} else {
					talloc_free(state->entry->cm_ca_error);
					state->entry->cm_ca_error =
						talloc_strndup(state->entry,
							       msg,
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

/* Convert any CR/LF pairs to just LF characters, in case we're getting a
 * certificate as a snippet of a document that uses the web conventions.  */
static char *
crlf_to_lf(char *s)
{
	char *p, *q;

	p = s;
	q = s;
	while (*q != '\0') {
		if ((q[0] == '\r') && (q[1] == '\n')) {
			q++;
		}
		if (q != p) {
			*p = *q;
		}
		p++;
		q++;
	}
	*p = '\0';
	return s;
}

/* Check if the certificate was issued.  If the exit status was 0, it was
 * issued. */
static int
cm_submit_e_issued(struct cm_submit_state *state)
{
	const char *msg, *p, *q;

	msg = cm_subproc_get_msg(state->subproc, NULL);
	if (((p = strstr(msg, "-----BEGIN CERTIFICATE-----")) != NULL) &&
	    ((q = strstr(p, "-----END CERTIFICATE-----")) != NULL)) {
		talloc_free(state->entry->cm_cert);
		q += strcspn(q, "\r\n");
		if (strspn(q, "\r\n") == 0) {
			p = talloc_asprintf(state, "%s\n", p);
			q = p + strlen(p);
		} else {
			q += strspn(q, "\r\n");
		}
		state->entry->cm_cert = crlf_to_lf(talloc_strndup(state->entry,
								  p, q - p));
		cm_log(1, "Certificate issued.\n");
		return 0;
	} else {
		cm_log(1, "No issued certificate read.\n");
		return -1;
	}
}

/* Check if the submission helper can't request certificates. */
static int
cm_submit_e_unsupported(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED)) {
		return 0;
	}
	return -1;
}

/* Check if the submission helper is just unconfigured. */
static int
cm_submit_e_unconfigured(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_UNCONFIGURED)) {
		return 0;
	}
	return -1;
}

/* Check if the certificate was issued.  If the exit status was 0, it was
 * issued. */
static int
cm_submit_e_rejected(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_REJECTED)) {
		return 0;
	}
	return -1;
}

/* Check if the CA was unreachable.  If the exit status was right, then we
 * never actually talked to the CA. */
static int
cm_submit_e_unreachable(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_UNREACHABLE)) {
		return 0;
	}
	return -1;
}

/* Done talking to the CA; clean up. */
static void
cm_submit_e_done(struct cm_submit_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Attempt to exec the helper. */
struct cm_submit_e_args {
	int error_fd;
	const char *csr, *spkac, *spki, *cookie, *operation;
};

static int
cm_submit_e_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	struct cm_submit_e_args *args = userdata;
	char **argv;
	const char *error, *key_type;
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
	if ((args->spkac != NULL) && (strlen(args->spkac) > 0)) {
		setenv(CM_SUBMIT_SPKAC_ENV, args->spkac, 1);
	}
	if ((args->spki != NULL) && (strlen(args->spki) > 0)) {
		setenv(CM_SUBMIT_SPKI_ENV, args->spki, 1);
	}
	if (cm_env_local_ca_dir() != NULL) {
		setenv(CM_STORE_LOCAL_CA_DIRECTORY_ENV,
		       cm_env_local_ca_dir(), 1);
	}
	key_type = NULL;
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_rsa:
		key_type = "RSA";
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		key_type = "DSA";
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		key_type = "EC";
		break;
#endif
	case cm_key_unspecified:
		key_type = NULL;
		break;
	}
	if (key_type != NULL) {
		setenv(CM_SUBMIT_KEY_TYPE_ENV, key_type, 1);
	}
	if ((args->cookie != NULL) && (strlen(args->cookie) > 0)) {
		setenv(CM_SUBMIT_COOKIE_ENV, args->cookie, 1);
	}
	if ((entry->cm_ca_nickname != NULL) &&
	    (strlen(entry->cm_ca_nickname) > 0)) {
		setenv(CM_SUBMIT_CA_NICKNAME_ENV, entry->cm_ca_nickname, 1);
	}
	if ((entry->cm_template_profile != NULL) &&
	    (strlen(entry->cm_template_profile) > 0)) {
		setenv(CM_SUBMIT_PROFILE_ENV, entry->cm_template_profile, 1);
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
	cm_subproc_mark_most_cloexec(STDOUT_FILENO);
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
			    const char *spkac,
			    const char *spki,
			    const char *cookie,
			    const char *operation)
{
	int errorfds[2], nread;
	unsigned char u;
	struct cm_submit_state *state;
	struct cm_submit_e_args args;

	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->entry = entry;
		state->save_ca_cookie = cm_submit_e_save_ca_cookie;
		state->ready = cm_submit_e_ready;
		state->issued = cm_submit_e_issued;
		state->rejected = cm_submit_e_rejected;
		state->unreachable = cm_submit_e_unreachable;
		state->unconfigured = cm_submit_e_unconfigured;
		state->unsupported = cm_submit_e_unsupported;
		state->done = cm_submit_e_done;
		state->delay = -1;
		if (pipe(errorfds) != -1) {
			if (fcntl(errorfds[1], F_SETFD, 1L) == -1) {
				close(errorfds[0]);
				close(errorfds[1]);
				cm_log(-1, "Unexpected error while "
				       "starting helper \"%s\".",
				       ca->cm_ca_external_helper);
				cm_subproc_done(state->subproc);
				talloc_free(state);
				state = NULL;
			} else {
				args.error_fd = errorfds[1];
				args.csr = csr;
				args.spkac = spkac;
				args.spki = spki;
				args.cookie = cookie;
				args.operation = operation;
				state->subproc = cm_subproc_start(cm_submit_e_main,
								  state,
								  ca, entry,
								  &args);
				close(errorfds[1]);
				if (state->subproc == NULL) {
					talloc_free(state);
					state = NULL;
				} else {
					nread = read(errorfds[0], &u, 1);
					switch (nread) {
					case 0:
						/* no data = kernel
						 * closed-on-exec, so the
						 * helper started */
						break;
					case -1:
						/* huh? */
						cm_log(-1, "Unexpected error "
						       "while starting helper "
						       "\"%s\".\n",
						       ca->cm_ca_external_helper);
						cm_subproc_done(state->subproc);
						talloc_free(state);
						state = NULL;
						break;
					case 1:
					default:
						cm_log(-1,
						       "Error while starting "
						       "helper \"%s\": %s.\n",
						       ca->cm_ca_external_helper,
						       strerror(u));
						cm_subproc_done(state->subproc);
						talloc_free(state);
						state = NULL;
						break;
					}
				}
				close(errorfds[0]);
			}
		}
	}
	return state;
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_e_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	struct cm_submit_state *ret;
	char *spki = NULL;

	if (entry->cm_key_pubkey_info != NULL) {
		spki = cm_store_base64_from_hex(entry,
						entry->cm_key_pubkey_info);
	}
	if ((entry->cm_ca_cookie != NULL) &&
	    (strlen(entry->cm_ca_cookie) > 0)) {
		ret = cm_submit_e_start_or_resume(ca, entry, entry->cm_csr,
						  entry->cm_spkac,
						  spki,
						  entry->cm_ca_cookie,
						  "POLL");
	} else {
		ret = cm_submit_e_start_or_resume(ca, entry, entry->cm_csr,
						  entry->cm_spkac,
						  spki,
						  entry->cm_ca_cookie,
						  "SUBMIT");
	}
	if (spki != NULL) {
		talloc_free(spki);
	}
	return ret;
}

const char *
cm_submit_e_status_text(enum cm_external_status status)
{
	switch (status) {
	case CM_SUBMIT_STATUS_ISSUED:
		return "ISSUED";
	case CM_SUBMIT_STATUS_WAIT:
		return "WAIT";
	case CM_SUBMIT_STATUS_REJECTED:
		return "REJECTED";
	case CM_SUBMIT_STATUS_UNREACHABLE:
		return "UNREACHABLE";
	case CM_SUBMIT_STATUS_UNCONFIGURED:
		return "UNCONFIGURED";
	case CM_SUBMIT_STATUS_WAIT_WITH_DELAY:
		return "WAIT_WITH_DELAY";
	case CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED:
		return "OPERATION_NOT_SUPPORTED_BY_HELPER";
	}
	return "(unknown)";
}
