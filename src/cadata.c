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

#include "cadata.h"
#include "env.h"
#include "log.h"
#include "store-int.h"
#include "submit-e.h"
#include "subproc.h"
#include "tdbus.h"

const char *attribute_map[] = {
	CM_SUBMIT_REQ_SUBJECT_ENV, CM_DBUS_PROP_TEMPLATE_SUBJECT,
	CM_SUBMIT_REQ_HOSTNAME_ENV, CM_DBUS_PROP_TEMPLATE_HOSTNAME,
	CM_SUBMIT_REQ_PRINCIPAL_ENV, CM_DBUS_PROP_TEMPLATE_PRINCIPAL,
	CM_SUBMIT_REQ_EMAIL_ENV, CM_DBUS_PROP_TEMPLATE_EMAIL,
	CM_SUBMIT_PROFILE_ENV, CM_DBUS_PROP_TEMPLATE_PROFILE,
	NULL,
};

struct cm_cadata_state {
	struct cm_store_ca *ca;
	struct cm_subproc_state *subproc;
	void (*parse)(struct cm_store_ca *ca, struct cm_cadata_state *state,
		      const char *msg);
	const char *op;
	int error_fd, delay;
	unsigned int modified: 1;
};

static int
fetch(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry, void *data)
{
	struct cm_cadata_state *state = data;
	char **argv;
	const char *error;
	unsigned char u;

	setenv(CM_SUBMIT_OPERATION_ENV, state->op, 1);
	if ((ca->cm_nickname != NULL) &&
	    (strlen(ca->cm_nickname) > 0)) {
		setenv(CM_SUBMIT_CA_NICKNAME_ENV, ca->cm_nickname, 1);
	}
	if (dup2(fd, STDOUT_FILENO) == -1) {
		u = errno;
		cm_log(1, "Error redirecting standard out for "
		       "enrollment helper: %s.\n",
		       strerror(errno));
		if (write(state->error_fd, &u, 1) != 1) {
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
	cm_log(1, "Running enrollment/cadata helper \"%s\".\n", argv[0]);
	execvp(argv[0], argv);
	u = errno;
	if (write(state->error_fd, &u, 1) != 1) {
		cm_log(1, "Error sending error result to parent.\n");
	}
	return u;
}

static void
parse_identification(struct cm_store_ca *ca, struct cm_cadata_state *state,
		     const char *msg)
{
	const char *p, *q;
	char *old_aka;

	old_aka = ca->cm_ca_aka;
	p = msg;
	q = p + strcspn(p, "\r\n");
	if (p != q) {
		ca->cm_ca_aka = talloc_strndup(ca, p, q - p);
	} else {
		ca->cm_ca_aka = NULL;
	}

	if (state != NULL) {
		if ((old_aka == NULL) && (ca->cm_ca_aka == NULL)) {
			state->modified = 0;
		} else
		if ((old_aka == NULL) && (ca->cm_ca_aka != NULL)) {
			state->modified = 1;
		} else
		if ((old_aka != NULL) && (ca->cm_ca_aka == NULL)) {
			state->modified = 1;
		} else {
			state->modified = (strcmp(old_aka, ca->cm_ca_aka) != 0);
		}
	}

	talloc_free(old_aka);
}

static int
nickcertlistcmp(struct cm_nickcert **a, struct cm_nickcert **b)
{
	int i, j;

	if ((a == NULL) && (b == NULL)) {
		return 0;
	} else
	if ((a == NULL) && (b != NULL)) {
		return 1;
	} else
	if ((a != NULL) && (b == NULL)) {
		return 1;
	} else {
		for (i = 0; a[i] != NULL; i++) {
			for (j = 0; b[j] != NULL; j++) {
				if ((strcmp(a[i]->cm_nickname,
					    b[j]->cm_nickname) == 0) &&
				    (strcmp(a[i]->cm_cert,
					    b[j]->cm_cert) == 0)) {
					break;
				}
			}
			if (b[j] == NULL) {
				return 1;
			}
		}
		for (i = 0; b[i] != NULL; i++) {
			for (j = 0; a[j] != NULL; j++) {
				if ((strcmp(b[i]->cm_nickname,
					    a[j]->cm_nickname) == 0) &&
				    (strcmp(b[i]->cm_cert,
					    a[j]->cm_cert) == 0)) {
					break;
				}
			}
			if (a[j] == NULL) {
				return 1;
			}
		}
		return 0;
	}
}

static const char *
parse_cert_list(struct cm_store_ca *ca, struct cm_cadata_state *state,
		const char *msg, struct cm_nickcert ***list)
{
	struct cm_nickcert **certs = NULL, **tmp, *nc;
	const char *p, *q;
	char *s;
	int i = 0;

	p = msg;
	q = p + strcspn(p, "\r\n");
	while (p != q) {
		nc = talloc_ptrtype(NULL, nc);
		if (nc == NULL) {
			talloc_free(certs);
			return NULL;
		}
		memset(nc, 0, sizeof(*nc));
		tmp = talloc_realloc(ca, certs, struct cm_nickcert *, i + 2);
		if (tmp == NULL) {
			talloc_free(certs);
			return NULL;
		}
		certs = tmp;
		certs[i++] = nc;
		certs[i] = NULL;
		talloc_steal(certs, nc);
		nc->cm_nickname = talloc_strndup(nc, p, q - p);
		p = q + strspn(q, "\r\n");
		if (strncmp(p, "-----BEGIN", 10) != 0) {
			talloc_free(certs);
			return NULL;
		}
		q = strstr(p, "-----END");
		if (q == NULL) {
			talloc_free(certs);
			return NULL;
		}
		q += strcspn(q, "\r\n");
		nc->cm_cert = talloc_asprintf(nc, "%.*s\n", (int) (q - p), p);
		if ((nc->cm_nickname == NULL) || (nc->cm_cert == NULL)) {
			talloc_free(certs);
			return NULL;
		}
		while ((s = strstr(nc->cm_cert, "\r\n")) != NULL) {
			memmove(s, s + 1, strlen(s));
		}
		if ((strncmp(q, "\n\n", 2) == 0) ||
		    (strncmp(q, "\r\n\r\n", 4) == 0)) {
			if ((state != NULL) &&
			    (nickcertlistcmp(*list, certs) != 0)) {
				state->modified = 1;
			}
			*list = certs;
			return q + strspn(q, "\r\n");
		} else {
			p = q + strspn(q, "\r\n");
			q = p + strcspn(p, "\r\n");
		}
	}
	if ((state != NULL) && (nickcertlistcmp(*list, certs) != 0)) {
		state->modified = 1;
	}
	*list = certs;
	return p;
}

static void
parse_certs(struct cm_store_ca *ca, struct cm_cadata_state *state,
	    const char *msg)
{
	struct cm_nickcert **roots, **other_roots, **others;
	const char *p;

	if (state != NULL) {
		state->modified = 0;
	}
	roots = ca->cm_ca_root_certs;
	p = parse_cert_list(ca, state, msg, &roots);
	if (p != NULL) {
		other_roots = ca->cm_ca_other_root_certs;
		p = parse_cert_list(ca, state, p, &other_roots);
		if (p != NULL) {
			others = ca->cm_ca_other_certs;
			p = parse_cert_list(ca, state, p, &others);
			if (p != NULL) {
				talloc_free(ca->cm_ca_root_certs);
				talloc_free(ca->cm_ca_other_root_certs);
				talloc_free(ca->cm_ca_other_certs);
				ca->cm_ca_root_certs = roots;
				ca->cm_ca_other_root_certs = other_roots;
				ca->cm_ca_other_certs = others;
				return;
			}
			talloc_free(other_roots);
		}
		talloc_free(roots);
	}
}

static void
parse_list(struct cm_store_ca *ca, struct cm_cadata_state *state,
	   const char *msg, const char **dict, char ***list)
{
	const char *p, *q;
	char **reqs = NULL, **tmp;
	int i = 0, j = 0, len;

	p = msg;
	q = p + strcspn(p, ",\r\n");
	while (p != q) {
		tmp = talloc_realloc(ca, reqs, char *, i + 2);
		if (tmp == NULL) {
			break;
		}
		reqs = tmp;
		if (dict == NULL) {
			reqs[i] = talloc_strndup(reqs, p, q - p);
			if ((reqs[i] != NULL) && (strlen(reqs[i]) > 0)) {
				i++;
			}
			reqs[i] = NULL;
		} else {
			for (j = 0; dict[j] != NULL; j += 2) {
				len = strlen(dict[j]);
				if ((q - p == len) &&
				    (strncasecmp(dict[j], p, len) == 0)) {
					reqs[i] = talloc_strdup(reqs,
								dict[j + 1]);
					if ((reqs[i] != NULL) &&
					    (strlen(reqs[i]) > 0)) {
						i++;
					}
					break;
				}
			}
			reqs[i] = NULL;
		}
		p = q + strspn(q, ",\r\n");
		q = p + strcspn(p, ",\r\n");
	}
	if (i == 0) {
		talloc_free(reqs);
		reqs = NULL;
	}

	if (state != NULL) {
		if ((*list == NULL) && (reqs == NULL)) {
			state->modified = 0;
		} else
		if ((*list == NULL) && (reqs != NULL)) {
			state->modified = 1;
		} else
		if ((*list != NULL) && (reqs == NULL)) {
			state->modified = 1;
		} else {
			state->modified = 0;
			for (i = 0; (*list)[i] != NULL; i++) {
				for (j = 0; reqs[j] != NULL; j++) {
					if (strcmp((*list)[i], reqs[j]) == 0) {
						break;
					}
				}
				if (reqs[j] == NULL) {
					state->modified = 1;
					break;
				}
			}
			for (i = 0; reqs[i] != NULL; i++) {
				for (j = 0; (*list)[j] != NULL; j++) {
					if (strcmp(reqs[i], (*list)[j]) == 0) {
						break;
					}
				}
				if ((*list)[j] == NULL) {
					state->modified = 1;
					break;
				}
			}
		}
	}

	talloc_free(*list);
	*list = reqs;
}

static void
parse_profiles(struct cm_store_ca *ca, struct cm_cadata_state *state,
	       const char *msg)
{
	parse_list(ca, state, msg, NULL, &ca->cm_ca_profiles);
}

static void
parse_default_profile(struct cm_store_ca *ca, struct cm_cadata_state *state,
		      const char *msg)
{
	const char *p, *q;
	char *old_dp;

	old_dp = ca->cm_ca_default_profile;
	p = msg;
	q = p + strcspn(p, "\r\n");
	if (p != q) {
		ca->cm_ca_default_profile = talloc_strndup(ca, p, q - p);
	} else {
		ca->cm_ca_default_profile = NULL;
	}

	if (state != NULL) {
		if ((old_dp == NULL) && (ca->cm_ca_default_profile == NULL)) {
			state->modified = 0;
		} else
		if ((old_dp == NULL) && (ca->cm_ca_default_profile != NULL)) {
			state->modified = 1;
		} else
		if ((old_dp != NULL) && (ca->cm_ca_default_profile == NULL)) {
			state->modified = 1;
		} else {
			state->modified =
				(strcmp(old_dp,
					ca->cm_ca_default_profile) != 0);
		}
	}

	talloc_free(old_dp);
}

static void
parse_enroll_reqs(struct cm_store_ca *ca, struct cm_cadata_state *state,
		  const char *msg)
{
	parse_list(ca, state, msg, attribute_map,
		   &ca->cm_ca_required_enroll_attributes);
}

static void
parse_renew_reqs(struct cm_store_ca *ca, struct cm_cadata_state *state,
		 const char *msg)
{
	parse_list(ca, state, msg, attribute_map,
		   &ca->cm_ca_required_renewal_attributes);
}

static struct cm_cadata_state *
cm_cadata_start_generic(struct cm_store_ca *ca, const char *op,
			void (*parse)(struct cm_store_ca *,
				      struct cm_cadata_state *, const char *))
{
	struct cm_cadata_state *ret;
	int error_fd[2];
	unsigned char u;

	switch (ca->cm_ca_type) {
	case cm_ca_internal_self:
		if (strcasecmp(op, CM_OP_IDENTIFY) == 0) {
			ca->cm_ca_aka = talloc_asprintf(ca,
							"SelfSign (%s %s)",
							PACKAGE_NAME,
							PACKAGE_VERSION);
		} else
		if (strcasecmp(op, CM_OP_FETCH_ROOTS) == 0) {
		} else
		if (strcasecmp(op, CM_OP_FETCH_PROFILES) == 0) {
		} else
		if (strcasecmp(op, CM_OP_FETCH_DEFAULT_PROFILE) == 0) {
		} else
		if (strcasecmp(op, CM_OP_FETCH_ENROLL_REQUIREMENTS) == 0) {
			parse_list(ca, NULL,
				   CM_SUBMIT_REQ_SUBJECT_ENV,
				   attribute_map,
				   &ca->cm_ca_required_enroll_attributes);
		} else
		if (strcasecmp(op, CM_OP_FETCH_RENEWAL_REQUIREMENTS) == 0) {
			parse_list(ca, NULL,
				   CM_SUBMIT_REQ_SUBJECT_ENV,
				   attribute_map,
				   &ca->cm_ca_required_renewal_attributes);
		}
		return NULL;
		break;
	case cm_ca_external:
		break;
	}

	if (pipe(error_fd) != 0) {
		cm_log(1, "Error creating pipe for reporting "
		       "errors: %s.\n", strerror(errno));
		return NULL;
	}

	ret = talloc_ptrtype(ca, ret);
	if (ret == NULL) {
		return NULL;
	}
	memset(ret, 0, sizeof(*ret));
	ret->ca = ca;
	ret->error_fd = error_fd[1];
	ret->delay = -1;
	ret->op = op;
	ret->modified = 0;
	ret->subproc = cm_subproc_start(fetch, ret, ca, NULL, ret);
	if (ret->subproc == NULL) {
		close(error_fd[0]);
		close(error_fd[1]);
		talloc_free(ret);
		return NULL;
	}
	close(error_fd[1]);
	ret->error_fd = -1;
	ret->parse = parse;
	if (read(error_fd[0], &u, 1) == 1) {
		cm_log(1, "Error running enrollment helper: %s.\n",
		       strerror(u));
		talloc_free(ret);
		return NULL;
	}
	return ret;
}

struct cm_cadata_state *
cm_cadata_start_identify(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_IDENTIFY,
				       parse_identification);
}

struct cm_cadata_state *
cm_cadata_start_certs(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_ROOTS,
				       parse_certs);
}

struct cm_cadata_state *
cm_cadata_start_profiles(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_PROFILES,
				       parse_profiles);
}

struct cm_cadata_state *
cm_cadata_start_default_profile(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_DEFAULT_PROFILE,
				       parse_default_profile);
}

struct cm_cadata_state *
cm_cadata_start_enroll_reqs(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_ENROLL_REQUIREMENTS,
				       parse_enroll_reqs);
}

struct cm_cadata_state *
cm_cadata_start_renew_reqs(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_RENEWAL_REQUIREMENTS,
				       parse_renew_reqs);
}

int
cm_cadata_ready(struct cm_cadata_state *state)
{
	int ready, status, length;
	const char *msg = NULL;
	char *p = NULL;
	long delay = -1;

	ready = cm_subproc_ready(state->subproc);
	if (ready == 0) {
		status = cm_subproc_get_exitstatus(state->subproc);
		msg = cm_subproc_get_msg(state->subproc, &length);
		if (WIFEXITED(status)) {
			switch (WEXITSTATUS(status)) {
			case CM_SUBMIT_STATUS_ISSUED:
				(*(state->parse))(state->ca, state, msg);
				break;
			case CM_SUBMIT_STATUS_WAIT_WITH_DELAY:
				if (length > 0) {
					delay = strtol(msg, &p, 10);
					if ((p != NULL) &&
					    ((*p == '\0') ||
					     (strchr("\r\n", *p) != NULL))) {
						state->delay = delay;
					}
				}
				break;
			default:
				break;
			}
		}
	}
	return ready;
}

int
cm_cadata_get_fd(struct cm_cadata_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

int
cm_cadata_modified(struct cm_cadata_state *state)
{
	return state->modified ? 0 : -1;
}

int
cm_cadata_unsupported(struct cm_cadata_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED)) {
		return 0;
	}
	return -1;
}

int
cm_cadata_needs_retry(struct cm_cadata_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    ((WEXITSTATUS(status) == CM_SUBMIT_STATUS_WAIT) ||
	     (WEXITSTATUS(status) == CM_SUBMIT_STATUS_WAIT_WITH_DELAY))) {
		return 0;
	}
	return -1;
}

int
cm_cadata_specified_delay(struct cm_cadata_state *state)
{
	return state->delay;
}

int
cm_cadata_unreachable(struct cm_cadata_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_UNREACHABLE)) {
		return 0;
	}
	return -1;
}

int
cm_cadata_unconfigured(struct cm_cadata_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_UNCONFIGURED)) {
		return 0;
	}
	return -1;
}

void
cm_cadata_done(struct cm_cadata_state *state)
{
	cm_subproc_done(state->subproc);
	talloc_free(state);
}
