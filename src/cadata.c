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
#include "json.h"
#include "log.h"
#include "store-int.h"
#include "submit-e.h"
#include "subproc.h"
#include "tdbus.h"

#define CM_CADATA_ROOTS "roots"
#define CM_CADATA_OTHER_ROOTS "other-roots"
#define CM_CADATA_OTHERS "other"
#define CM_CADATA_CERTIFICATE "certificate"
#define CM_CADATA_NICKNAME "nickname"

const char *attribute_map[] = {
	CM_SUBMIT_REQ_SUBJECT_ENV, CM_DBUS_PROP_TEMPLATE_SUBJECT,
	CM_SUBMIT_REQ_HOSTNAME_ENV, CM_DBUS_PROP_TEMPLATE_HOSTNAME,
	CM_SUBMIT_REQ_PRINCIPAL_ENV, CM_DBUS_PROP_TEMPLATE_PRINCIPAL,
	CM_SUBMIT_REQ_EMAIL_ENV, CM_DBUS_PROP_TEMPLATE_EMAIL,
	CM_SUBMIT_REQ_IP_ADDRESS_ENV, CM_DBUS_PROP_TEMPLATE_IP_ADDRESS,
	CM_SUBMIT_PROFILE_ENV, CM_DBUS_PROP_TEMPLATE_PROFILE,
	NULL,
};

struct cm_cadata_state {
	enum cm_submit_external_phase {
		parsing,
		postprocessing,
	} phase;
	struct cm_store_ca *ca;
	struct cm_subproc_state *subproc;
	int (*parse)(struct cm_store_ca *ca, struct cm_cadata_state *state,
		     const char *msg);
	int (*second_sub)(int fd, struct cm_store_ca *ca,
			  struct cm_store_entry *e, void *data);
	int (*postprocess)(struct cm_store_ca *ca,
			   struct cm_cadata_state *state, const char *msg);
	const char *op;
	char *intermediate;
	int error_fd, delay;
	unsigned int modified: 1;
};

/* Callback that just runs the helper to gather the specified data. */
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
	cm_subproc_mark_most_cloexec(STDOUT_FILENO, -1, -1);
	cm_log(1, "Running enrollment/cadata helper \"%s\".\n", argv[0]);
	execvp(argv[0], argv);
	u = errno;
	if (write(state->error_fd, &u, 1) != 1) {
		cm_log(1, "Error sending error result to parent.\n");
	}
	return u;
}

/* Parse IDENTIFY output.  It's just an arbitrary string. */
static int
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
		if ((old_aka != NULL) && (ca->cm_ca_aka != NULL)) {
			state->modified = (strcmp(old_aka, ca->cm_ca_aka) != 0);
		} else {
			state->modified = 1;
		}
	}

	talloc_free(old_aka);
	return 0;
}

/* Compare two lists of nickname+certificate pairs. */
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

/* Parse a list of nickname+certificate pairs. */
static const char *
parse_old_cert_list(struct cm_store_ca *ca, struct cm_cadata_state *state,
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
			*list = certs;
			return q + strspn(q, "\r\n");
		} else {
			p = q + strspn(q, "\r\n");
			q = p + strcspn(p, "\r\n");
		}
	}
	*list = certs;
	return p;
}

/* Build a nickcert list out of the keys and values in a JSON object. */
struct cm_nickcert **
parse_json_cert_list(void *parent, struct cm_json *nickcerts)
{
	struct cm_nickcert **ret, *c;
	struct cm_json *cert, *val;
	int i, j;
	const char *nickname, *pem;

	i = cm_json_array_size(nickcerts);
	if (i > 0) {
		ret = talloc_array_ptrtype(parent, ret, i + 1);
		if (ret != NULL) {
			for (i = 0, j = 0;
			     i < cm_json_array_size(nickcerts);
			     i++) {
				c = talloc_ptrtype(ret, c);
				if (c != NULL) {
					cert = cm_json_n(nickcerts, i);
					if (cm_json_type(cert) != cm_json_type_object) {
						continue;
					}
					val = cm_json_get(cert, CM_CADATA_NICKNAME);
					if (cm_json_type(val) != cm_json_type_string) {
						continue;
					}
					nickname = cm_json_string(val, NULL);
					c->cm_nickname = talloc_strdup(c, nickname);
					val = cm_json_get(cert, CM_CADATA_CERTIFICATE);
					if (cm_json_type(val) != cm_json_type_string) {
						continue;
					}
					pem = cm_json_string(val, NULL);
					c->cm_cert = talloc_strdup(c, pem);
					if ((c->cm_nickname != NULL) &&
					    (c->cm_cert != NULL)) {
						ret[j++] = c;
					}
				}
			}
			ret[j] = NULL;
			if (j > 0) {
				return ret;
			} else {
				return NULL;
			}
		}
	}
	return NULL;
}

/* Parse three lists of nickname+certificate pairs, or a JSON document that
 * makes them all members of objects named "root", "other-roots", and "others",
 * members of an unnamed top-level object. */
static int
parse_certs(struct cm_store_ca *ca, struct cm_cadata_state *state,
	    const char *msg)
{
	struct cm_nickcert **certs;
	struct cm_json *json = NULL, *sub, *cert, *val;
	const char *p, *eom;
	int i;

	state->modified = 0;
	if (cm_json_decode(state, msg, -1, &json, &eom) != 0) {
		json = cm_json_new_object(state);
		/* Take the older-format data and build a JSON object out of
		 * it. */
		certs = NULL;
		p = parse_old_cert_list(ca, state, msg, &certs);
		if (p != NULL) {
			sub = cm_json_new_array(json);
			for (i = 0;
			     (certs != NULL) &&
			     (certs[i] != NULL);
			     i++) {
				cert = cm_json_new_object(sub);
				val = cm_json_new_string(cert,
							 certs[i]->cm_nickname,
							 -1);
				cm_json_set(cert, CM_CADATA_NICKNAME, val);
				val = cm_json_new_string(cert,
							 certs[i]->cm_cert,
							 -1);
				cm_json_set(cert, CM_CADATA_CERTIFICATE, val);
				cm_json_append(sub, cert);
			}
			if (cm_json_array_size(sub) > 0) {
				cm_json_set(json, CM_CADATA_ROOTS, sub);
			}
			certs = NULL;
			p = parse_old_cert_list(ca, state, p, &certs);
			if (p != NULL) {
				sub = cm_json_new_array(json);
				for (i = 0;
				     (certs != NULL) &&
				     (certs[i] != NULL);
				     i++) {
					cert = cm_json_new_object(sub);
					val = cm_json_new_string(cert,
								 certs[i]->cm_nickname,
								 -1);
					cm_json_set(cert, CM_CADATA_NICKNAME, val);
					val = cm_json_new_string(cert,
								 certs[i]->cm_cert,
								 -1);
					cm_json_set(cert, CM_CADATA_CERTIFICATE, val);
					cm_json_append(sub, cert);
				}
				if (cm_json_array_size(sub) > 0) {
					cm_json_set(json, CM_CADATA_OTHER_ROOTS, sub);
				}
				certs = NULL;
				p = parse_old_cert_list(ca, state, p, &certs);
				if (p != NULL) {
					sub = cm_json_new_array(json);
					for (i = 0;
					     (certs != NULL) &&
					     (certs[i] != NULL);
					     i++) {
						cert = cm_json_new_object(sub);
						val = cm_json_new_string(cert,
									 certs[i]->cm_nickname,
									 -1);
						cm_json_set(cert, CM_CADATA_NICKNAME, val);
						val = cm_json_new_string(cert,
									 certs[i]->cm_cert,
									 -1);
						cm_json_set(cert, CM_CADATA_CERTIFICATE, val);
						cm_json_append(sub, cert);
					}
					if (cm_json_array_size(sub) > 0) {
						cm_json_set(json, CM_CADATA_OTHERS, sub);
					}
				}
			}
		}
	}
	/* Save the JSON document for postprocessing. */
	state->intermediate = cm_json_encode(state, json);
	return 0;
}

static int
postprocess_certs_sub(int fd, struct cm_store_ca *ca, struct cm_store_entry *e,
		      void *data)
{
	struct cm_cadata_state *state = data;
	FILE *status;

	status = fdopen(fd, "w");
	if (status == NULL) {
		cm_log(1, "Internal error.\n");
		_exit(errno);
	}
	fprintf(status, "%s\n", state->intermediate);
	fflush(status);
	fclose(status);
	_exit(0);
}

static int
postprocess_certs(struct cm_store_ca *ca, struct cm_cadata_state *state,
		  const char *msg)
{
	struct cm_nickcert **roots, **other_roots, **others;
	struct cm_json *json;
	const char *eom;

	if (cm_json_decode(state, msg, -1, &json, &eom) != 0) {
		cm_log(1, "Error parsing JSON root certificate object.\n");
		return 0;
	}
	roots = parse_json_cert_list(ca, cm_json_get(json, CM_CADATA_ROOTS));
	other_roots = parse_json_cert_list(ca, cm_json_get(json, CM_CADATA_OTHER_ROOTS));
	others = parse_json_cert_list(ca, cm_json_get(json, CM_CADATA_OTHERS));
	if ((nickcertlistcmp(roots, ca->cm_ca_root_certs) != 0) ||
	    (nickcertlistcmp(other_roots, ca->cm_ca_other_root_certs) != 0) ||
	    (nickcertlistcmp(others, ca->cm_ca_other_certs) != 0)) {
		state->modified = 1;
	}
	talloc_free(ca->cm_ca_root_certs);
	talloc_free(ca->cm_ca_other_root_certs);
	talloc_free(ca->cm_ca_other_certs);
	ca->cm_ca_root_certs = roots;
	ca->cm_ca_other_root_certs = other_roots;
	ca->cm_ca_other_certs = others;
	return 0;
}

/* Parse a list of comma or newline-separated items.  This handles both SCEP
 * capability lists and our lists of required attributes. */
static int
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
			/* Save every item. */
			reqs[i] = talloc_strndup(reqs, p, q - p);
			if ((reqs[i] != NULL) && (strlen(reqs[i]) > 0)) {
				i++;
			}
			reqs[i] = NULL;
		} else {
			/* Save only dictionary items that can be mapped from
			 * items in the list. */
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
	return 0;
}

/* Parse a list of known profiles. */
static int
parse_profiles(struct cm_store_ca *ca, struct cm_cadata_state *state,
	       const char *msg)
{
	parse_list(ca, state, msg, NULL, &ca->cm_ca_profiles);
	return 0;
}

/* Parse a single profile name that we'll advertise as a default. */
static int
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
	return 0;
}

/* Parse a list of properties that the helper expects us to have set for new
 * enrollment requests. */
static int
parse_enroll_reqs(struct cm_store_ca *ca, struct cm_cadata_state *state,
		  const char *msg)
{
	parse_list(ca, state, msg, attribute_map,
		   &ca->cm_ca_required_enroll_attributes);
	return 0;
}

/* Parse a list of properties that the helper expects us to have set for
 * renewal requests. */
static int
parse_renew_reqs(struct cm_store_ca *ca, struct cm_cadata_state *state,
		 const char *msg)
{
	parse_list(ca, state, msg, attribute_map,
		   &ca->cm_ca_required_renewal_attributes);
	return 0;
}

/* Parse a list of SCEP capabilities. */
static int
parse_capabilities(struct cm_store_ca *ca, struct cm_cadata_state *state,
		   const char *msg)
{
	parse_list(ca, state, msg, NULL, &ca->cm_ca_capabilities);
	return 0;
}

/* Compare two strings, treating NULL and empty as the same. */
static dbus_bool_t
strings_differ(const char *a, const char *b)
{
	if (a == NULL) {
		a = "";
	}
	if (b == NULL) {
		b = "";
	}
	return (strcmp(a, b) != 0);
}

/* Parse SCEP encryption certificate data, which is a series of concatenated
 * X.509 certificates.  The first is for the SCEP server.  The second, if there
 * is one, is for the CA.  Any additional certificates are assumed to be
 * intermediates. */
static int
parse_encryption_certs(struct cm_store_ca *ca, struct cm_cadata_state *state,
		       const char *msg)
{
	const char *olde, *oldei, *oldep;
	char *p;

	olde = ca->cm_ca_encryption_cert;
	oldei = ca->cm_ca_encryption_issuer_cert;
	oldep = ca->cm_ca_encryption_cert_pool;
	ca->cm_ca_encryption_cert = talloc_strdup(ca, msg);
	ca->cm_ca_encryption_issuer_cert = NULL;
	ca->cm_ca_encryption_cert_pool = NULL;
	p = strstr(ca->cm_ca_encryption_cert, "-----END CERTIFICATE-----");
	if (p != NULL) {
		p += strcspn(p, "\r\n");
		p += strspn(p, "\r\n");
		if (strstr(p, "-----END CERTIFICATE-----") != NULL) {
			ca->cm_ca_encryption_issuer_cert = talloc_strdup(ca, p);
			*p = '\0';
		}
	}
	if (ca->cm_ca_encryption_issuer_cert != NULL) {
		p = strstr(ca->cm_ca_encryption_issuer_cert,
			   "-----END CERTIFICATE-----");
		if (p != NULL) {
			p += strcspn(p, "\r\n");
			p += strspn(p, "\r\n");
			if (strstr(p, "-----END CERTIFICATE-----") != NULL) {
				ca->cm_ca_encryption_cert_pool = talloc_strdup(ca, p);
			}
			*p = '\0';
		}
	}
	if (ca->cm_ca_encryption_cert != NULL) {
		if (strspn(ca->cm_ca_encryption_cert, "\r\n \t") ==
		    strlen(ca->cm_ca_encryption_cert)) {
			ca->cm_ca_encryption_cert = NULL;
		}
	}
	if (ca->cm_ca_encryption_issuer_cert != NULL) {
		if (strspn(ca->cm_ca_encryption_issuer_cert, "\r\n \t") ==
		    strlen(ca->cm_ca_encryption_issuer_cert)) {
			ca->cm_ca_encryption_issuer_cert = NULL;
		}
	}
	if (ca->cm_ca_encryption_cert_pool != NULL) {
		if (strspn(ca->cm_ca_encryption_cert_pool, "\r\n \t") ==
		    strlen(ca->cm_ca_encryption_cert_pool)) {
			ca->cm_ca_encryption_cert_pool = NULL;
		}
	}
	state->modified = strings_differ(olde, ca->cm_ca_encryption_cert) ||
			  strings_differ(oldei, ca->cm_ca_encryption_issuer_cert) ||
			  strings_differ(oldep, ca->cm_ca_encryption_cert_pool);
	return 0;
}

/* Start the helper with the right $CERTMONGER_OPERATION, and feed the output
 * to the right parser callback. */
static struct cm_cadata_state *
cm_cadata_start_generic(struct cm_store_ca *ca, const char *op,
			int (*parse)(struct cm_store_ca *,
				     struct cm_cadata_state *, const char *),
			int (*second_sub)(int fd, struct cm_store_ca *,
					  struct cm_store_entry *, void *),
			int (*postprocess)(struct cm_store_ca *,
					   struct cm_cadata_state *, const char *))
{
	struct cm_cadata_state *ret;
	int error_fd[2];
	unsigned char u;

	switch (ca->cm_ca_type) {
	case cm_ca_internal_self:
		if (strcasecmp(op, CM_OP_IDENTIFY) == 0) {
			ca->cm_ca_aka = talloc_asprintf(ca,
							CM_SELF_SIGN_CA_NAME " (%s %s)",
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
	ret->phase = parsing;
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
	ret->second_sub = second_sub;
	ret->postprocess = postprocess;
	if (read(error_fd[0], &u, 1) == 1) {
		cm_log(1, "Error running enrollment helper \"%s\": %s.\n",
		       ca->cm_ca_external_helper, strerror(u));
		talloc_free(ret);
		return NULL;
	}
	return ret;
}

struct cm_cadata_state *
cm_cadata_start_identify(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_IDENTIFY,
				       parse_identification, NULL, NULL);
}

struct cm_cadata_state *
cm_cadata_start_certs(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_ROOTS,
				       parse_certs,
				       postprocess_certs_sub,
				       postprocess_certs);
}

struct cm_cadata_state *
cm_cadata_start_profiles(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_PROFILES,
				       parse_profiles, NULL, NULL);
}

struct cm_cadata_state *
cm_cadata_start_default_profile(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_DEFAULT_PROFILE,
				       parse_default_profile, NULL, NULL);
}

struct cm_cadata_state *
cm_cadata_start_enroll_reqs(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_ENROLL_REQUIREMENTS,
				       parse_enroll_reqs, NULL, NULL);
}

struct cm_cadata_state *
cm_cadata_start_renew_reqs(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_RENEWAL_REQUIREMENTS,
				       parse_renew_reqs, NULL, NULL);
}

struct cm_cadata_state *
cm_cadata_start_capabilities(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_SCEP_CA_CAPS,
				       parse_capabilities, NULL, NULL);
}

struct cm_cadata_state *
cm_cadata_start_encryption_certs(struct cm_store_ca *ca)
{
	return cm_cadata_start_generic(ca, CM_OP_FETCH_SCEP_CA_CERTS,
				       parse_encryption_certs, NULL, NULL);
}

int
cm_cadata_ready(struct cm_cadata_state *state)
{
	struct cm_subproc_state *subproc;
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
				switch (state->phase) {
				case parsing:
					ready = (*(state->parse))(state->ca, state, msg);
					if ((ready == 0) &&
					    (state->second_sub != NULL) &&
					    (state->postprocess != NULL)) {
						subproc = cm_subproc_start(state->second_sub,
									   state, state->ca, NULL, state);
						if (subproc != NULL) {
							cm_subproc_done(state->subproc);
							state->subproc = subproc;
							state->phase = postprocessing;
							ready = -1;
						} else {
							cm_log(1, "Error running second helper.\n");
						}
					}
					break;
				case postprocessing:
					ready = (*(state->postprocess))(state->ca, state, msg);
					break;
				}
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
cm_cadata_rejected(struct cm_cadata_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_REJECTED)) {
		return 0;
	}
	return -1;
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
