/*
 * Copyright (C) 2009,2010,2011,2012,2014,2015 Red Hat, Inc.
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
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <krb5.h>

#include <talloc.h>

#include "log.h"
#include "pin.h"
#include "prefs.h"
#include "prefs-o.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"
#include "submit-int.h"
#include "submit-o.h"
#include "submit-u.h"
#include "subproc.h"
#include "tm.h"
#include "util-o.h"

static int
cm_submit_so_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		  void *userdata)
{
	FILE *keyfp, *pem;
	EVP_PKEY *pkey;
	X509 *cert;
	char *pin;
	int status;
	long error;
	char buf[LINE_MAX];
	time_t lifedelta;
	long life;
	time_t now;
	char *filename;

	util_o_init();
	ERR_load_crypto_strings();
	status = 1;
	cert = NULL;
	if (ca->cm_ca_internal_force_issue_time) {
		now = ca->cm_ca_internal_issue_time;
	} else {
		now = cm_time(NULL);
	}
	if ((entry->cm_key_next_marker != NULL) &&
	    (strlen(entry->cm_key_next_marker) > 0)) {
		filename = util_build_next_filename(entry->cm_key_storage_location, entry->cm_key_next_marker);
		if (filename == NULL) {
			cm_log(1, "Error reading private key from "
			       "\"%s\": %s.\n",
			       filename, strerror(errno));
			keyfp = NULL;
		} else {
			keyfp = fopen(filename, "r");
		}
	} else {
		filename = entry->cm_key_storage_location;
		keyfp = fopen(filename, "r");
	}
	if (cm_submit_u_delta_from_string(cm_prefs_selfsign_validity_period(),
					  now, &lifedelta) == 0) {
		life = lifedelta;
	} else {
		if (cm_submit_u_delta_from_string(CM_DEFAULT_CERT_LIFETIME, now,
						  &lifedelta) == 0) {
			life = lifedelta;
		} else {
			life = 365 * 24 * 60 * 60;
		}
	}
	if (keyfp != NULL) {
		pkey = EVP_PKEY_new();
		if (pkey != NULL) {
			if (cm_pin_read_for_key(entry, &pin) == 0) {
				pkey = PEM_read_PrivateKey(keyfp, NULL, NULL, pin);
				if (pkey != NULL) {
					status = cm_submit_o_sign(ca, entry->cm_csr,
								  NULL, pkey,
								  ca->cm_ca_internal_serial,
								  now, life, &cert);
				} else {
					cm_log(1, "Error reading private key from "
					       "'%s': %s.\n",
					       filename, strerror(errno));
				}
			} else {
				cm_log(1, "Error reading PIN.\n");
			}
			EVP_PKEY_free(pkey);
		} else {
			cm_log(1, "Internal error.\n");
		}
		fclose(keyfp);
	} else {
		cm_log(1, "Error opening key file '%s' for reading: %s.\n",
		       filename, strerror(errno));
	}
	if (status == 0) {
		pem = fdopen(fd, "w");
		if (pem != NULL) {
			if (PEM_write_X509(pem, cert) == 0) {
				cm_log(1, "Error serializing certificate.\n");
				status = -1;
			}
			fclose(pem);
		}
	}
	while ((error = ERR_get_error()) != 0) {
		ERR_error_string_n(error, buf, sizeof(buf));
		cm_log(1, "%s\n", buf);
	}
	if (status != 0) {
		_exit(status);
	}
	return 0;
}

/* Save CA-specific identifier for our submitted request. */
static int
cm_submit_so_save_ca_cookie(struct cm_submit_state *state)
{
	talloc_free(state->entry->cm_ca_cookie);
	state->entry->cm_ca_cookie =
		talloc_strdup(state->entry,
			      state->entry->cm_key_storage_location);
	if (state->entry->cm_ca_cookie == NULL) {
		cm_log(1, "Out of memory.\n");
		return ENOMEM;
	}
	return 0;
}

/* Check if an attempt to submit has finished. */
static int
cm_submit_so_ready(struct cm_submit_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Check if the certificate was issued. */
static int
cm_submit_so_issued(struct cm_submit_state *state)
{
	const char *msg;

	msg = cm_subproc_get_msg(state->subproc, NULL);
	if ((strstr(msg, "-----BEGIN CERTIFICATE-----") != NULL) &&
	    (strstr(msg, "-----END CERTIFICATE-----") != NULL)) {
		talloc_free(state->entry->cm_cert);
		state->entry->cm_cert = talloc_strdup(state->entry, msg);
		return 0;
	}
	return -1;
}

/* Check if the signing request was rejected. */
static int
cm_submit_so_rejected(struct cm_submit_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 2)) {
		return -1; /* it should never get rejected */
	}
	return 0;
}

/* Check if we need SCEP messages. */
static int
cm_submit_so_need_scep_messages(struct cm_submit_state *state)
{
	return -1; /* nope */
}

/* Check if we need to use a different key. */
static int
cm_submit_so_need_rekey(struct cm_submit_state *state)
{
	return -1; /* nope */
}

/* Check if the CA was unreachable. */
static int
cm_submit_so_unreachable(struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Check if the CA was unconfigured. */
static int
cm_submit_so_unconfigured(struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Check if the CA is something we can ask for certificates. */
static int
cm_submit_so_unsupported(struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Done talking to the CA. */
static void
cm_submit_so_done(struct cm_submit_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_so_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	struct cm_submit_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_file) {
		cm_log(1, "Wrong submission method: only keys stored "
		       "in files can be used.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->entry = entry;
		state->save_ca_cookie = cm_submit_so_save_ca_cookie;
		state->ready = cm_submit_so_ready;
		state->issued = cm_submit_so_issued;
		state->rejected = cm_submit_so_rejected;
		state->need_scep_messages = cm_submit_so_need_scep_messages;
		state->need_rekey = cm_submit_so_need_rekey;
		state->unreachable = cm_submit_so_unreachable;
		state->unconfigured = cm_submit_so_unconfigured;
		state->unsupported = cm_submit_so_unsupported;
		state->done = cm_submit_so_done;
		state->delay = -1;
		state->subproc = cm_subproc_start(cm_submit_so_main, state,
						  ca, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
		if ((entry->cm_key_next_marker != NULL) &&
		    (strlen(entry->cm_key_next_marker) > 0)) {
			entry->cm_key_next_requested_count++;
		} else {
			entry->cm_key_requested_count++;
		}
	}
	return state;
}
