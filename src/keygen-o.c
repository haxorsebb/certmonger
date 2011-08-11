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

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <talloc.h>

#include "keygen.h"
#include "keygen-int.h"
#include "log.h"
#include "pin.h"
#include "prefs-o.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "util-o.h"

struct cm_keygen_state {
	struct cm_keygen_state_pvt pvt;
	struct cm_subproc_state *subproc;
};

static int
cm_keygen_o_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	struct cm_pin_cb_data cb_data;
	FILE *fp, *status;
	RSA *rsa;
	EVP_PKEY *pkey;
	char buf[LINE_MAX], *pin;
	long error;
	enum cm_key_algorithm cm_key_algorithm;
	int cm_key_size;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	cm_key_algorithm = entry->cm_key_type.cm_key_gen_algorithm;
	if (cm_key_algorithm == cm_key_unspecified) {
		cm_key_algorithm = CM_DEFAULT_PUBKEY_TYPE;
	}
	cm_key_size = entry->cm_key_type.cm_key_gen_size;
	if (cm_key_size <= 0) {
		cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
	}
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		util_o_init();
		ERR_load_crypto_strings();
		pkey = EVP_PKEY_new();
		if (pkey == NULL) {
			cm_log(1, "Internal error generating key.\n");
			_exit(CM_STATUS_ERROR_INTERNAL);
		}
		rsa = RSA_generate_key(cm_key_size, CM_DEFAULT_RSA_MODULUS,
				       NULL, NULL);
		if (rsa == NULL) {
			cm_log(1, "Error generating key.\n");
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(CM_STATUS_ERROR_INTERNAL);
		}
		EVP_PKEY_assign_RSA(pkey, rsa);
		fp = fopen(entry->cm_key_storage_location, "w");
		if (fp == NULL) {
			if (errno != ENOENT) {
				cm_log(1,
				       "Error opening key file \"%s\" "
				       "for writing.\n",
				       entry->cm_key_storage_location);
			}
			_exit(CM_STATUS_ERROR_INITIALIZING);
		}
		if (cm_pin_read_for_key(entry, &pin) != 0) {
			cm_log(1, "Error reading key encryption PIN.\n");
			_exit(CM_STATUS_ERROR_AUTH);
		}
		memset(&cb_data, 0, sizeof(cb_data));
		cb_data.entry = entry;
		cb_data.n_attempts = 0;
		if (PEM_write_PKCS8PrivateKey(fp, pkey,
					      pin ? cm_prefs_ossl_cipher() : NULL,
					      NULL, 0,
					      cm_pin_read_for_key_ossl_cb,
					      &cb_data) == 0) {
			cm_log(1, "Error storing key.\n");
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(CM_STATUS_ERROR_INITIALIZING);
		}
		fclose(fp);
		break;
	default:
		cm_log(1, "Unknown or unsupported key type.\n");
		_exit(CM_STATUS_ERROR_INTERNAL);
		break;
	}
	fclose(status);
	return 0;
}

/* Check if the keypair is ready. */
static int
cm_keygen_o_ready(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_keygen_o_get_fd(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Tell us if the keypair was saved to the location specified in the entry. */
static int
cm_keygen_o_saved_keypair(struct cm_store_entry *entry,
		          struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Tell us if we need a new/correct PIN to use the key store. */
static int
cm_keygen_o_need_pin(struct cm_store_entry *entry,
		     struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to generate the key. */
static int
cm_keygen_o_need_token(struct cm_store_entry *entry,
		       struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
static void
cm_keygen_o_done(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *
cm_keygen_o_start(struct cm_store_entry *entry)
{
	struct cm_keygen_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_file) {
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_keygen_o_ready;
		state->pvt.get_fd = cm_keygen_o_get_fd;
		state->pvt.saved_keypair = cm_keygen_o_saved_keypair;
		state->pvt.need_pin = cm_keygen_o_need_pin;
		state->pvt.need_token = cm_keygen_o_need_token;
		state->pvt.done = cm_keygen_o_done;
		state->subproc = cm_subproc_start(cm_keygen_o_main,
						  NULL, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
