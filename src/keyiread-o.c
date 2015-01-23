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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include <talloc.h>

#include "keyiread.h"
#include "keyiread-int.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "util-o.h"

struct cm_keyiread_state {
	struct cm_keyiread_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};

static int
cm_keyiread_o_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	struct cm_pin_cb_data cb_data;
	FILE *pem, *fp;
	EVP_PKEY *pkey, *nextpkey = NULL;
	int status;
	char buf[LINE_MAX];
	const char *alg;
	int bits, length;
	long error;
	char *pin, *pubkey, *pubikey, *nextfile;
	unsigned char *tmp;

	util_o_init();
	ERR_load_crypto_strings();
	status = CM_SUB_STATUS_INTERNAL_ERROR;
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		cm_log(1, "Unable to initialize I/O.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	pem = fopen(entry->cm_key_storage_location, "r");
	if (pem != NULL) {
		if (cm_pin_read_for_key(entry, &pin) != 0) {
			cm_log(1, "Error reading key encryption PIN.\n");
			_exit(CM_SUB_STATUS_ERROR_AUTH);
		}
		memset(&cb_data, 0, sizeof(cb_data));
		cb_data.entry = entry;
		cb_data.n_attempts = 0;
		pkey = PEM_read_PrivateKey(pem, NULL,
					   cm_pin_read_for_key_ossl_cb,
					   &cb_data);
		if (pkey == NULL) {
			cm_log(1, "Internal error reading key from \"%s\".\n",
			       entry->cm_key_storage_location);
			status = CM_SUB_STATUS_ERROR_AUTH; /* XXX */
		} else {
			if ((pin != NULL) &&
			    (strlen(pin) > 0) &&
			    (cb_data.n_attempts == 0)) {
				cm_log(1, "PIN was not needed to read private "
				       "key '%s', though one was provided. "
				       "Treating this as an error.\n",
				       entry->cm_key_storage_location);
				status = CM_SUB_STATUS_ERROR_AUTH; /* XXX */
			} else {
				status = 0;
			}
		}
		fclose(pem);
		if ((status == 0) &&
		    (entry->cm_key_next_marker != NULL) &&
		    (strlen(entry->cm_key_next_marker) > 0)) {
			nextfile = util_build_next_filename(entry->cm_key_storage_location, entry->cm_key_next_marker);
			pem = fopen(nextfile, "r");
			if (pem != NULL) {
				nextpkey = PEM_read_PrivateKey(pem, NULL,
							       cm_pin_read_for_key_ossl_cb,
							       &cb_data);
				if (nextpkey == NULL) {
					cm_log(1, "Internal error reading key from \"%s\".\n",
					       nextfile);
					status = CM_SUB_STATUS_ERROR_AUTH; /* XXX */
				} else {
					if ((pin != NULL) &&
					    (strlen(pin) > 0) &&
					    (cb_data.n_attempts == 0)) {
						cm_log(1, "PIN was not needed to read private "
						       "key '%s', though one was provided. "
						       "Treating this as an error.\n",
						       nextfile);
						status = CM_SUB_STATUS_ERROR_AUTH; /* XXX */
					}
				}
				fclose(pem);
			} else {
				cm_log(1, "Error opening key file '%s' "
				       "for reading: %s.\n",
				       nextfile, strerror(errno));
				nextpkey = NULL;
			}
			free(nextfile);
		}
	} else {
		if (errno != ENOENT) {
			cm_log(1, "Error opening key file '%s' "
			       "for reading: %s.\n",
			       entry->cm_key_storage_location,
			       strerror(errno));
		}
		pkey = NULL;
	}
	if (status == 0) {
		alg = "";
		bits = 0;
		pubkey = "";
		pubikey = "";
		if (pkey != NULL) {
			switch (EVP_PKEY_type(pkey->type)) {
			case EVP_PKEY_RSA:
				cm_log(3, "Key is an RSA key.\n");
				alg = "RSA";
				break;
#ifdef CM_ENABLE_DSA
			case EVP_PKEY_DSA:
				cm_log(3, "Key is a DSA key.\n");
				alg = "DSA";
				break;
#endif
#ifdef CM_ENABLE_EC
			case EVP_PKEY_EC:
				cm_log(3, "Key is an EC key.\n");
				alg = "EC";
				break;
#endif
			default:
				cm_log(3, "Key is for an unknown algorithm.\n");
				alg = "";
				break;
			}
			bits = EVP_PKEY_bits(pkey);
			cm_log(3, "Key size is %d.\n", bits);
			tmp = NULL;
			length = i2d_PUBKEY(pkey, (unsigned char **) &tmp);
			if (length > 0) {
				pubikey = cm_store_hex_from_bin(NULL, tmp, length);
			}
			tmp = NULL;
			length = i2d_PublicKey(pkey, (unsigned char **) &tmp);
			if (length > 0) {
				pubkey = cm_store_hex_from_bin(NULL, tmp, length);
			}
		}
		fprintf(fp, "%s/%d/%s/%s\n", alg, bits, pubikey, pubkey);
		if (nextpkey != NULL) {
			switch (EVP_PKEY_type(nextpkey->type)) {
			case EVP_PKEY_RSA:
				cm_log(3, "Next key is an RSA key.\n");
				alg = "RSA";
				break;
#ifdef CM_ENABLE_DSA
			case EVP_PKEY_DSA:
				cm_log(3, "Next key is a DSA key.\n");
				alg = "DSA";
				break;
#endif
#ifdef CM_ENABLE_EC
			case EVP_PKEY_EC:
				cm_log(3, "Next key is an EC key.\n");
				alg = "EC";
				break;
#endif
			default:
				cm_log(3, "Next key is for an unknown algorithm.\n");
				alg = "";
				break;
			}
			bits = EVP_PKEY_bits(nextpkey);
			cm_log(3, "Next key size is %d.\n", bits);
			tmp = NULL;
			length = i2d_PUBKEY(nextpkey, (unsigned char **) &tmp);
			if (length > 0) {
				pubikey = cm_store_hex_from_bin(NULL, tmp, length);
			}
			tmp = NULL;
			length = i2d_PublicKey(nextpkey, (unsigned char **) &tmp);
			if (length > 0) {
				pubkey = cm_store_hex_from_bin(NULL, tmp, length);
			}
			fprintf(fp, "%s/%d/%s/%s\n", alg, bits, pubikey, pubkey);
		} else {
			fprintf(fp, "\n");
		}
		status = 0;
	} else {
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
	}
	fclose(fp);
	if (status != 0) {
		_exit(status);
	}
	return 0;
}

/* Check if we were able to successfully read the key information. */
static int
cm_keyiread_o_finished_reading(struct cm_keyiread_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Check if we need a PIN (or a new PIN) to access the key information. */
static int
cm_keyiread_o_need_pin(struct cm_keyiread_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to access the key information. */
static int
cm_keyiread_o_need_token(struct cm_keyiread_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Check if something changed, for example we finished reading the data we need
 * from the key file. */
static int
cm_keyiread_o_ready(struct cm_keyiread_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_keyiread_o_get_fd(struct cm_keyiread_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Clean up after reading the key. */
static void
cm_keyiread_o_done(struct cm_keyiread_state *state)
{
	if (state->subproc != NULL) {
		cm_keyiread_read_data_from_buffer(state->entry,
						  cm_subproc_get_msg(state->subproc,
								     NULL));
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start reading the key from the configured location. */
struct cm_keyiread_state *
cm_keyiread_o_start(struct cm_store_entry *entry)
{
	struct cm_keyiread_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_file) {
		cm_log(1, "Wrong read method: can only read keys "
		       "from a file.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.finished_reading = cm_keyiread_o_finished_reading;
		state->pvt.need_pin = cm_keyiread_o_need_pin;
		state->pvt.need_token = cm_keyiread_o_need_token;
		state->pvt.ready = cm_keyiread_o_ready;
		state->pvt.get_fd= cm_keyiread_o_get_fd;
		state->pvt.done= cm_keyiread_o_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_keyiread_o_main, state,
						  NULL, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
