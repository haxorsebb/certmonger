/*
 * Copyright (C) 2009,2010,2011,2013,2014 Red Hat, Inc.
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
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>

#ifdef CM_ENABLE_DSA
#include <openssl/dsa.h>
#endif
#ifdef CM_ENABLE_EC
#include <openssl/ec.h>
#endif
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
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
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};

static int
cm_keygen_o_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	struct cm_pin_cb_data cb_data;
	FILE *fp, *status;
	EVP_PKEY *pkey;
	char buf[LINE_MAX], *pin, *pubhex, *pubihex;
	unsigned char *p, *q;
	long error, errno_save;
	enum cm_key_algorithm cm_key_algorithm;
	int cm_key_size;
	int len;
	BIGNUM *exponent;
	RSA *rsa;
#ifdef CM_ENABLE_DSA
	DSA *dsa;
#endif
#ifdef CM_ENABLE_EC
	EC_KEY *ec;
	int ecurve;
#endif

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	cm_key_algorithm = entry->cm_key_type.cm_key_gen_algorithm;
	if (cm_key_algorithm == cm_key_unspecified) {
		cm_key_algorithm = CM_DEFAULT_PUBKEY_TYPE;
	}
	cm_key_size = entry->cm_key_type.cm_key_gen_size;
	if (cm_key_size <= 0) {
		cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
	}

	util_o_init();
	ERR_load_crypto_strings();
	if (RAND_status() != 1) {
		cm_log(1, "PRNG not seeded for generating key.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}

retry_gen:
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		cm_log(1, "Error allocating new key.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		exponent = BN_new();
		if (exponent == NULL) {
			cm_log(1, "Error setting up exponent.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		BN_set_word(exponent, CM_DEFAULT_RSA_EXPONENT);
		rsa = RSA_new();
		if (rsa == NULL) {
			cm_log(1, "Error allocating new RSA key.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		if (RSA_generate_key_ex(rsa, cm_key_size, exponent, NULL) != 1) {
			if (cm_key_size != CM_DEFAULT_PUBKEY_SIZE) {
				cm_log(1, "Error generating %d-bit key, "
				       "attempting %d bits.\n",
				       cm_key_size, CM_DEFAULT_PUBKEY_SIZE);
				cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
				goto retry_gen;
			}
			cm_log(1, "Error generating key.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		if (RSA_check_key(rsa) != 1) { /* should be unnecessary */
			cm_log(1, "Key fails checks.  Retrying.\n");
			goto retry_gen;
		}
		EVP_PKEY_set1_RSA(pkey, rsa);
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		dsa = DSA_new();
		if (dsa == NULL) {
			cm_log(1, "Error allocating new DSA key.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		if (DSA_generate_parameters_ex(dsa, cm_key_size,
					       NULL, 0,
					       NULL, NULL, NULL) != 1) {
			if (cm_key_size != CM_DEFAULT_PUBKEY_SIZE) {
				cm_log(1, "Error generating %d-bit key, "
				       "attempting %d bits.\n",
				       cm_key_size, CM_DEFAULT_PUBKEY_SIZE);
				cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
				goto retry_gen;
			}
			cm_log(1, "Error generating parameters.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		if (DSA_generate_key(dsa) != 1) {
			cm_log(1, "Error generating key.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		EVP_PKEY_set1_DSA(pkey, dsa);
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		if (cm_key_size <= 256)
			ecurve = NID_X9_62_prime256v1;
		else if (cm_key_size <= 384)
			ecurve = NID_secp384r1;
		else
			ecurve = NID_secp521r1;
		ec = EC_KEY_new_by_curve_name(ecurve);
		while ((ec == NULL) && (ecurve != NID_X9_62_prime256v1)) {
			cm_log(1, "Error allocating new EC key.\n");
			switch (ecurve) {
			case NID_secp521r1:
				cm_log(1, "Trying with a smaller key.\n");
				ecurve = NID_secp384r1;
				ec = EC_KEY_new_by_curve_name(ecurve);
				break;
			case NID_secp384r1:
				cm_log(1, "Trying with a smaller key.\n");
				ecurve = NID_X9_62_prime256v1;
				ec = EC_KEY_new_by_curve_name(ecurve);
				break;
			}
		}
		if (ec == NULL) {
			cm_log(1, "Error allocating new EC key.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		if (EC_KEY_generate_key(ec) != 1) {
			cm_log(1, "Error generating key.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
		EVP_PKEY_set1_EC_KEY(pkey, ec);
		break;
#endif
	default:
		cm_log(1, "Unknown or unsupported key type.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		break;
	}

	fp = fopen(entry->cm_key_storage_location, "w");
	if (fp == NULL) {
		if (errno != ENOENT) {
			error = errno;
			cm_log(1,
			       "Error opening key file \"%s\" "
			       "for writing: %s.\n",
			       entry->cm_key_storage_location,
			       strerror(errno));
			switch (error) {
			case EACCES:
			case EPERM:
				_exit(CM_SUB_STATUS_ERROR_PERMS);
				break;
			default:
				break;
			}
		}
		_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
	}

	if (cm_pin_read_for_key(entry, &pin) != 0) {
		cm_log(1, "Error reading key encryption PIN.\n");
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}

	memset(&cb_data, 0, sizeof(cb_data));
	cb_data.entry = entry;
	cb_data.n_attempts = 0;
	if (PEM_write_PKCS8PrivateKey(fp, pkey,
				      pin ? cm_prefs_ossl_cipher() : NULL,
				      NULL, 0,
				      cm_pin_read_for_key_ossl_cb,
				      &cb_data) == 0) {
		errno_save = errno;
		cm_log(1, "Error storing key.\n");
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		switch (errno_save) {
		case EACCES:
		case EPERM:
			_exit(CM_SUB_STATUS_ERROR_PERMS);
			break;
		default:
			break;
		}
		_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
	}
	pubihex = "";
	len = i2d_PUBKEY(pkey, NULL);
	if (len > 0) {
		p = malloc(len);
		if (p != NULL) {
			q = p;
			if (i2d_PUBKEY(pkey, &q) == len) {
				pubihex = cm_store_hex_from_bin(NULL, p, q - p);
			}
			free(p);
		}
	}
	pubhex = "";
	len = i2d_PublicKey(pkey, NULL);
	if (len > 0) {
		p = malloc(len);
		if (p != NULL) {
			q = p;
			if (i2d_PublicKey(pkey, &q) == len) {
				pubhex = cm_store_hex_from_bin(NULL, p, q - p);
			}
			free(p);
		}
	}
	fprintf(status, "%s\n%s\n", pubihex, pubhex);
	fclose(fp);
	fclose(status);

	return 0;
}

/* Check if the keypair is ready. */
static int
cm_keygen_o_ready(struct cm_keygen_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_keygen_o_get_fd(struct cm_keygen_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Tell us if the keypair was saved to the location specified in the entry. */
static int
cm_keygen_o_saved_keypair(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Tell us if we don't have permissions. */
static int
cm_keygen_o_need_perms(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_PERMS)) {
		return 0;
	}
	return -1;
}

/* Tell us if we need a new/correct PIN to use the key store. */
static int
cm_keygen_o_need_pin(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to generate the key. */
static int
cm_keygen_o_need_token(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
static void
cm_keygen_o_done(struct cm_keygen_state *state)
{
	const char *pubkey_info, *p;
	int len;

	if (state->subproc != NULL) {
		pubkey_info = cm_subproc_get_msg(state->subproc, NULL);
		if (pubkey_info != NULL) {
			len = strcspn(pubkey_info, "\r\n");
			state->entry->cm_key_pubkey_info =
				talloc_strndup(state->entry, pubkey_info, len);
			p = pubkey_info + len;
			p += strspn(p, "\r\n");
			len = strcspn(p, "\r\n");
			state->entry->cm_key_pubkey =
				talloc_strndup(state->entry, p, len);
		} else {
			state->entry->cm_key_pubkey_info = NULL;
			state->entry->cm_key_pubkey = NULL;
		}
		cm_subproc_done(state->subproc);
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
		state->pvt.need_perms = cm_keygen_o_need_perms;
		state->pvt.need_pin = cm_keygen_o_need_pin;
		state->pvt.need_token = cm_keygen_o_need_token;
		state->pvt.done = cm_keygen_o_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_keygen_o_main, state,
						  NULL, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
