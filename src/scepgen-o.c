/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <nss.h>
#include <pk11pub.h>
#include <secpkcs7.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <talloc.h>

#include <krb5.h>

#include "certext.h"
#include "keygen.h"
#include "log.h"
#include "pin.h"
#include "pkcs7.h"
#include "prefs-o.h"
#include "scepgen.h"
#include "scepgen-int.h"
#include "store.h"
#include "store-int.h"
#include "submit-u.h"
#include "subproc.h"
#include "util-o.h"

struct cm_scepgen_state {
	struct cm_scepgen_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};

static EVP_PKEY *
key_from_file(const char *filename, struct cm_store_entry *entry)
{
	char buf[LINE_MAX];
	struct cm_pin_cb_data cb_data;
	EVP_PKEY *pkey;
	FILE *keyfp;
	char *pin;
	long error;

	keyfp = fopen(filename, "r");
	if (keyfp == NULL) {
		if (errno != ENOENT) {
			cm_log(1, "Error opening key file \"%s\" "
			       "for reading: %s.\n",
			       filename, strerror(errno));
		}
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if (filename != NULL) {
		keyfp = fopen(filename, "r");
		if (keyfp == NULL) {
			if (errno != ENOENT) {
				cm_log(1, "Error opening key file \"%s\" "
				       "for reading: %s.\n",
				       filename, strerror(errno));
			}
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
	} else {
		keyfp = NULL;
	}
	if (cm_pin_read_for_key(entry, &pin) != 0) {
		cm_log(1, "Internal error reading key encryption PIN.\n");
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}
	memset(&cb_data, 0, sizeof(cb_data));
	cb_data.entry = entry;
	cb_data.n_attempts = 0;
	pkey = PEM_read_PrivateKey(keyfp, NULL,
				   cm_pin_read_for_key_ossl_cb, &cb_data);
	if (pkey == NULL) {
		error = errno;
		cm_log(1, "Error reading private key '%s': %s.\n",
		       filename, strerror(error));
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		_exit(CM_SUB_STATUS_ERROR_AUTH); /* XXX */
	} else {
		if ((pin != NULL) &&
		    (strlen(pin) > 0) &&
		    (cb_data.n_attempts == 0)) {
			cm_log(1, "PIN was not needed to read private "
			       "key '%s', though one was provided. "
			       "Treating this as an error.\n",
			       filename);
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(CM_SUB_STATUS_ERROR_AUTH); /* XXX */
		}
	}
	return pkey;
}

static X509 *
cert_from_pem(char *pem, struct cm_store_entry *entry)
{
	BIO *in;
	X509 *cert = NULL;

	if ((pem != NULL) && (strlen(pem) > 0)) {
		in = BIO_new_mem_buf(pem, -1);
		if (in == NULL) {
			cm_log(1, "Out of memory.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
		BIO_free(in);
		if (cert == NULL) {
			cm_log(1, "Error parsing certificate.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		return cert;
	}
	return NULL;
}

static int
cert_cmp(const void *a, const void *b)
{
	X509 * const *x, * const *y;

	x = a;
	y = b;
	return X509_cmp(*x, *y);
}


static STACK_OF(X509) *
certs_from_nickcerts(struct cm_nickcert **list)
{
	BIO *in;
	X509 *cert = NULL;
	STACK_OF(X509) *sk = NULL;
	struct cm_nickcert *this;
	int i;

	for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
		this = list[i];
		if ((this->cm_cert != NULL) && (strlen(this->cm_cert) > 0)) {
			in = BIO_new_mem_buf(this->cm_cert, -1);
			if (in == NULL) {
				cm_log(1, "Out of memory.\n");
				_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			}
			cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
			BIO_free(in);
			if (cert == NULL) {
				cm_log(1, "Error parsing certificate.\n");
				_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			}
			if (sk == NULL) {
				sk = sk_X509_new(cert_cmp);
				if (sk == NULL) {
					cm_log(1, "Out of memory.\n");
					_exit(CM_SUB_STATUS_INTERNAL_ERROR);
				}
			}
			sk_X509_push(sk, cert);
		}
	}
	return sk;
}

char *
cm_scepgen_o_b64_from_p7(void *parent, PKCS7 *p7)
{
	unsigned char *u, *p;
	char *ret;
	int len;

	len = i2d_PKCS7(p7, NULL);
	p = malloc(len);
	if (p == NULL) {
		return NULL;
	}
	u = p;
	if (i2d_PKCS7(p7, &u) != len) {
		free(p);
		return NULL;
	}
	ret = cm_store_base64_from_bin(parent, p, len);
	free(p);
	return ret;
}

void
cm_scepgen_o_cooked(struct cm_store_ca *ca, struct cm_store_entry *entry,
		    unsigned char *nonce, size_t nonce_length,
		    EVP_PKEY *old_pkey, EVP_PKEY *new_pkey,
		    PKCS7 **csr_new, PKCS7 **csr_old,
		    PKCS7 **ias_new, PKCS7 **ias_old)
{
	char buf[LINE_MAX];
	unsigned char *new_ias, *old_ias, *csr;
	size_t new_ias_length, old_ias_length, csr_length;
	BIO *in;
	X509 *old_cert, *new_cert = NULL;
	STACK_OF(X509) *chain = NULL;
	EVP_PKEY *pubkey;
	char *pem;
	long error;
	int flags = PKCS7_BINARY | PKCS7_NOSMIMECAP | PKCS7_NOVERIFY;

	util_o_init();
	ERR_load_crypto_strings();
        if (RAND_status() != 1) {
		cm_log(1, "PRNG not seeded for generating key.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if (RAND_pseudo_bytes(nonce, nonce_length) == -1) {
		cm_log(1, "PRNG unable to generate nonce.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}

	if (entry->cm_cert != NULL) {
		old_cert = cert_from_pem(entry->cm_cert, entry);
	} else {
		old_cert = NULL;
	}
	pem = cm_submit_u_pem_from_base64("CERTIFICATE", 0,
					  entry->cm_minicert);
	if (pem == NULL) {
		cm_log(1, "Out of memory.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	new_cert = cert_from_pem(pem, entry);
	if (new_cert == NULL) {
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		free(pem);
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if (old_cert != NULL) {
		if (cm_pkcs7_envelope_ias(ca->cm_ca_encryption_cert,
					  ca->cm_ca_encryption_issuer_cert,
					  entry->cm_cert,
					  &old_ias, &old_ias_length) != 0) {
			cm_log(1, "Error generating enveloped issuer-and-subject.\n");
			free(pem);
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
	} else {
		old_ias = NULL;
		old_ias_length = 0;
	}
	if (cm_pkcs7_envelope_ias(ca->cm_ca_encryption_cert,
				  ca->cm_ca_encryption_issuer_cert,
				  pem,
				  &new_ias, &new_ias_length) != 0) {
		cm_log(1, "Error generating enveloped issuer-and-subject.\n");
		free(pem);
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	free(pem);
	if (cm_pkcs7_envelope_csr(ca->cm_ca_encryption_cert,
				  entry->cm_csr,
				  &csr, &csr_length) != 0) {
		cm_log(1, "Error generating enveloped CSR.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}

	chain = certs_from_nickcerts(entry->cm_cert_chain);
	if (old_cert != NULL) {
		/* Sign the data using the previously-issued certificate and
		 * the matching key. */
		pubkey = X509_PUBKEY_get(old_cert->cert_info->key);
		X509_PUBKEY_set(&old_cert->cert_info->key, old_pkey);
		in = BIO_new_mem_buf(csr, csr_length);
		if (in == NULL) {
			cm_log(1, "Out of memory.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		*csr_old = PKCS7_sign(old_cert, old_pkey, chain, in, flags);
		BIO_free(in);
		in = BIO_new_mem_buf(old_ias, old_ias_length);
		if (in == NULL) {
			cm_log(1, "Out of memory.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		*ias_old = PKCS7_sign(old_cert, old_pkey, chain, in, flags);
		BIO_free(in);
		X509_PUBKEY_set(&old_cert->cert_info->key, pubkey);
		X509_free(old_cert);
	} else {
		*csr_old = NULL;
		*ias_old = NULL;
	}
	if (new_pkey != NULL) {
		/* Sign the data using the new key and mini certificate, since
		 * any previously-issued certificate won't match. */
		pubkey = X509_PUBKEY_get(new_cert->cert_info->key);
		X509_PUBKEY_set(&new_cert->cert_info->key, new_pkey);
		in = BIO_new_mem_buf(csr, csr_length);
		if (in == NULL) {
			cm_log(1, "Out of memory.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		*csr_new = PKCS7_sign(new_cert, new_pkey, NULL, in, flags);
		BIO_free(in);
		in = BIO_new_mem_buf(new_ias, new_ias_length);
		if (in == NULL) {
			cm_log(1, "Out of memory.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		*ias_new = PKCS7_sign(new_cert, new_pkey, NULL, in, flags);
		BIO_free(in);
		X509_PUBKEY_set(&new_cert->cert_info->key, pubkey);
	} else {
		/* Sign the data using the old key and the mini certificate,
		 * since we may not have a previously-issued certificate (and
		 * if we do, we just did that). */
		pubkey = X509_PUBKEY_get(new_cert->cert_info->key);
		X509_PUBKEY_set(&new_cert->cert_info->key, old_pkey);
		in = BIO_new_mem_buf(csr, csr_length);
		if (in == NULL) {
			cm_log(1, "Out of memory.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		*csr_new = PKCS7_sign(new_cert, old_pkey, NULL, in, PKCS7_BINARY);
		BIO_free(in);
		in = BIO_new_mem_buf(new_ias, new_ias_length);
		if (in == NULL) {
			cm_log(1, "Out of memory.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		*ias_new = PKCS7_sign(new_cert, old_pkey, NULL, in, PKCS7_BINARY);
		X509_PUBKEY_set(&new_cert->cert_info->key, pubkey);
		BIO_free(in);
	}
	X509_free(new_cert);
	while ((error = ERR_get_error()) != 0) {
		ERR_error_string_n(error, buf, sizeof(buf));
		cm_log(1, "%s\n", buf);
	}
}

static int
cm_scepgen_o_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		  void *userdata)
{
	unsigned char nonce[16];
	PKCS7 *csr_new, *csr_old, *ias_new, *ias_old;
	FILE *status;
	EVP_PKEY *old_pkey, *new_pkey = NULL;
	char *filename, *p;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}

	if (ca->cm_ca_encryption_cert == NULL) {
		cm_log(1, "Can't generate new SCEP request data without "
		       "the RA/CA encryption certificate.\n");
		_exit(CM_SUB_STATUS_NEED_SCEP_DATA);
	}

	old_pkey = key_from_file(entry->cm_key_storage_location, entry);
	if ((entry->cm_key_next_marker != NULL) &&
	    (strlen(entry->cm_key_next_marker) > 0)) {
		filename = util_build_next_filename(entry->cm_key_storage_location, entry->cm_key_next_marker);
		if (filename == NULL) {
			cm_log(1, "Error opening key file \"%s\" "
			       "for reading: %s.\n",
			       filename, strerror(errno));
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		filename = entry->cm_key_storage_location;
		new_pkey = key_from_file(filename, entry);
		free(filename);
	} else {
		new_pkey = NULL;
	}

	cm_scepgen_o_cooked(ca, entry, nonce, sizeof(nonce),
			    old_pkey, new_pkey,
			    &csr_new, &csr_old, &ias_new, &ias_old);

	p = cm_store_base64_from_bin(NULL, nonce, sizeof(nonce));
	fprintf(status, "%s:", p ? p : "");
	p = csr_old ? cm_scepgen_o_b64_from_p7(NULL, csr_old) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = ias_old ? cm_scepgen_o_b64_from_p7(NULL, ias_old) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = csr_new ? cm_scepgen_o_b64_from_p7(NULL, csr_new) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = ias_new ? cm_scepgen_o_b64_from_p7(NULL, ias_new) : NULL;
	fprintf(status, "%s\n", p ? p : "");

	fclose(status);
	if (new_pkey != NULL) {
		EVP_PKEY_free(new_pkey);
	}
	if (old_pkey != NULL) {
		EVP_PKEY_free(old_pkey);
	}
	return 0;
}

/* Check if a SCEP is ready. */
static int
cm_scepgen_o_ready(struct cm_scepgen_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_scepgen_o_get_fd(struct cm_scepgen_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Save the SCEP to the entry. */
static int
cm_scepgen_o_save_scep(struct cm_scepgen_state *state)
{
	int status;
	const char *p, *q;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
		return -1;
	}
	talloc_free(state->entry->cm_scep_nonce);
	talloc_free(state->entry->cm_scep_req);
	talloc_free(state->entry->cm_scep_gic);
	talloc_free(state->entry->cm_scep_req_next);
	talloc_free(state->entry->cm_scep_gic_next);
	p = cm_subproc_get_msg(state->subproc, NULL);
	q = p + strcspn(p, ":");
	state->entry->cm_scep_nonce = talloc_strndup(state->entry, p, q - p);
	state->entry->cm_scep_req = NULL;
	state->entry->cm_scep_gic = NULL;
	state->entry->cm_scep_req_next = NULL;
	state->entry->cm_scep_gic_next = NULL;
	if (*q != '\0') {
		p = ++q;
		q = p + strcspn(p, ":");
		if (q > p) {
			state->entry->cm_scep_req =
				talloc_strndup(state->entry, p, q - p);
		}
	}
	if (*q != '\0') {
		p = ++q;
		q = p + strcspn(p, ":");
		if (q > p) {
			state->entry->cm_scep_gic =
				talloc_strndup(state->entry, p, q - p);
		}
	}
	if (*q != '\0') {
		p = ++q;
		q = p + strcspn(p, ":");
		if (q > p) {
			state->entry->cm_scep_req_next =
				talloc_strndup(state->entry, p, q - p);
		}
	}
	if (*q != '\0') {
		p = ++q;
		q = p + strcspn(p, ":");
		if (q > p) {
			state->entry->cm_scep_gic_next =
				talloc_strndup(state->entry, p, q - p);
		}
	}
	return 0;
}

/* Check if we need a PIN (or a new PIN) to access the key information. */
static int
cm_scepgen_o_need_pin(struct cm_scepgen_state *state)
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
cm_scepgen_o_need_token(struct cm_scepgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Check if we need informatoin about the CA in order to generate data. */
static int
cm_scepgen_o_need_encryption_certs(struct cm_scepgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_NEED_SCEP_DATA)) {
		return 0;
	}
	return -1;
}

/* Clean up after SCEP generation. */
static void
cm_scepgen_o_done(struct cm_scepgen_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start SCEP request data generation using template information in the entry.
 * */
struct cm_scepgen_state *
cm_scepgen_o_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	struct cm_scepgen_state *state;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = &cm_scepgen_o_ready;
		state->pvt.get_fd = &cm_scepgen_o_get_fd;
		state->pvt.save_scep = &cm_scepgen_o_save_scep;
		state->pvt.need_pin = &cm_scepgen_o_need_pin;
		state->pvt.need_token = &cm_scepgen_o_need_token;
		state->pvt.need_encryption_certs =
			&cm_scepgen_o_need_encryption_certs;
		state->pvt.done = &cm_scepgen_o_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_scepgen_o_main, state,
						  ca, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
