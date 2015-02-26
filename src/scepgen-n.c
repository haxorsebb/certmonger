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
#include <cert.h>
#include <certdb.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secdig.h>
#include <secpkcs7.h>
#include <secport.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <talloc.h>

#include <krb5.h>

#include "certext.h"
#include "keygen.h"
#include "keyiread-n.h"
#include "log.h"
#include "pin.h"
#include "pkcs7.h"
#include "prefs-n.h"
#include "scepgen.h"
#include "scepgen-int.h"
#include "store.h"
#include "store-int.h"
#include "submit-o.h"
#include "submit-u.h"
#include "subproc.h"
#include "util-n.h"

struct cm_scepgen_state {
	struct cm_scepgen_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};

static void
cm_scepgen_n_resign(PKCS7 *p7, SECKEYPrivateKey *privkey)
{
	unsigned char *sabuf = NULL, *u;
	int salen;
	SECItem signature;
	SECOidTag digalg, sigalg;
	PKCS7_SIGNER_INFO *sinfo;

	if (p7 == NULL) {
		return;
	}
	if (sk_PKCS7_SIGNER_INFO_num(p7->d.sign->signer_info) != 1) {
		cm_log(1, "More than one signer, not sure what to do.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	sinfo = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);

	salen = i2d_ASN1_SET_OF_X509_ATTRIBUTE(sinfo->auth_attr, NULL,
					       i2d_X509_ATTRIBUTE,
					       V_ASN1_SET,
					       V_ASN1_UNIVERSAL,
					       IS_SET);
	sabuf = malloc(salen);
	if (sabuf == NULL) {
		cm_log(1, "Out of memory.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	u = sabuf;
	if (i2d_ASN1_SET_OF_X509_ATTRIBUTE(sinfo->auth_attr, &u,
					   i2d_X509_ATTRIBUTE,
					   V_ASN1_SET,
					   V_ASN1_UNIVERSAL,
					   IS_SET) != salen) {
		cm_log(1, "Encoding error.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	memset(&signature, 0, sizeof(signature));
	digalg = cm_submit_n_tag_from_nid(OBJ_obj2nid(sinfo->digest_alg->algorithm));
	sigalg = SEC_GetSignatureAlgorithmOidTag(privkey->keyType, digalg);
	if (sigalg == SEC_OID_UNKNOWN) {
		cm_log(1, "Unable to match digest algorithm and key.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if (SEC_SignData(&signature, sabuf, salen, privkey,
			 sigalg) != SECSuccess) {
		cm_log(1, "Error re-signing: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	M_ASN1_OCTET_STRING_set(sinfo->enc_digest,
				signature.data, signature.len);
	free(sabuf);
}

static int
cm_scepgen_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		  void *userdata)
{
	FILE *status;
	NSSInitContext *ctx;
	unsigned char nonce[16];
	struct cm_keyiread_n_ctx_and_keys *keys;
	const char *p, *es, *reason;
	int ec;
	PKCS7 *csr_new, *csr_old, *ias_new, *ias_old;
	EVP_PKEY *key;
	RSA *rsa;
	BIGNUM *exponent;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}

	if (ca->cm_ca_encryption_cert == NULL) {
		cm_log(1, "Can't generate new SCEP request data without "
		       "the RA/CA encryption certificate.\n");
		_exit(CM_SUB_STATUS_NEED_SCEP_DATA);
	}

	/* Start up NSS and open the database. */
	errno = 0;
	ctx = NSS_InitContext(entry->cm_key_storage_location,
			      NULL, NULL, NULL, NULL,
			      NSS_INIT_READONLY |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	ec = PORT_GetError();
	if (ctx == NULL) {
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			fprintf(status, "Error opening database "
				"'%s': %s.\n",
				entry->cm_key_storage_location, es);
			cm_log(1, "Error opening database '%s': %s.\n",
			       entry->cm_key_storage_location, es);
		} else {
			fprintf(status, "Error opening database '%s'.\n",
				entry->cm_key_storage_location);
			cm_log(1, "Error opening database '%s'.\n",
			       entry->cm_key_storage_location);
		}
		switch (ec) {
		case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
			_exit(CM_SUB_STATUS_ERROR_PERMS);
			break;
		default:
			_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
			break;
		}
	}
	reason = util_n_fips_hook();
	if (reason != NULL) {
		cm_log(1, "Error putting NSS into FIPS mode: %s\n", reason);
		_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
	}

	/* Use a dummy key to sign using OpenSSL. */
	cm_log(1, "Generating dummy key.\n");
	key = EVP_PKEY_new();
	if (key == NULL) {
		cm_log(1, "Error allocating new key.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
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
retry_gen:
	if (RSA_generate_key_ex(rsa, CM_DEFAULT_PUBKEY_SIZE, exponent, NULL) != 1) {
		cm_log(1, "Error generating key.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if (RSA_check_key(rsa) != 1) { /* should be unnecessary */
		cm_log(1, "Key fails checks.  Retrying.\n");
		goto retry_gen;
	}
	BN_free(exponent);

	/* Read the proper keys. */
	keys = cm_keyiread_n_get_keys(entry, 0);
	if ((keys->privkey->keyType != rsaKey) ||
	    ((keys->privkey_next != NULL) &&
	     (keys->privkey_next->keyType != rsaKey))) {
		cm_log(1, "Keys aren't RSA.  They won't work with SCEP.\n");
		_exit(CM_SUB_STATUS_ERROR_KEY_TYPE);
	}

	/* Sign using a dummy key. */
	EVP_PKEY_set1_RSA(key, rsa);
	csr_new = NULL;
	csr_old = NULL;
	ias_new = NULL;
	ias_old = NULL;
	cm_scepgen_o_cooked(ca, entry,
			    nonce, sizeof(nonce),
			    key, (keys->privkey_next != NULL) ? key : NULL,
			    &csr_new, &csr_old,
			    &ias_new, &ias_old);
	EVP_PKEY_free(key);

	/* Re-sign using the proper keys. */
	if (csr_old != NULL) {
		cm_log(1, "Re-signing PKCSREQ message with proper key.\n");
		cm_scepgen_n_resign(csr_old, keys->privkey);
	}
	if (ias_old != NULL) {
		cm_log(1, "Re-signing GetCertInitial message with proper key.\n");
		cm_scepgen_n_resign(ias_old, keys->privkey);
	}
	if (keys->privkey_next != NULL) {
		if (csr_new != NULL) {
			cm_log(1, "Re-signing PKCSREQ rekeying message with "
			       "proper key.\n");
			cm_scepgen_n_resign(csr_new, keys->privkey_next);
		}
		if (ias_new != NULL) {
			cm_log(1, "Re-signing GetCertInitial rekeying message "
			       "with proper key.\n");
			cm_scepgen_n_resign(ias_new, keys->privkey_next);
		}
	}

	p = cm_store_base64_from_bin(NULL, nonce, sizeof(nonce));
	fprintf(status, "%s:", p ? p : "");
	p = csr_old ? cm_scepgen_o_b64_from_p7(NULL, csr_old) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = ias_old ? cm_scepgen_o_b64_from_p7(NULL, ias_old) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = csr_new ? cm_scepgen_o_b64_from_p7(NULL, csr_new) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = ias_new ? cm_scepgen_o_b64_from_p7(NULL, ias_new) : NULL;
	fprintf(status, "%s:\n", p ? p : "");

	fclose(status);
	if (keys->pubkey != NULL) {
		SECKEY_DestroyPublicKey(keys->pubkey);
	}
	if (keys->pubkey_next != NULL) {
		SECKEY_DestroyPublicKey(keys->pubkey_next);
	}
	SECKEY_DestroyPrivateKey(keys->privkey);
	if (keys->privkey_next != NULL) {
		SECKEY_DestroyPrivateKey(keys->privkey_next);
	}
	if (NSS_ShutdownContext(ctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	_exit(0);
}

/* Check if a SCEP is ready. */
static int
cm_scepgen_n_ready(struct cm_scepgen_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_scepgen_n_get_fd(struct cm_scepgen_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

static char *
make_pem(void *parent, const char *p, size_t len)
{
	char *s, *t;

	s = talloc_strndup(parent, p, len);
	if (s != NULL) {
		t = cm_submit_u_pem_from_base64("PKCS7", 0, s);
		if (t != NULL) {
			talloc_free(s);
			s = talloc_strdup(parent, t);
			free(t);
		}
	}
	return s;
}

/* Save the SCEP data to the entry. */
static int
cm_scepgen_n_save_scep(struct cm_scepgen_state *state)
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
			state->entry->cm_scep_req = make_pem(state->entry,
							     p, q - p);
		}
	}
	if (*q != '\0') {
		p = ++q;
		q = p + strcspn(p, ":");
		if (q > p) {
			state->entry->cm_scep_gic = make_pem(state->entry,
							     p, q - p);
		}
	}
	if (*q != '\0') {
		p = ++q;
		q = p + strcspn(p, ":");
		if (q > p) {
			state->entry->cm_scep_req_next = make_pem(state->entry,
								  p, q - p);
		}
	}
	if (*q != '\0') {
		p = ++q;
		q = p + strcspn(p, ":");
		if (q > p) {
			state->entry->cm_scep_gic_next = make_pem(state->entry,
								  p, q - p);
		}
	}
	return 0;
}

/* Check if we need a PIN (or a new PIN) to access the key information. */
static int
cm_scepgen_n_need_pin(struct cm_scepgen_state *state)
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
cm_scepgen_n_need_token(struct cm_scepgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Check if we need information about the CA in order to generate data. */
static int
cm_scepgen_n_need_encryption_certs(struct cm_scepgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_NEED_SCEP_DATA)) {
		return 0;
	}
	return -1;
}

/* Check if we need a different key type (which is probably RSA). */
static int
cm_scepgen_n_need_different_key_type(struct cm_scepgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_KEY_TYPE)) {
		return 0;
	}
	return -1;
}

/* Clean up after SCEP generation. */
static void
cm_scepgen_n_done(struct cm_scepgen_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start SCEP request data generation using template information in the entry.
 * */
struct cm_scepgen_state *
cm_scepgen_n_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	struct cm_scepgen_state *state;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = &cm_scepgen_n_ready;
		state->pvt.get_fd = &cm_scepgen_n_get_fd;
		state->pvt.save_scep = &cm_scepgen_n_save_scep;
		state->pvt.need_pin = &cm_scepgen_n_need_pin;
		state->pvt.need_token = &cm_scepgen_n_need_token;
		state->pvt.need_encryption_certs =
			&cm_scepgen_n_need_encryption_certs;
		state->pvt.need_different_key_type =
			&cm_scepgen_n_need_different_key_type;
		state->pvt.done = &cm_scepgen_n_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_scepgen_n_main, state,
						  ca, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
