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
#include <openssl/evp.h>
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
#include "scep.h"
#include "scep-o.h"
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
			cm_log(1, "Error parsing certificate \"%s\".\n", pem);
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

static void
set_pkimessage_attrs(PKCS7 *p7,
		     const char *tx, const char *msgtype,
		     const char *pkistatus, const char *failinfo,
		     const unsigned char *sender_nonce,
		     size_t sender_nonce_length,
		     const unsigned char *recipient_nonce,
		     size_t recipient_nonce_length)
{
	PKCS7_SIGNER_INFO *sinfo;
	ASN1_OCTET_STRING *s, *r;
	ASN1_PRINTABLESTRING *t, *m, *p, *f;

	sinfo = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	if (tx != NULL) {
		cm_log(1, "Setting transaction ID \"%s\".\n", tx);
		t = M_ASN1_PRINTABLE_new();
		if (t == NULL) {
			return;
		}
		ASN1_STRING_set(t, tx, strlen(tx));
		PKCS7_add_signed_attribute(sinfo, cm_scep_o_get_tx_nid(),
					   V_ASN1_PRINTABLESTRING, t);
	}
	if (msgtype != NULL) {
		cm_log(1, "Setting message type \"%s\".\n", msgtype);
		m = M_ASN1_PRINTABLE_new();
		if (m == NULL) {
			return;
		}
		ASN1_STRING_set(m, msgtype, strlen(msgtype));
		PKCS7_add_signed_attribute(sinfo, cm_scep_o_get_msgtype_nid(),
					   V_ASN1_PRINTABLESTRING, m);
	}
	if (pkistatus != NULL) {
		cm_log(1, "Setting pkiStatus \"%s\".\n", pkistatus);
		p = M_ASN1_PRINTABLE_new();
		if (p == NULL) {
			return;
		}
		ASN1_STRING_set(p, pkistatus, strlen(pkistatus));
		PKCS7_add_signed_attribute(sinfo, cm_scep_o_get_pkistatus_nid(),
					   V_ASN1_PRINTABLESTRING, p);
	}
	if (failinfo != NULL) {
		cm_log(1, "Setting failInfo \"%s\".\n", failinfo);
		f = M_ASN1_PRINTABLE_new();
		if (f == NULL) {
			return;
		}
		ASN1_STRING_set(f, failinfo, strlen(failinfo));
		PKCS7_add_signed_attribute(sinfo, cm_scep_o_get_failinfo_nid(),
					   V_ASN1_PRINTABLESTRING, f);
	}
	if (sender_nonce != NULL) {
		cm_log(1, "Setting sender nonce.\n");
		s = ASN1_OCTET_STRING_new();
		if (s == NULL) {
			return;
		}
		M_ASN1_OCTET_STRING_set(s, sender_nonce, sender_nonce_length);
		PKCS7_add_signed_attribute(sinfo, cm_scep_o_get_sender_nonce_nid(),
					   V_ASN1_OCTET_STRING, s);
	}
	if (recipient_nonce != NULL) {
		cm_log(1, "Setting recipient nonce.\n");
		r = ASN1_OCTET_STRING_new();
		if (r == NULL) {
			return;
		}
		M_ASN1_OCTET_STRING_set(r, recipient_nonce, recipient_nonce_length);
		PKCS7_add_signed_attribute(sinfo,
					   cm_scep_o_get_recipient_nonce_nid(),
					   V_ASN1_OCTET_STRING, r);
	}
	PKCS7_add_signed_attribute(sinfo, NID_pkcs9_contentType, V_ASN1_OBJECT,
				   OBJ_nid2obj(NID_pkcs7_data));
}

static PKCS7 *
build_pkimessage(EVP_PKEY *key, X509 *signer, STACK_OF(X509) *certs,
		 enum cm_prefs_digest pref_digest,
		 unsigned char *data, size_t data_length,
		 const char *tx, const char *msgtype,
		 const char *pkistatus, const char *failinfo,
		 const unsigned char *sender_nonce,
		 size_t sender_nonce_length,
		 const unsigned char *recipient_nonce,
		 size_t recipient_nonce_length)
{
	BIO *in, *out;
	PKCS7 *ret;
	PKCS7_SIGNER_INFO *p7i;
	X509_ALGOR *digests;
	ASN1_OBJECT *digest;
	long error;
	char buf[LINE_MAX];
	int flags = PKCS7_BINARY | PKCS7_NOSMIMECAP | PKCS7_NOVERIFY;

	in = BIO_new_mem_buf(data, data_length);
	if (in == NULL) {
		cm_log(1, "Out of memory.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	ret = PKCS7_sign(signer, key, certs, in, flags);
	if (ret == NULL) {
		cm_log(1, "Error signing data.\n");
		goto errors;
	}
	BIO_free(in);

	/* Set the digest to use for signing. */
	if (sk_PKCS7_SIGNER_INFO_num(ret->d.sign->signer_info) != 1) {
		cm_log(1, "Error signing data: %d signers.\n",
		       sk_PKCS7_SIGNER_INFO_num(ret->d.sign->signer_info));
		goto errors;
	}
	p7i = sk_PKCS7_SIGNER_INFO_value(ret->d.sign->signer_info, 0);
	digest = NULL;
	switch (pref_digest) {
	case cm_prefs_sha256:
		digest = OBJ_nid2obj(NID_sha256);
		break;
	case cm_prefs_sha384:
		digest = OBJ_nid2obj(NID_sha384);
		break;
	case cm_prefs_sha512:
		digest = OBJ_nid2obj(NID_sha512);
		break;
	case cm_prefs_sha1:
		digest = OBJ_nid2obj(NID_sha1);
		break;
	case cm_prefs_md5:
		digest = OBJ_nid2obj(NID_md5);
		break;
	}
	if ((digest != NULL) && (p7i->digest_alg != NULL)) {
		ASN1_OBJECT_free(p7i->digest_alg->algorithm);
		p7i->digest_alg->algorithm = OBJ_dup(digest);
		digests = sk_X509_ALGOR_pop(ret->d.sign->md_algs);
		if (digests != NULL) {
			X509_ALGOR_free(digests);
		}
		sk_X509_ALGOR_push(ret->d.sign->md_algs,
				   X509_ALGOR_dup(p7i->digest_alg));
	}

	/* Set the SCEP parameters. */
	set_pkimessage_attrs(ret, tx, msgtype, pkistatus, failinfo,
			     sender_nonce, sender_nonce_length,
			     recipient_nonce, recipient_nonce_length);

	/* We'd use PKCS7_SIGNER_INFO_sign() here, but it's relatively new, and
	 * we want to build on versions of OpenSSL that didn't have it. */
	PKCS7_content_new(ret, NID_pkcs7_data);
	out = PKCS7_dataInit(ret, NULL);
	if (out == NULL) {
		cm_log(1, "Error signing data.\n");
		goto errors;
	}
	BIO_write(out, data, data_length);
	PKCS7_dataFinal(ret, out);
	cm_log(1, "Signed data.\n");
	return ret;
errors:
	while ((error = ERR_get_error()) != 0) {
		ERR_error_string_n(error, buf, sizeof(buf));
		cm_log(1, "%s\n", buf);
	}
	_exit(CM_SUB_STATUS_INTERNAL_ERROR);
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
	X509 *old_cert, *new_cert = NULL;
	STACK_OF(X509) *chain = NULL;
	EVP_PKEY *pubkey;
	char *pem;
	const char *capability;
	int i;
	long error;
	enum cm_prefs_cipher cipher;
	enum cm_prefs_digest digest, pref_digest;

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
	cipher = cm_prefs_des;
	for (i = 0;
	     (ca->cm_ca_capabilities != NULL) &&
	     (ca->cm_ca_capabilities[i] != NULL);
	     i++) {
		capability = ca->cm_ca_capabilities[i];
		if (strcmp(capability, "DES3") == 0) {
			cm_log(1, "Server supports DES3, using that.\n");
			cipher = cm_prefs_des3;
			break;
		}
	}
	if (cipher == cm_prefs_des) {
		cm_log(1, "Server does not support DES3, using DES.\n");
	}
	pref_digest = cm_prefs_preferred_digest();
	digest = cm_prefs_md5;
	for (i = 0;
	     (ca->cm_ca_capabilities != NULL) &&
	     (ca->cm_ca_capabilities[i] != NULL);
	     i++) {
		capability = ca->cm_ca_capabilities[i];
		if ((pref_digest == cm_prefs_sha1) &&
		    (strcmp(capability, "SHA-1") == 0)) {
			cm_log(1, "Server supports SHA-1, using that.\n");
			digest = cm_prefs_sha1;
			break;
		}
		if ((pref_digest == cm_prefs_sha256) &&
		    (strcmp(capability, "SHA-256") == 0)) {
			cm_log(1, "Server supports SHA-256, using that.\n");
			digest = cm_prefs_sha256;
			break;
		}
		if ((pref_digest == cm_prefs_sha512) &&
		    (strcmp(capability, "SHA-512") == 0)) {
			cm_log(1, "Server supports SHA-512, using that.\n");
			digest = cm_prefs_sha512;
			break;
		}
	}
	if (digest == cm_prefs_md5) {
		cm_log(1, "Server does not support better digests, using MD5.\n");
	}
	if (old_cert != NULL) {
		if (cm_pkcs7_envelope_ias(ca->cm_ca_encryption_cert, cipher,
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
	if (cm_pkcs7_envelope_ias(ca->cm_ca_encryption_cert, cipher,
				  ca->cm_ca_encryption_issuer_cert,
				  pem,
				  &new_ias, &new_ias_length) != 0) {
		cm_log(1, "Error generating enveloped issuer-and-subject.\n");
		free(pem);
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	free(pem);
	if (cm_pkcs7_envelope_csr(ca->cm_ca_encryption_cert, cipher,
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
		cm_log(1, "Generating PKCSREQ pkiMessage.\n");
		*csr_old = build_pkimessage(old_pkey, old_cert, chain, digest,
					    csr, csr_length,
					    entry->cm_scep_tx,
					    SCEP_MSGTYPE_PKCSREQ,
					    NULL, NULL,
					    nonce, nonce_length,
					    NULL, 0);
		cm_log(1, "Generating GetCertInitial pkiMessage.\n");
		*ias_old = build_pkimessage(old_pkey, old_cert, chain, digest,
					    old_ias, old_ias_length,
					    entry->cm_scep_tx,
					    SCEP_MSGTYPE_GETCERTINITIAL,
					    NULL, NULL,
					    nonce, nonce_length,
					    NULL, 0);
		cm_log(1, "Signing using previously-issued key and cert.\n");
		X509_PUBKEY_set(&old_cert->cert_info->key, pubkey);
		X509_free(old_cert);
	} else {
		if (new_pkey == NULL) {
			/* Sign the data using the old key and the mini certificate,
			 * since we may not have a previously-issued certificate (and
			 * if we do, we did that in another code path. */
			pubkey = X509_PUBKEY_get(new_cert->cert_info->key);
			X509_PUBKEY_set(&new_cert->cert_info->key, old_pkey);
			cm_log(1, "Generating PKCSREQ pkiMessage.\n");
			*csr_old = build_pkimessage(old_pkey, new_cert, chain, digest,
						    csr, csr_length,
						    entry->cm_scep_tx,
						    SCEP_MSGTYPE_PKCSREQ,
						    NULL, NULL,
						    nonce, nonce_length,
						    NULL, 0);
			cm_log(1, "Generating GetCertInitial pkiMessage.\n");
			*ias_old = build_pkimessage(old_pkey, new_cert, chain, digest,
						    new_ias, new_ias_length,
						    entry->cm_scep_tx,
						    SCEP_MSGTYPE_GETCERTINITIAL,
						    NULL, NULL,
						    nonce, nonce_length,
						    NULL, 0);
			cm_log(1, "Signing using old key.\n");
			X509_PUBKEY_set(&new_cert->cert_info->key, pubkey);
		} else {
			/* No cert, and the minicert matches the new key. */
			*csr_old = NULL;
			*ias_old = NULL;
		}
	}
	if (new_pkey != NULL) {
		/* Sign the data using the new key and mini certificate, since
		 * any previously-issued certificate won't match. */
		pubkey = X509_PUBKEY_get(new_cert->cert_info->key);
		X509_PUBKEY_set(&new_cert->cert_info->key, new_pkey);
		cm_log(1, "Generating rekeying PKCSREQ pkiMessage.\n");
		*csr_new = build_pkimessage(new_pkey, new_cert, chain, digest,
					    csr, csr_length,
					    entry->cm_scep_tx,
					    SCEP_MSGTYPE_PKCSREQ,
					    NULL, NULL,
					    nonce, nonce_length,
					    NULL, 0);
		cm_log(1, "Generating rekeying GetCertInitial pkiMessage.\n");
		*ias_new = build_pkimessage(new_pkey, new_cert, chain, digest,
					    new_ias, new_ias_length,
					    entry->cm_scep_tx,
					    SCEP_MSGTYPE_GETCERTINITIAL,
					    NULL, NULL,
					    nonce, nonce_length,
					    NULL, 0);
		cm_log(1, "Signing using new key.\n");
		X509_PUBKEY_set(&new_cert->cert_info->key, pubkey);
	} else {
		*csr_new = NULL;
		*ias_new = NULL;
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
	if (old_pkey == NULL) {
		cm_log(1, "Error reading key from file \"%s\".\n",
		       entry->cm_key_storage_location);
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if ((entry->cm_key_next_marker != NULL) &&
	    (strlen(entry->cm_key_next_marker) > 0)) {
		filename = util_build_next_filename(entry->cm_key_storage_location,
						    entry->cm_key_next_marker);
		if (filename == NULL) {
			cm_log(1, "Error opening key file \"%s\" "
			       "for reading: %s.\n",
			       filename, strerror(errno));
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		new_pkey = key_from_file(filename, entry);
		if (new_pkey == NULL) {
			cm_log(1, "Error reading key from file \"%s\".\n",
			       filename);
			free(filename);
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		free(filename);
	} else {
		new_pkey = NULL;
	}
	if ((EVP_PKEY_type(old_pkey->type) != EVP_PKEY_RSA) ||
	    ((new_pkey != NULL) && (EVP_PKEY_type(new_pkey->type) != EVP_PKEY_RSA))) {
		cm_log(1, "Keys aren't RSA.  They won't work with SCEP.\n");
		_exit(CM_SUB_STATUS_ERROR_KEY_TYPE);
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
	fprintf(status, "%s:\n", p ? p : "");

	fclose(status);
	if (new_pkey != NULL) {
		EVP_PKEY_free(new_pkey);
	}
	EVP_PKEY_free(old_pkey);
	_exit(0);
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

/* Check if we need information about the CA in order to generate data. */
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

/* Check if we need a different key type (which is probably RSA). */
static int
cm_scepgen_o_need_different_key_type(struct cm_scepgen_state *state)
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
		state->pvt.need_different_key_type =
			&cm_scepgen_o_need_different_key_type;
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
