/*
 * Copyright (C) 2009,2010,2011,2012,2014.2015 Red Hat, Inc.
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
#include "submit-e.h"
#include "submit-int.h"
#include "submit-o.h"
#include "submit-u.h"
#include "subproc.h"
#include "util-o.h"

int
cm_submit_o_sign(void *parent, char *csr,
		 X509 *signer, EVP_PKEY *signer_key,
		 const char *hexserial, time_t now, long life,
		 X509 **cert)
{
	X509_REQ *req;
	BIO *bio;
	ASN1_INTEGER *seriali;
	BASIC_CONSTRAINTS *basic;
	ASN1_OCTET_STRING *skid;
	AUTHORITY_KEYID akid;
	unsigned char *seriald, *basicd, md[CM_DIGEST_MAX];
	const unsigned char *serialtmp, *basictmp;
	char *serial;
	int status = CM_SUBMIT_STATUS_WAIT, seriall, basicl, crit, i;
	unsigned int mdlen;
#ifdef HAVE_UUID
	unsigned char uuid[16];
#endif

	bio = BIO_new_mem_buf(csr, -1);
	if (bio != NULL) {
		req = PEM_read_bio_X509_REQ(bio, NULL,
					    NULL, NULL);
		if (req != NULL) {
			*cert = X509_new();
			if (*cert != NULL) {
				X509_set_subject_name(*cert, X509_REQ_get_subject_name(req));
				if (signer != NULL) {
					X509_set_issuer_name(*cert, signer->cert_info->subject);
				} else {
					X509_set_issuer_name(*cert, X509_REQ_get_subject_name(req));
				}
				X509_set_pubkey(*cert, X509_PUBKEY_get(req->req_info->pubkey));
				ASN1_TIME_set((*cert)->cert_info->validity->notBefore, now);
				if ((life == 0) && (signer != NULL)) {
					(*cert)->cert_info->validity->notAfter =
						M_ASN1_TIME_dup(signer->cert_info->validity->notAfter);
				} else {
					ASN1_TIME_set((*cert)->cert_info->validity->notAfter, now + life);
				}
				X509_set_version(*cert, 2);
				/* set the serial number */
				cm_log(3, "Setting certificate serial number \"%s\".\n",
				       hexserial);
				serial = cm_store_serial_to_der(parent, hexserial);
				seriall = strlen(serial) / 2;
				seriald = talloc_size(parent, seriall);
				seriall = cm_store_hex_to_bin(serial, seriald, seriall);
				serialtmp = seriald;
				seriali = d2i_ASN1_INTEGER(NULL, &serialtmp, seriall);
				X509_set_serialNumber(*cert, seriali);
#ifdef HAVE_UUID
				if (cm_prefs_populate_unique_id()) {
					if (cm_submit_uuid_new(uuid) == 0) {
						(*cert)->cert_info->subjectUID = M_ASN1_BIT_STRING_new();
						if ((*cert)->cert_info->subjectUID != NULL) {
							ASN1_BIT_STRING_set((*cert)->cert_info->subjectUID, uuid, 16);
						}
						if (signer != NULL) {
							if (signer->cert_info->subjectUID != NULL) {
								(*cert)->cert_info->issuerUID = M_ASN1_BIT_STRING_dup(signer->cert_info->subjectUID);
							}
						} else {
							(*cert)->cert_info->issuerUID = M_ASN1_BIT_STRING_new();
							if ((*cert)->cert_info->issuerUID != NULL) {
								ASN1_BIT_STRING_set((*cert)->cert_info->issuerUID, uuid, 16);
							}
						}
					}
				}
#endif
				/* add basic constraints if needed */
				(*cert)->cert_info->extensions = X509_REQ_get_extensions(req);
				i = X509_get_ext_by_NID(*cert, NID_basic_constraints, -1);
				if (i == -1) {
					basicl = strlen(CM_BASIC_CONSTRAINT_NOT_CA) / 2;
					basicd = talloc_size(parent, basicl);
					basicl = cm_store_hex_to_bin(CM_BASIC_CONSTRAINT_NOT_CA,
								     basicd, basicl);
					basictmp = basicd;
					basic = d2i_BASIC_CONSTRAINTS(NULL, &basictmp, basicl);
					X509_add1_ext_i2d(*cert, NID_basic_constraints, basic, 1, 0);
				}
				/* copy the signer's subject key id to our authority key id */
				if (signer != NULL) {
					skid = X509_get_ext_d2i(signer, NID_subject_key_identifier, &crit, NULL);
					memset(&akid, 0, sizeof(akid));
					akid.keyid = skid;
					X509_add1_ext_i2d(*cert, NID_authority_key_identifier, &akid, crit, X509V3_ADD_REPLACE);
					/* make sure we have a subject key id */
					i = X509_get_ext_by_NID(*cert, NID_subject_key_identifier, -1);
					if (i == -1) {
						if (X509_pubkey_digest(*cert, EVP_sha1(), md, &mdlen)) {
							skid = M_ASN1_OCTET_STRING_new();
							M_ASN1_OCTET_STRING_set(skid, md, mdlen);
							X509_add1_ext_i2d(*cert, NID_subject_key_identifier, skid, 0, 0);
						}
					}
				}
				/* finish up */
				if (signer_key != NULL) {
					X509_sign(*cert, signer_key, cm_prefs_ossl_hash());
					status = CM_SUBMIT_STATUS_ISSUED;
				} else {
					status = CM_SUBMIT_STATUS_UNREACHABLE;
				}
			} else {
				cm_log(1, "Error building "
				       "template certificate.\n");
				status = CM_SUBMIT_STATUS_REJECTED;
			}
		} else {
			cm_log(1, "Error reading "
			       "signing request.\n");
		}
		BIO_free(bio);
	} else {
		cm_log(1, "Error parsing signing "
		       "request.\n");
	}
	return status;
}

void
cm_submit_o_decrypt_envelope(const unsigned char *envelope,
			     size_t length,
			     void *decrypt_userdata,
			     unsigned char **payload,
			     size_t *payload_length)
{
	struct cm_pin_cb_data cb_data;
	struct cm_submit_decrypt_envelope_args *args = decrypt_userdata;
	FILE *keyfp, *keyfp_next;
	BIO *out = NULL;
	EVP_PKEY *pkey = NULL, *pkey_next = NULL;
	PKCS7 *p7;
	char buf[LINE_MAX], *pin, *filename, *p;
	const unsigned char *u;
	long error, l;
	int result = 0;

	if ((args->entry->cm_key_next_marker != NULL) &&
	    (strlen(args->entry->cm_key_next_marker) > 0)) {
		filename = util_build_next_filename(args->entry->cm_key_storage_location,
						    args->entry->cm_key_next_marker);
		keyfp_next = fopen(filename, "r");
		free(filename);
	} else {
		keyfp_next = NULL;
	}
	keyfp = fopen(args->entry->cm_key_storage_location, "r");

	util_o_init();
	ERR_load_crypto_strings();
	if (cm_pin_read_for_key(args->entry, &pin) != 0) {
		cm_log(1, "Error reading key encryption PIN.\n");
		goto done;
	}
	memset(&cb_data, 0, sizeof(cb_data));
	cb_data.entry = args->entry;
	cb_data.n_attempts = 0;
	if (keyfp != NULL) {
		pkey = PEM_read_PrivateKey(keyfp, NULL,
					   cm_pin_read_for_key_ossl_cb, &cb_data);
	}
	if (keyfp_next != NULL) {
		pkey_next = PEM_read_PrivateKey(keyfp_next, NULL,
						cm_pin_read_for_key_ossl_cb, &cb_data);
	}
	if ((pkey == NULL) && (pkey_next == NULL)) {
		error = errno;
		cm_log(1, "Error reading private key '%s': %s.\n",
		       args->entry->cm_key_storage_location, strerror(error));
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		goto done;
	}
	u = envelope;
	p7 = d2i_PKCS7(NULL, &u, length);
	if ((p7 == NULL) || !PKCS7_type_is_enveloped(p7)) {
		goto done;
	}
	out = BIO_new(BIO_s_mem());
	if (out == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	if (pkey_next != NULL) {
		result = PKCS7_decrypt(p7, pkey_next, NULL, out, 0);
		if (result == 1) {
			goto done;
		}
	}
	result = PKCS7_decrypt(p7, pkey, NULL, out, 0);
done:
	if (result == 1) {
		p = NULL;
		l = BIO_get_mem_data(out, &p);
		cm_log(1, "Succeeded in decrypting enveloped data.\n");
		if (p != NULL) {
			*payload = malloc(l + 1);
			if (*payload != NULL) {
				memcpy(*payload, p, l + 1);
				(*payload)[l] = '\0';
				*payload_length = l;
			}
		}
	}
	if (keyfp != NULL) {
		fclose(keyfp);
	}
	if (keyfp_next != NULL) {
		fclose(keyfp_next);
	}
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	if (pkey_next != NULL) {
		EVP_PKEY_free(pkey_next);
	}
	if (out != NULL) {
		BIO_free(out);
	}
}
