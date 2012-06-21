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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
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
#include "submit-u.h"
#include "subproc.h"
#include "tm.h"
#include "util-o.h"

struct cm_submit_state {
	struct cm_submit_state_pvt pvt;
	struct cm_subproc_state *subproc;
};

static int
cm_submit_so_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		  void *userdata)
{
	FILE *keyfp, *pem;
	RSA *rsa;
	EVP_PKEY *pkey;
	X509_REQ *req;
	X509 *cert;
	BIO *bio;
	ASN1_INTEGER *seriali;
	BASIC_CONSTRAINTS *basic;
	unsigned char *seriald, *basicd;
	const unsigned char *serialtmp, *basictmp;
	char *serial, *pin;
	int status, seriall, basicl;
	long error;
	char buf[LINE_MAX];
	time_t lifedelta;
	long life;
	time_t now;
#ifdef HAVE_UUID
	unsigned char uuid[16];
#endif

	util_o_init();
	ERR_load_crypto_strings();
	status = 1;
	cert = NULL;
	if (ca->cm_ca_internal_force_issue_time) {
		now = ca->cm_ca_internal_issue_time;
	} else {
		now = cm_time(NULL);
	}
	keyfp = fopen(entry->cm_key_storage_location, "r");
	if (cm_submit_u_delta_from_string(cm_prefs_validity_period(), now,
					  &lifedelta) == 0) {
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
				rsa = PEM_read_RSAPrivateKey(keyfp, NULL, NULL, pin);
				if (rsa != NULL) {
					EVP_PKEY_assign_RSA(pkey, rsa); /* pkey owns rsa now */
					bio = BIO_new_mem_buf(entry->cm_csr,
							      strlen(entry->cm_csr));
					if (bio != NULL) {
						req = PEM_read_bio_X509_REQ(bio, NULL,
									    NULL, NULL);
						if (req != NULL) {
							cert = X509_REQ_to_X509(req,
										0,
										pkey);
							ASN1_TIME_set(cert->cert_info->validity->notBefore, now);
							ASN1_TIME_set(cert->cert_info->validity->notAfter, now + life);
							X509_set_version(cert, 2);
							/* set the serial number */
							cm_log(3, "Setting certificate serial number \"%s\".\n",
							       ca->cm_ca_internal_serial);
							serial = cm_store_serial_to_der(ca, ca->cm_ca_internal_serial);
							seriall = strlen(serial) / 2;
							seriald = talloc_size(ca, seriall);
							cm_store_hex_to_bin(serial, seriald, seriall);
							serialtmp = seriald;
							seriali = d2i_ASN1_INTEGER(NULL, &serialtmp, seriall);
							X509_set_serialNumber(cert, seriali);
#ifdef HAVE_UUID
							if (cm_prefs_populate_unique_id()) {
								if (cm_submit_uuid_new(uuid) == 0) {
									cert->cert_info->subjectUID = M_ASN1_BIT_STRING_new();
									if (cert->cert_info->subjectUID != NULL) {
										ASN1_BIT_STRING_set(cert->cert_info->subjectUID, uuid, 16);
										cert->cert_info->issuerUID = M_ASN1_BIT_STRING_new();
										if (cert->cert_info->issuerUID != NULL) {
											ASN1_BIT_STRING_set(cert->cert_info->issuerUID, uuid, 16);
										}
									}
								}
							}
#endif
							/* add basic constraints */
							cert->cert_info->extensions = X509_REQ_get_extensions(req);
							basicl = strlen(CM_BASIC_CONSTRAINT_NOT_CA) / 2;
							basicd = talloc_size(ca, basicl);
							cm_store_hex_to_bin(CM_BASIC_CONSTRAINT_NOT_CA, basicd, basicl);
							basictmp = basicd;
							basic = d2i_BASIC_CONSTRAINTS(NULL, &basictmp, basicl);
							X509_add1_ext_i2d(cert, NID_basic_constraints, basic, 1, 0);
							/* finish up */
							X509_sign(cert, pkey,
								  cm_prefs_ossl_hash());
							status = 0;
						} else {
							cm_log(1, "Error reading "
							       "signing request.\n");
						}
						BIO_free(bio);
					} else {
						cm_log(1, "Error parsing signing "
						       "request.\n");
					}
				} else {
					cm_log(1, "Error reading private key from "
					       "'%s': %s.\n",
					       entry->cm_key_storage_location,
					       strerror(errno));
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
		       entry->cm_key_storage_location, strerror(errno));
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

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_submit_so_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Save CA-specific identifier for our submitted request. */
static int
cm_submit_so_save_ca_cookie(struct cm_store_entry *entry,
			    struct cm_submit_state *state)
{
	talloc_free(entry->cm_ca_cookie);
	entry->cm_ca_cookie = talloc_strdup(entry,
					    entry->cm_key_storage_location);
	if (entry->cm_ca_cookie == NULL) {
		cm_log(1, "Out of memory.\n");
		return ENOMEM;
	}
	return 0;
}

/* Check if an attempt to submit has finished. */
static int
cm_submit_so_ready(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Check if the certificate was issued. */
static int
cm_submit_so_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	const char *msg;
	msg = cm_subproc_get_msg(entry, state->subproc, NULL);
	if ((strstr(msg, "-----BEGIN CERTIFICATE-----") != NULL) &&
	    (strstr(msg, "-----END CERTIFICATE-----") != NULL)) {
		talloc_free(entry->cm_cert);
		entry->cm_cert = talloc_strdup(entry, msg);
		return 0;
	}
	return -1;
}

/* Check if the signing request was rejected. */
static int
cm_submit_so_rejected(struct cm_store_entry *entry,
		      struct cm_submit_state *state)
{
	return -1; /* it never gets rejected */
}

/* Check if the CA was unreachable. */
static int
cm_submit_so_unreachable(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Check if the CA was unconfigured. */
static int
cm_submit_so_unconfigured(struct cm_store_entry *entry,
			  struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Done talking to the CA. */
static void
cm_submit_so_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
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
		state->pvt.get_fd = cm_submit_so_get_fd;
		state->pvt.save_ca_cookie = cm_submit_so_save_ca_cookie;
		state->pvt.ready = cm_submit_so_ready;
		state->pvt.issued = cm_submit_so_issued;
		state->pvt.rejected = cm_submit_so_rejected;
		state->pvt.unreachable = cm_submit_so_unreachable;
		state->pvt.unconfigured = cm_submit_so_unconfigured;
		state->pvt.done = cm_submit_so_done;
		state->pvt.delay = -1;
		state->subproc = cm_subproc_start(cm_submit_so_main,
						  ca, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
