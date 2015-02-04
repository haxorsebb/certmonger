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
#include <pk11pub.h>
#include <prerror.h>
#include <secpkcs7.h>
#include <secport.h>

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
#include "submit-u.h"
#include "subproc.h"
#include "util-n.h"

struct cm_scepgen_state {
	struct cm_scepgen_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};

static int
cm_scepgen_sign(CERTCertificate *signer, SECKEYPrivateKey *privkey,
		SECOidTag digalg, SECItem *content, SECItem *result)
{
	CERTCertTrust trust;
	SEC_PKCS7ContentInfo *cinfo;
	SECCertUsage certusage = certUsageSSLClient;
	SECItem *itemp, item;
	unsigned int bits = CERTDB_TRUSTED_CLIENT_CA | CERTDB_TRUSTED_CA;

	memset(&trust, 0, sizeof(trust));
	if (CERT_GetCertTrust(signer, &trust) != SECSuccess) {
		cm_log(1, "Error reading trust on signer: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	trust.sslFlags |= bits;
	trust.emailFlags |= bits;
	trust.objectSigningFlags |= bits;
	if (CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), signer,
				 &trust) != SECSuccess) {
		cm_log(1, "Error tweaking trust on signer: %s; continuing.\n",
		       PR_ErrorToName(PORT_GetError()));
	}

	cinfo = SEC_PKCS7CreateSignedData(signer, certusage,
					  CERT_GetDefaultCertDB(),
					  digalg, NULL, NULL, NULL);
	if (cinfo == NULL) {
		cm_log(1, "Error creating signed data: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if (SEC_PKCS7SetContent(cinfo, (const char *) content->data,
				content->len) != SECSuccess) {
		cm_log(1, "Error setting signed content: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	memset(&item, 0, sizeof(item));
	itemp = SEC_PKCS7EncodeItem(NULL, &item, cinfo, NULL, NULL, NULL);
	if (itemp != &item) {
		cm_log(1, "Error encoding enveloped content: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	memset(result, 0, sizeof(*result));
	*result = item;
	return 0;
}

static int
cm_scepgen_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		  void *userdata)
{
	FILE *status;
	NSSInitContext *ctx;
	CERTCertificate *new_cert, *old_cert;
	unsigned char nonce[16], *new_ias, *old_ias, *csr;
	size_t new_ias_length, old_ias_length, csr_length;
	SECItem content, csr_new, csr_old, ias_new, ias_old;
	struct cm_keyiread_n_ctx_and_keys *keys;
	char *pem;
	const char *p, *es, *reason;
	int ec;

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

	if (PK11_GenerateRandom(nonce, sizeof(nonce)) != SECSuccess) {
		cm_log(1, "Error generating nonce: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}

	keys = cm_keyiread_n_get_keys(entry, 0);
	if (entry->cm_cert != NULL) {
		old_cert = CERT_DecodeCertFromPackage(entry->cm_cert,
						      strlen(entry->cm_cert));
		if (old_cert == NULL) {
			cm_log(1, "Error parsing previously-issued certificate: %s.\n",
			       PR_ErrorToName(PORT_GetError()));
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
	} else {
		old_cert = NULL;
	}
	pem = cm_submit_u_pem_from_base64("CERTIFICATE", 0,
					  entry->cm_minicert);
	if (pem == NULL) {
		cm_log(1, "Out of memory.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	new_cert = CERT_DecodeCertFromPackage(pem, strlen(pem));
	if (new_cert == NULL) {
		cm_log(1, "Error parsing self-signed mini certificate: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		free(pem);
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}

	if (old_cert != NULL) {
		if (cm_pkcs7_envelope_ias(ca->cm_ca_encryption_cert,
					  ca->cm_ca_encryption_issuer_cert,
					  entry->cm_cert,
					  &old_ias, &old_ias_length) != 0) {
			cm_log(1, "Error generating enveloped issuer-and-subject.\n");
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
	memset(&content, 0, sizeof(content));
	memset(&csr_old, 0, sizeof(csr_old));
	memset(&ias_old, 0, sizeof(ias_old));
	if (old_cert != NULL) {
		/* Sign the data using the previously-issued certificate and
		 * the matching key. */
		content.data = csr;
		content.len = csr_length;
		cm_scepgen_sign(old_cert, keys->privkey, cm_prefs_nss_dig_alg(),
				&content, &csr_old);
		content.data = old_ias;
		content.len = old_ias_length;
		cm_scepgen_sign(old_cert, keys->privkey, cm_prefs_nss_dig_alg(),
				&content, &ias_old);
	}
	memset(&csr_new, 0, sizeof(csr_new));
	memset(&ias_new, 0, sizeof(ias_new));
	if (keys->privkey_next != NULL) {
		/* Sign the data using the new key and mini certificate, since
		 * any previously-issued certificate won't match. */
		content.data = csr;
		content.len = csr_length;
		cm_scepgen_sign(new_cert, keys->privkey_next,
				cm_prefs_nss_dig_alg(), &content, &csr_new);
		content.data = new_ias;
		content.len = new_ias_length;
		cm_scepgen_sign(new_cert, keys->privkey_next,
				cm_prefs_nss_dig_alg(), &content, &ias_new);
	} else {
		/* Sign the data using the old key and the mini certificate,
		 * since we may not have a previously-issued certificate (and
		 * if we do, we just did that). */
		content.data = csr;
		content.len = csr_length;
		cm_scepgen_sign(new_cert, keys->privkey, cm_prefs_nss_dig_alg(),
				&content, &csr_new);
		content.data = new_ias;
		content.len = new_ias_length;
		cm_scepgen_sign(new_cert, keys->privkey, cm_prefs_nss_dig_alg(),
				&content, &ias_new);
	}
	p = cm_store_base64_from_bin(NULL, nonce, sizeof(nonce));
	fprintf(status, "%s:", p ? p : "");
	p = csr_old.data ? cm_store_base64_from_bin(NULL, csr_old.data, csr_old.len) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = ias_old.data ? cm_store_base64_from_bin(NULL, ias_old.data, ias_old.len) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = csr_new.data ? cm_store_base64_from_bin(NULL, csr_new.data, csr_new.len) : NULL;
	fprintf(status, "%s:", p ? p : "");
	p = ias_new.data ? cm_store_base64_from_bin(NULL, ias_new.data, ias_new.len) : NULL;
	fprintf(status, "%s\n", p ? p : "");

	fclose(status);
	return 0;
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

/* Save the SCEP to the entry. */
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

/* Check if we need informatoin about the CA in order to generate data. */
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
