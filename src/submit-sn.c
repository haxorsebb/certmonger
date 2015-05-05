/*
 * Copyright (C) 2009,2010,2012,2014,2015 Red Hat, Inc.
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
#include <nssb64.h>
#include <cert.h>
#include <certt.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <cryptohi.h>

#include <krb5.h>

#include <talloc.h>

#include "certext-n.h"
#include "keyiread-n.h"
#include "log.h"
#include "prefs.h"
#include "prefs-n.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"
#include "submit-int.h"
#include "submit-u.h"
#include "subproc.h"

static int
cm_submit_sn_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		  void *userdata)
{
	FILE *status;
	char *b64, *serial;
	const char *p, *q;
	SECStatus error;
	SECItem *esdata = NULL, *ecert = NULL;
	struct cm_keyiread_n_ctx_and_keys *keys;
	SECKEYPrivateKey *privkey;
	CERTCertificate *ucert = NULL;
	CERTCertExtension **extensions;
	CERTCertificateRequest *req = NULL, sreq;
	CERTSignedData *data = NULL, sdata, scert;
	CERTValidity *validity;
	PRTime now, life;
	time_t lifedelta;
	PLArenaPool *arena = NULL;
	SECOidData *sigoid, *extoid, *basicoid;
	int i, serial_length, basic_length;
	unsigned char btrue = 0xff;
	PRBool found_basic;

	/* Start up NSS and open the database. */
	keys = cm_keyiread_n_get_keys(entry, 0);
	if (keys == NULL) {
		cm_log(1, "Unable to locate private key for self-signing.\n");
		_exit(2);
	}
	/* Select the right key pair. */
	if ((entry->cm_key_next_marker != NULL) &&
	    (strlen(entry->cm_key_next_marker) > 0)) {
		privkey = keys->privkey_next;
	} else {
		privkey = keys->privkey;
	}
	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Error opening database '%s'.\n",
		       entry->cm_key_storage_location);
		NSS_Shutdown();
		_exit(ENOMEM);
	}
	/* Decode the CSR into a signeddata structure. */
	p = entry->cm_csr;
	q = NULL;
	if (p != NULL) {
		while (strncmp(p, "-----BEGIN ", 11) == 0) {
			p += strcspn(p, "\r\n");
			p += strspn(p, "\r\n");
		}
		q = strstr(p, "-----END");
	}
	if ((q == NULL) || (*p == '\0')) {
		cm_log(1, "Unable to parse CSR.\n");
		_exit(1);
	}
	esdata = NSSBase64_DecodeBuffer(arena, NULL, p, q - p);
	if (esdata == NULL) {
		cm_log(1, "Unable to decode CSR into buffer.\n");
		_exit(1);
	}
	memset(&sdata, 0, sizeof(sdata));
	if (SEC_ASN1DecodeItem(arena, &sdata,
			       CERT_SignedDataTemplate,
			       esdata) != SECSuccess) {
		cm_log(1, "Unable to decode signed signing request.\n");
		_exit(1);
	} else {
		data = &sdata;
	}
	sigoid = SECOID_FindOIDByTag(cm_prefs_nss_sig_alg(privkey));
	if (sigoid == NULL) {
		cm_log(1, "Internal error resolving signature OID.\n");
		_exit(1);
	}
	extoid = SECOID_FindOIDByTag(SEC_OID_PKCS9_EXTENSION_REQUEST);
	if (extoid == NULL) {
		cm_log(1, "Internal error resolving extension OID.\n");
		_exit(1);
	}

	/* Decode the CSR from the signeddata structure into a usable request.
	 */
	memset(&sreq, 0, sizeof(sreq));
	sreq.arena = arena;
	if (SEC_ASN1DecodeItem(arena, &sreq, CERT_CertificateRequestTemplate,
			       &data->data) != SECSuccess) {
		cm_log(1, "Unable to decode signing request.\n");
		_exit(1);
	} else {
		req = &sreq;
	}
	/* Build a certificate using the contents of the signing request. */
	if (ca->cm_ca_internal_force_issue_time) {
		now = ca->cm_ca_internal_issue_time;
		now *= 1000000;
	} else {
		now = PR_Now();
	}
	if (cm_submit_u_delta_from_string(cm_prefs_selfsign_validity_period(),
					  now / 1000000,
					  &lifedelta) == 0) {
		life = lifedelta;
	} else {
		if (cm_submit_u_delta_from_string(CM_DEFAULT_CERT_LIFETIME,
						  now / 1000000,
						  &lifedelta) == 0) {
			life = lifedelta;
		} else {
			life = 365 * 24 * 60 * 60;
		}
	}
	life *= 1000000L;
	validity = CERT_CreateValidity(now, now + life);
	if (validity == NULL) {
		cm_log(1, "Unable to create validity structure.\n");
		_exit(1);
	} else {
		ucert = CERT_CreateCertificate(0, &req->subject, validity, req);
		CERT_DestroyValidity(validity);
		if (ucert == NULL) {
			cm_log(1, "Unable to create certificate structure.\n");
			_exit(1);
		}
	}
	/* Populate the certificate's fields. */
	SEC_ASN1EncodeInteger(arena, &ucert->version, 2);
	serial = ca->cm_ca_internal_serial;
	if (serial != NULL) {
		cm_log(3, "Setting certificate serial number \"%s\".\n",
		       serial);
		serial_length = strlen(serial) / 2;
		ucert->serialNumber.data = PORT_ArenaZAlloc(arena,
							    serial_length);
		serial_length = cm_store_hex_to_bin(serial,
						    ucert->serialNumber.data,
						    serial_length);
		ucert->serialNumber.len = serial_length;
	} else {
		cm_log(1, "Unable to set certificate serial number.\n");
		_exit(1);
	}
	if (SECOID_SetAlgorithmID(arena, &ucert->signature,
				  sigoid->offset, NULL) != SECSuccess) {
		cm_log(1, "Unable to set signature algorithm ID.\n");
		_exit(1);
	}
	ucert->issuer = req->subject;
	ucert->subject = req->subject;
	ucert->subjectPublicKeyInfo = req->subjectPublicKeyInfo;
#ifdef HAVE_UUID
	if (cm_prefs_populate_unique_id()) {
		ucert->subjectID.data = PORT_ArenaZAlloc(arena, 16);
		if (ucert->subjectID.data != NULL) {
			if (cm_submit_uuid_new(ucert->subjectID.data) == 0) {
				ucert->subjectID.len = 16 * 8;
			} else {
				ucert->subjectID.data = NULL;
			}
		} else {
			ucert->subjectID.len = 0;
		}
		ucert->issuerID = ucert->subjectID;
	}
#endif
	/* Try to copy the extensions from the request into the certificate. */
	for (i = 0;
	     (req->attributes != NULL) && (req->attributes[i] != NULL);
	     i++) {
		if (SECITEM_ItemsAreEqual(&req->attributes[i]->attrType,
					  &extoid->oid)) {
			/* Found the requested-extensions attribute. */
			break;
		}
	}
	/* Add the requested extensions. */
	if ((req->attributes != NULL) && (req->attributes[i] != NULL)) {
		if (SEC_ASN1DecodeItem(arena, &ucert->extensions,
				       CERT_SequenceOfCertExtensionTemplate,
				       req->attributes[i]->attrValue[0]) != SECSuccess) {
			cm_log(1, "Error decoding requested extensions.\n");
		}
	}
	/* Figure out the OID for basicConstraints. */
	basicoid = SECOID_FindOIDByTag(SEC_OID_X509_BASIC_CONSTRAINTS);
	if (basicoid == NULL) {
		cm_log(1, "Unable to get basic constraints OID.\n");
		_exit(1);
	}
	/* Count the number of extensions and whether or not we requested a
	 * basicConstraints extension. */
	found_basic = PR_FALSE;
	if (ucert->extensions == NULL) {
		i = 0;
	} else {
		for (i = 0; ucert->extensions[i] != NULL; i++) {
			if (SECITEM_ItemsAreEqual(&ucert->extensions[i]->id,
						  &basicoid->oid)) {
				found_basic = PR_TRUE;
			}
		}
	}
	/* Allocate space for one more extension. */
	extensions = PORT_ArenaZAlloc(arena, (i + 2) * sizeof(extensions[0]));
	if (extensions != NULL) {
		memcpy(extensions, ucert->extensions,
		       i * sizeof(extensions[0]));
		if (found_basic) {
			extensions[i] = NULL;
		} else {
			extensions[i] = PORT_ArenaZAlloc(arena, sizeof(*(extensions[i])));
		}
		extensions[i + 1] = NULL;
		ucert->extensions = extensions;
	}
	/* Add basic constraints. */
	if ((extensions != NULL) && (extensions[i] != NULL) && !found_basic) {
		extensions[i]->id = basicoid->oid;
		extensions[i]->critical.data = &btrue;
		extensions[i]->critical.len = 1;
		basic_length = strlen(CM_BASIC_CONSTRAINT_NOT_CA) / 2;
		extensions[i]->value.data = PORT_ArenaZAlloc(arena, basic_length);
		extensions[i]->value.len = basic_length;
		basic_length = cm_store_hex_to_bin(CM_BASIC_CONSTRAINT_NOT_CA,
						   extensions[i]->value.data,
						   extensions[i]->value.len);
		extensions[i]->value.len = basic_length;
	}
	/* Encode the certificate into a tbsCertificate. */
	ecert = SEC_ASN1EncodeItem(arena, NULL, ucert,
				   CERT_CertificateTemplate);
	if (ecert == NULL) {
		cm_log(1, "Error encoding certificate structure.\n");
		_exit(1);
	}
	/* Create a signature. */
	memset(&scert, 0, sizeof(scert));
	scert.data = *ecert;
	if (SECOID_SetAlgorithmID(arena, &scert.signatureAlgorithm,
				  sigoid->offset, NULL) != SECSuccess) {
		cm_log(1, "Unable to set signature algorithm ID.\n");
		_exit(1);
	}
	if (SEC_SignData(&scert.signature, ecert->data, ecert->len,
			 privkey, sigoid->offset) != SECSuccess) {
		cm_log(1, "Unable to generate signature.\n");
		_exit(1);
	}
	/* Of course, the signature is a bitstring, so its length is specified
	 * in bits, but the item that stores it starts with the item length in
	 * bytes. */
	scert.signature.len *= 8;
	/* Encode the signed certificate. */
	ecert = SEC_ASN1EncodeItem(arena, NULL, &scert,
				   CERT_SignedDataTemplate);
	if (ecert == NULL) {
		cm_log(1, "Unable to encode signed certificate.\n");
		_exit(1);
	}
	/* Encode the certificate as base64. */
	b64 = NSSBase64_EncodeItem(arena, NULL, -1, ecert);
	if (b64 == NULL) {
		cm_log(1, "Unable to b64-encode certificate.\n");
		_exit(1);
	}
	/* Send the certificate to our parent. */
	status = fdopen(fd, "w");
	if (status == NULL) {
		cm_log(1, "Internal error.\n");
		_exit(errno);
	}
	fprintf(status, "-----BEGIN CERTIFICATE-----\n");
	p = b64;
	while (*p != '\0') {
		q = p + strcspn(p, "\r\n");
		fprintf(status, "%.*s\n", (int) (q - p), p);
		p = q + strspn(q, "\r\n");
	}
	fprintf(status, "-----END CERTIFICATE-----\n");
	fclose(status);

	if (keys->pubkey != NULL) {
		SECKEY_DestroyPublicKey(keys->pubkey);
	}
	if (keys->privkey != NULL) {
		SECKEY_DestroyPrivateKey(keys->privkey);
	}
	if (keys->pubkey_next != NULL) {
		SECKEY_DestroyPublicKey(keys->pubkey_next);
	}
	if (keys->privkey_next != NULL) {
		SECKEY_DestroyPrivateKey(keys->privkey_next);
	}
	PORT_FreeArena(arena, PR_TRUE);
	error = NSS_ShutdownContext(keys->ctx);
	PORT_FreeArena(keys->arena, PR_TRUE);
	if (error != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}

	return 0;
}

/* Save CA-specific identifier for our submitted request. */
static int
cm_submit_sn_save_ca_cookie(struct cm_submit_state *state)
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

/* Check if an attempt to submit has completed. */
static int
cm_submit_sn_ready(struct cm_submit_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Check if the certificate was issued. */
static int
cm_submit_sn_issued(struct cm_submit_state *state)
{
	const char *msg;
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
		return -1;
	}
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
cm_submit_sn_rejected(struct cm_submit_state *state)
{
	return -1; /* it never gets rejected */
}

/* Check if we need SCEP messages. */
static int
cm_submit_sn_need_scep_messages(struct cm_submit_state *state)
{
	return -1; /* nope */
}

/* Check if we need to use a different key. */
static int
cm_submit_sn_need_rekey(struct cm_submit_state *state)
{
	return -1; /* nope */
}

/* Check if the CA was unreachable. */
static int
cm_submit_sn_unreachable(struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Check if the CA was unconfigured. */
static int
cm_submit_sn_unconfigured(struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Check if the CA is something we can ask for certificates. */
static int
cm_submit_sn_unsupported(struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Done talking to the CA. */
static void
cm_submit_sn_done(struct cm_submit_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_sn_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	struct cm_submit_state *state;

	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		cm_log(1, "Wrong submission method: only keys stored "
		       "in an NSS database can be used.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->save_ca_cookie = cm_submit_sn_save_ca_cookie;
		state->ready = cm_submit_sn_ready;
		state->issued = cm_submit_sn_issued;
		state->rejected = cm_submit_sn_rejected;
		state->need_scep_messages = cm_submit_sn_need_scep_messages;
		state->need_rekey = cm_submit_sn_need_rekey;
		state->unreachable = cm_submit_sn_unreachable;
		state->unconfigured = cm_submit_sn_unconfigured;
		state->unsupported = cm_submit_sn_unsupported;
		state->done = cm_submit_sn_done;
		state->delay = -1;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_submit_sn_main, state,
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
