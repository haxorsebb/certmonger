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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <prerror.h>
#include <nss.h>
#include <nssb64.h>
#include <secder.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <keythi.h>
#include <cryptohi.h>
#include <cert.h>
#include <certt.h>

#include <krb5.h>

#include <talloc.h>

#include "certext.h"
#include "csrgen.h"
#include "csrgen-int.h"
#include "keygen.h"
#include "keyiread-n.h"
#include "log.h"
#include "pin.h"
#include "prefs-n.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"

struct cm_csrgen_state {
	struct cm_csrgen_state_pvt pvt;
	struct cm_subproc_state *subproc;
};

/* Ad-hoc. */
static const SEC_ASN1Template
cm_csrgen_n_cert_tmpattr_template[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof(CERTAttribute),
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(CERTAttribute, attrType),
	.sub = NULL,
	.size = sizeof(SECItem),
	},
	{
	.kind = SEC_ASN1_SET_OF,
	.offset = offsetof(CERTAttribute, attrValue),
	.sub = &SEC_OctetStringTemplate,
	.size = 0,
	},
	{0, 0, NULL, 0},
};
static const SEC_ASN1Template
cm_csrgen_n_set_of_cert_tmpattr_template[] = {
	{
	.kind = SEC_ASN1_SET_OF,
	.offset = 0,
	.sub = cm_csrgen_n_cert_tmpattr_template,
	.size = 0,
	},
};
static const SEC_ASN1Template
cm_csrgen_n_cert_pkac_template[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof(CERTPublicKeyAndChallenge),
	},
	{
	.kind = SEC_ASN1_ANY,
	.offset = offsetof(CERTPublicKeyAndChallenge, spki),
	.sub = NULL,
	.size = sizeof(SECItem),
	},
	{
	.kind = SEC_ASN1_IA5_STRING,
	.offset = offsetof(CERTPublicKeyAndChallenge, challenge),
	.sub = &SEC_IA5StringTemplate,
	.size = sizeof(SECItem),
	},
	{0, 0, NULL, 0},
};
static int
compare_items(const void *a, const void *b)
{
	return SECITEM_CompareItem(a, b);
}
static SECItem *
cm_csrgen_n_attributes(struct cm_store_entry *entry, PLArenaPool *arena)
{
	SECItem encoded_exts, *exts[2];
	unsigned char *extensions;
	size_t extensions_length;
	CERTAttribute attr[3];
	SECOidData *oid;
	SECItem *item, friendly, *friendlies[2], encoded, encattr[3], plain;
	SECItem *encattrs[4], **encattrs_ptr, password, *passwords[2];
	int i, n_attrs;

	i = 0;
	/* Build an attribute to hold the friendly name. */
	oid = SECOID_FindOIDByTag(SEC_OID_PKCS9_FRIENDLY_NAME);
	if (oid != NULL) {
		plain.data = (unsigned char *) entry->cm_cert_nickname;
		if (plain.data != NULL) {
			plain.len = strlen(entry->cm_cert_nickname);
			if (SEC_ASN1EncodeItem(arena, &friendly, &plain,
					       SEC_PrintableStringTemplate) == &friendly) {
				friendlies[0] = &friendly;
				friendlies[1] = NULL;
				attr[i].attrType = oid->oid;
				attr[i].attrValue = friendlies;
				i++;
			}
		}
	}
	/* Build the extension list. */
	extensions = NULL;
	cm_certext_build_csr_extensions(entry, &extensions, &extensions_length);
	/* Build an attribute to hold the extensions. */
	if ((extensions != NULL) && (extensions_length > 0)) {
		encoded_exts.data = extensions;
		encoded_exts.len = extensions_length;
		exts[0] = &encoded_exts;
		exts[1] = NULL;
		oid = SECOID_FindOIDByTag(SEC_OID_PKCS9_EXTENSION_REQUEST);
		if (oid != NULL) {
			attr[i].attrType = oid->oid;
			attr[i].attrValue = exts;
			i++;
		}
	}
	/* Build an attribute to hold the challenge password. */
	oid = SECOID_FindOIDByTag(SEC_OID_PKCS9_CHALLENGE_PASSWORD);
	if (oid != NULL) {
		plain.data = (unsigned char *) entry->cm_challenge_password;
		if (plain.data != NULL) {
			plain.len = strlen(entry->cm_challenge_password);
			if (SEC_ASN1EncodeItem(arena, &password, &plain,
					       SEC_PrintableStringTemplate) == &password) {
				passwords[0] = &password;
				passwords[1] = NULL;
				attr[i].attrType = oid->oid;
				attr[i].attrValue = passwords;
				i++;
			} else
			if (SEC_ASN1EncodeItem(arena, &password, &plain,
					       SEC_UTF8StringTemplate) == &password) {
				passwords[0] = &password;
				passwords[1] = NULL;
				attr[i].attrType = oid->oid;
				attr[i].attrValue = passwords;
				i++;
			}
		}
	}
	n_attrs = i;
	for (i = 0; i < n_attrs; i++) {
		memset(&encattr[i], 0, sizeof(encattr[i]));
		if (SEC_ASN1EncodeItem(arena, &encattr[i], &attr[i],
				       cm_csrgen_n_cert_tmpattr_template) != &encattr[i]) {
			break;
		}
	}
	if (i == n_attrs) {
		qsort(&encattr[0], n_attrs, sizeof(encattr[0]), compare_items);
		for (i = 0; i < n_attrs; i++) {
			encattrs[i] = &encattr[i];
		}
		encattrs[i] = NULL;
		encattrs_ptr = &encattrs[0];
		if (SEC_ASN1EncodeItem(arena, &encoded, &encattrs_ptr,
				       SEC_SetOfAnyTemplate) == &encoded) {
			item = SECITEM_ArenaDupItem(arena, &encoded);
		} else {
			cm_log(1, "Error encoding set of request attributes.\n");
			item = NULL;
		}
	} else {
		item = NULL;
	}
	return item;
}

static int
cm_csrgen_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	FILE *status;
	SECStatus error;
	struct cm_keyiread_n_ctx_and_key *privkey;
	SECKEYPublicKey *pubkey;
	CERTSubjectPublicKeyInfo *spki;
	CERTPublicKeyAndChallenge pkac;
	CERTCertificateRequest *req;
	CERTSignedData sreq, spkac;
	CERTName *name;
	PLArenaPool *arena;
	SECItem ereq, esreq, epkac, espkac, *attrs;
	PRErrorCode ec;
	char *b64, *b642, *p, *q;
	SECOidData *sigoid;

	/* Allocate an arena pool and a place to write status updates. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Out of memory?.\n");
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	status = fdopen(fd, "w");
	if (status == NULL) {
		cm_log(1, "Internal error: %s.\n", strerror(errno));
		_exit(CM_STATUS_ERROR_INTERNAL);
	}

	/* Start up NSS and find the key pair. */
	privkey = cm_keyiread_n_get_private_key(entry, 0);
	if (privkey == NULL) {
		cm_log(1, "Error finding key pair for %s('%s').\n",
		       entry->cm_busname, entry->cm_nickname);
		PORT_FreeArena(arena, PR_TRUE);
		_exit(CM_STATUS_ERROR_NO_TOKEN);
	}
	/* Select a subject name. */
	if ((entry->cm_template_subject != NULL) &&
	    (strlen(entry->cm_template_subject) != 0)) {
		name = CERT_AsciiToName(entry->cm_template_subject);
	} else {
		name = CERT_AsciiToName("CN=" CM_DEFAULT_CERT_SUBJECT_CN);
	}
	/* Find the public key. */
	pubkey = SECKEY_ConvertToPublicKey(privkey->key);
	if (pubkey == NULL) {
		ec = PR_GetError();
		if (ec == 0) {
			cm_log(1, "Error retrieving public key.\n");
		} else {
			cm_log(1, "Error retrieving public key: %s.\n",
			       PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT));
		}
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Generate a subjectPublicKeyInfo. */
	spki = SECKEY_CreateSubjectPublicKeyInfo(pubkey);
	if (spki == NULL) {
		ec = PR_GetError();
		if (ec == 0) {
			cm_log(1, "Error building spki value.\n");
		} else {
			cm_log(1, "Error building spki value: %s.\n",
			       PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT));
		}
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Build the request. */
	req = CERT_CreateCertificateRequest(name, spki, NULL);
	if (req == NULL) {
		ec = PR_GetError();
		if (ec == 0) {
			cm_log(1, "Error building certificate request.\n");
		} else {
			cm_log(1, "Error building certificate request: %s.\n",
			       PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT));
		}
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Generate requested values for various extensions and a friendly
	 * name. */
	attrs = cm_csrgen_n_attributes(entry, arena);
	if ((attrs == NULL) ||
	    (SEC_ASN1DecodeItem(arena, &req->attributes,
				cm_csrgen_n_set_of_cert_tmpattr_template,
				attrs) != SECSuccess)) {
		req->attributes = NULL;
	}
	/* req->arena = arena;
	req->subjectPublicKeyInfo = *spki; redundant? */
	if (SEC_ASN1EncodeInteger(arena, &req->version,
				  SEC_CERTIFICATE_REQUEST_VERSION) !=
	    &req->version) {
		cm_log(1, "Error encoding certificate request version.\n");
	}
	/* Encode the request. */
	if (SEC_ASN1EncodeItem(arena, &ereq, req,
			       CERT_CertificateRequestTemplate) !=
	    &ereq) {
		cm_log(1, "Error encoding certificate request.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Build the PublicKeyAndChallenge. */
	memset(&pkac, 0, sizeof(pkac));
	if (SEC_ASN1EncodeItem(arena, &pkac.spki, spki,
			       CERT_SubjectPublicKeyInfoTemplate) !=
	    &pkac.spki) {
		cm_log(1, "Error encoding subject public key info.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	pkac.challenge.data = (unsigned char *) entry->cm_challenge_password;
	pkac.challenge.len = entry->cm_challenge_password ?
			     strlen(entry->cm_challenge_password) : 0;
	/* Encode the PublicKeyAndChallenge. */
	if (SEC_ASN1EncodeItem(arena, &epkac, &pkac,
			       cm_csrgen_n_cert_pkac_template) !=
	    &epkac) {
		cm_log(1, "Error encoding public key and challenge.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Sign the request using the private key. */
	sigoid = SECOID_FindOIDByTag(cm_prefs_nss_sig_alg(pubkey));
	memset(&sreq, 0, sizeof(sreq));
	sreq.data = ereq;
	if (SECOID_SetAlgorithmID(arena, &sreq.signatureAlgorithm,
				  sigoid->offset, NULL) != SECSuccess) {
		cm_log(1, "Error setting up algorithm ID for signing the "
		       "certificate request.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	if (SEC_SignData(&sreq.signature, sreq.data.data, sreq.data.len,
			 privkey->key, sigoid->offset) != SECSuccess) {
		cm_log(1, "Error signing certificate request with the client's "
		       "key.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Sign the PublicKeyAndChallenge using the private key. */
	memset(&spkac, 0, sizeof(spkac));
	spkac.data = epkac;
	if (SECOID_SetAlgorithmID(arena, &spkac.signatureAlgorithm,
				  sigoid->offset, NULL) != SECSuccess) {
		cm_log(1, "Error setting up algorithm ID for signing the "
		       "certificate request.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	if (SEC_SignData(&spkac.signature, spkac.data.data, spkac.data.len,
			 privkey->key, sigoid->offset) != SECSuccess) {
		cm_log(1, "Error signing public-key-and-challenge with "
		       "the client's key.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Encode the signed request. */
	sreq.signature.len *= 8;
	if (SEC_ASN1EncodeItem(arena, &esreq, &sreq,
			       CERT_SignedDataTemplate) !=
	    &esreq) {
		cm_log(1, "Error encoding signed certificate request.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Encode the signed public key and challenge. */
	spkac.signature.len *= 8;
	if (SEC_ASN1EncodeItem(arena, &espkac, &spkac,
			       CERT_SignedDataTemplate) !=
	    &espkac) {
		cm_log(1, "Error encoding signed public key and challenge.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Encode the request into base-64 and pass it to our caller. */
	b64 = NSSBase64_EncodeItem(arena, NULL, -1, &esreq);
	b642 = NSSBase64_EncodeItem(arena, NULL, -1, &espkac);
	if ((b64 != NULL) && (b642 != NULL)) {
		fprintf(status, "-----BEGIN NEW CERTIFICATE REQUEST-----\n");
		p = b64;
		while (*p != '\0') {
			q = p + strcspn(p, "\r\n");
			fprintf(status, "%.*s\n", (int) (q - p), p);
			p = q + strspn(q, "\r\n");
		}
		fprintf(status, "-----END NEW CERTIFICATE REQUEST-----\n");
		p = b642;
		while (*p != '\0') {
			q = p + strcspn(p, "\r\n");
			fprintf(status, "%.*s", (int) (q - p), p);
			p = q + strspn(q, "\r\n");
		}
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKey(privkey->key);
		PORT_FreeArena(arena, PR_TRUE);
		error = NSS_ShutdownContext(privkey->ctx);
		PORT_FreeArena(privkey->arena, PR_TRUE);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(0);
	}
	/* Clean up. */
	SECKEY_DestroyPublicKey(pubkey);
	SECKEY_DestroyPrivateKey(privkey->key);
	PORT_FreeArena(arena, PR_TRUE);
	error = NSS_ShutdownContext(privkey->ctx);
	PORT_FreeArena(privkey->arena, PR_TRUE);
	if (error != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	fclose(status);
	_exit(CM_STATUS_ERROR_INTERNAL);
}

/* Check if a CSR is ready. */
static int
cm_csrgen_n_ready(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_csrgen_n_get_fd(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Save the CSR to the entry. */
static int
cm_csrgen_n_save_csr(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state)
{
	int status;
	char *p, *q;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
		return -1;
	}
	talloc_free(entry->cm_csr);
	entry->cm_csr = talloc_strdup(entry,
				      cm_subproc_get_msg(entry,
							 state->subproc,
							 NULL));
	if (entry->cm_csr == NULL) {
		return ENOMEM;
	}
	p = strstr(entry->cm_csr, "-----END");
	if (p != NULL) {
		p = strstr(p, "REQUEST-----");
		if (p != NULL) {
			p += strcspn(p, "\r\n");
			q = p + strspn(p, "\r\n");
			entry->cm_spkac = talloc_strdup(entry, q);
			if (entry->cm_spkac == NULL) {
				return ENOMEM;
			}
			*q = '\0';
		}
	}
	return 0;
}

/* Check if we need a PIN (or a new PIN) to access the key information. */
static int
cm_csrgen_n_need_pin(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to access the key information. */
static int
cm_csrgen_n_need_token(struct cm_store_entry *entry,
		       struct cm_csrgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Clean up after CSR generation. */
static void
cm_csrgen_n_done(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}

/* Start CSR generation using template information in the entry. */
struct cm_csrgen_state *
cm_csrgen_n_start(struct cm_store_entry *entry)
{
	struct cm_csrgen_state *state;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = &cm_csrgen_n_ready;
		state->pvt.get_fd = &cm_csrgen_n_get_fd;
		state->pvt.save_csr = &cm_csrgen_n_save_csr;
		state->pvt.need_pin = &cm_csrgen_n_need_pin;
		state->pvt.need_token = &cm_csrgen_n_need_token;
		state->pvt.done = &cm_csrgen_n_done;
		state->subproc = cm_subproc_start(cm_csrgen_n_main,
						  NULL, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
