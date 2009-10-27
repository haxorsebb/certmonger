/*
 * Copyright (C) 2009 Red Hat, Inc.
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
#include <nssb64.h>
#include <cert.h>
#include <certt.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <cryptohi.h>

#include <talloc.h>

#include "log.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"
#include "submit-int.h"

struct cm_submit_state {
	struct cm_submit_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, count, status;
};

static void
cm_submit_sn_main(int fd, struct cm_store_entry *entry)
{
	FILE *status;
	char *b64;
	const char *keyname, *token, *p, *q;
	SECStatus error;
	SECItem *esdata = NULL, *ecert = NULL, *item;
	SECKEYPrivateKey *privkey;
	SECKEYPrivateKeyList *privkeys;
	SECKEYPrivateKeyListNode *node;
	CERTCertificate *ucert = NULL;
	CERTCertificateRequest *req = NULL, sreq;
	CERTSignedData *data = NULL, sdata, scert;
	CERTValidity *validity;
	PRTime now, life;
	PLArenaPool *arena = NULL;
	SECOidData *sigoid;
	enum cm_key_algorithm cm_key_algorithm;
	CK_MECHANISM_TYPE mech;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	PK11SlotInfo *slot;

	/* Start up NSS and open the database. */
	error = NSS_InitReadWrite(entry->cm_key_storage_location);
	if (error != SECSuccess) {
		cm_log(1, "Error opening database '%s'.\n",
		       entry->cm_key_storage_location);
		_exit(1);
	}
	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Error opening database '%s'.\n",
		       entry->cm_key_storage_location);
		NSS_Shutdown();
		_exit(ENOMEM);
	}
	/* Handle defaults. */
	if (entry->cm_key_type_default) {
		cm_key_algorithm = CM_DEFAULT_PUBKEY_TYPE;
	} else {
		cm_key_algorithm = entry->cm_key_type.cm_key_algorithm;
	}
	/* Convert our key type to a mechanism. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;
	default:
		cm_log(1, "Unknown key type.\n");
		_exit(2);
		break;
	}
	/* Find the token that contains our key pair. */
	slotlist = PK11_GetAllTokens(mech, PR_TRUE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		cm_log(1, "Error locating slot for CSR generation.\n");
		_exit(2);
	}
	/* Walk the list looking for the requested slot, or the first one if
	 * none was requested. */
	slot = NULL;
	for (sle = slotlist->head;
	     ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		token = PK11_GetTokenName(sle->slot);
		if (token != NULL) {
			cm_log(3, "Found token '%s'.\n", token);
		}
		if ((entry->cm_key_token == NULL) ||
		    (strlen(entry->cm_key_token) == 0) ||
		    (strcmp(entry->cm_key_token, token) == 0)) {
			slot = sle->slot;
			break;
		}
		if (sle == slotlist->tail) {
			break;
		}
	}
	if (slot == NULL) {
		cm_log(1, "Error locating slot for key generation.\n");
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}
	/* Log in to the database, if we can. */
	if (PK11_NeedLogin(slot) || !PK11_IsFriendly(slot)) {
		error = PK11_Authenticate(slot, PR_TRUE, NULL);
		if (error != SECSuccess) {
			cm_log(1, "Error authenticating to key store.\n");
			PK11_FreeSlotList(slotlist);
			error = NSS_Shutdown();
			if (error != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(2);
		}
	}
	/* Locate the key pair. */
	privkeys = PK11_ListPrivKeysInSlot(slot, entry->cm_key_nickname, NULL);
	if (privkeys == NULL) {
		cm_log(1, "Error finding matching key pairs.\n");
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}
	privkey = NULL;
	if (!PR_CLIST_IS_EMPTY(&(privkeys->list))) {
		for (node = PRIVKEY_LIST_HEAD(privkeys);
		     ((node != NULL) && (node->key != NULL));
		     node = PRIVKEY_LIST_NEXT(node)) {
			keyname = PK11_GetPrivateKeyNickname(node->key);
			if ((entry->cm_key_nickname == NULL) ||
			    (strlen(entry->cm_key_nickname) == 0) ||
			    (strcmp(entry->cm_key_nickname, keyname) == 0)) {
				privkey = node->key;
				break;
			}
			if (PRIVKEY_LIST_END(node, privkeys)) {
				break;
			}
		}
	}
	if (privkey == NULL) {
		cm_log(1, "Error finding designated key pair.\n");
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}
	/* Decode the CSR into a signeddata structure. */
	p = entry->cm_csr;
	q = NULL;
	while (strncmp(p, "-----BEGIN ", 11) == 0) {
		p += strcspn(p, "\r\n");
		p += strspn(p, "\r\n");
	}
	q = strstr(p, "-----END");
	if ((p == NULL) || (q == NULL)) {
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
	sigoid = SECOID_FindOIDByTag(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION);
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
	now = PR_Now();
	life = CM_DEFAULT_CERT_LIFETIME * 24 * 60 * 60 * 1000000L;
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
	item = SEC_ASN1EncodeUnsignedInteger(arena, &ucert->version, 2);
	if (item == NULL) {
		cm_log(1, "Unable to set certificate structure version.\n");
		_exit(1);
	}
	item = SEC_ASN1EncodeUnsignedInteger(arena, &ucert->serialNumber, 0); /* XXX */
	if (item == NULL) {
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
	/* Try to copy the extensions from the request into the certificate. */
	if (CERT_GetCertificateRequestExtensions(req,
						 &ucert->extensions) != SECSuccess) {
		cm_log(1, "Error getting certificate request extensions.\n");
	}
	/* Encode the certificate. */
	ecert = SEC_ASN1EncodeItem(arena, NULL, ucert,
				   CERT_CertificateTemplate);
	if (ecert == NULL) {
		cm_log(1, "Error encoding certificate structure.\n");
		_exit(1);
	}
	/* Create a signed certificate. */
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
	/* Encode the certificate. */
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
	_exit(0);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_submit_sn_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return state->fd;
}

/* Save CA-specific identifier for our submitted request. */
static int
cm_submit_sn_save_ca_cookie(struct cm_store_entry *entry,
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

/* Check if an attempt to submit has completed. */
static int
cm_submit_sn_ready(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	ssize_t i, remainder;
	int status;
	do {
		remainder = (sizeof(state->msg) - state->count) - 1;
		i = read(state->fd, state->msg + state->count, remainder);
		switch (i) {
		case -1:
		case 0:
			break;
		default:
			state->count += i;
			break;
		}
	} while (i > 0);
	if ((i == -1) && ((errno == EAGAIN) || (errno == EINTR))) {
		status = -1;
	} else {
		state->msg[state->count] = '\0';
		close(state->fd);
		state->fd = -1;
		waitpid(state->pid, &state->status, 0);
		state->pid = -1;
		status = 0;
	}
	return status;
}

/* Check if the certificate was issued. */
static int
cm_submit_sn_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->pid == -1) {
		if (!WIFEXITED(state->status) ||
		    (WEXITSTATUS(state->status) != 0)) {
			return -1;
		}
	}
	if ((strstr(state->msg, "-----BEGIN CERTIFICATE-----") != NULL) &&
	    (strstr(state->msg, "-----END CERTIFICATE-----") != NULL)) {
		talloc_free(entry->cm_cert);
		entry->cm_cert = talloc_strdup(entry, state->msg);
		return 0;
	}
	return -1;
}

/* Check if the signing request was rejected. */
static int
cm_submit_sn_rejected(struct cm_store_entry *entry,
		      struct cm_submit_state *state)
{
	return -1; /* it never gets rejected */
}

/* Check if the CA was unreachable. */
static int
cm_submit_sn_unreachable(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	return -1; /* uh, we're the CA */
}

/* Done talking to the CA. */
static void
cm_submit_sn_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_sn_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_submit_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		cm_log(1, "Wrong submission method: only keys stored "
		       "in an NSS database can be used.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.get_fd = cm_submit_sn_get_fd;
		state->pvt.save_ca_cookie = cm_submit_sn_save_ca_cookie;
		state->pvt.ready = cm_submit_sn_ready;
		state->pvt.issued = cm_submit_sn_issued;
		state->pvt.rejected = cm_submit_sn_rejected;
		state->pvt.unreachable = cm_submit_sn_unreachable;
		state->pvt.done = cm_submit_sn_done;
		state->fd = -1;
		if (pipe(fds) != -1) {
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(fds[0]);
				close(fds[1]);
				talloc_free(state);
				state = NULL;
				break;
			case 0:
				close(fds[0]);
				cm_submit_sn_main(fds[1], entry);
				_exit(0);
				break;
			default:
				state->fd = fds[0];
				close(fds[1]);
				break;
			}
		}
	}
	return state;
}
