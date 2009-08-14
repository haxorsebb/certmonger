#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certt.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <cryptohi.h>

#include "log.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"

struct cm_submit_state {
	char msg[0x10000];
	pid_t pid;
	int fd, status;
};

static void
cm_submit_main(int fd, struct cm_store_entry *entry)
{
	FILE *status;
	char *b64;
	const char *keyname, *token, *p, *q;
	SECStatus error;
	SECItem *esdata = NULL, *ecert = NULL;
	SECKEYPrivateKey *privkey;
	SECKEYPrivateKeyList *privkeys;
	SECKEYPrivateKeyListNode *node;
	CERTCertificate *ucert = NULL;
	CERTCertificateRequest *req = NULL, sreq;
	CERTSignedData *data = NULL, sdata, scert;
	CERTValidity *validity;
	PRTime now;
	PLArenaPool *arena = NULL;
	SECOidData *oid;
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
		for (node = PR_LIST_HEAD(&(privkeys->list));
		     ((node != NULL) && (node->key != NULL));
		     node = PR_NEXT_LINK(&(node->links))) {
			keyname = PK11_GetPrivateKeyNickname(node->key);
			if ((entry->cm_key_nickname == NULL) ||
			    (strlen(entry->cm_key_nickname) == 0) ||
			    (strcmp(entry->cm_key_nickname, keyname) == 0)) {
				privkey = node->key;
				break;
			}
			if (node == PR_LIST_TAIL(&(privkeys->list))) {
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
		q = strstr(entry->cm_csr, "-----END");
	}
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
	validity = CERT_CreateValidity(now, now + 30 * 24 * 60 * 60);
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
	/* Encode the certificate. */
	ecert = SEC_ASN1EncodeItem(arena, NULL, ucert,
				   CERT_CertificateTemplate);
	if (ecert == NULL) {
		cm_log(1, "Error encoding certificate structure.\n");
		_exit(1);
	}
	/* Create a signed certificate. */
	oid = SECOID_FindOIDByTag(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION);
	memset(&scert, 0, sizeof(scert));
	scert.data = *ecert;
	if (SECOID_SetAlgorithmID(arena, &scert.signatureAlgorithm,
				  oid->offset, NULL) != SECSuccess) {
		cm_log(1, "Unable to set signature algorithm ID.\n");
		_exit(1);
	}
	if (SEC_SignData(&scert.signature, ecert->data, ecert->len,
			 privkey, oid->offset) != SECSuccess) {
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

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_start(struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_submit_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		cm_log(1, "Wrong submission method: only keys stored "
		       "in an NSS database can be used.\n");
		return NULL;
	}
	state = malloc(sizeof(*state));
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->fd = -1;
		if (pipe(fds) != -1) {
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(fds[0]);
				close(fds[1]);
				free(state);
				state = NULL;
				break;
			case 0:
				close(fds[0]);
				cm_submit_main(fds[1], entry);
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

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_submit_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return state->fd;
}

/* Check if the CSR was received by the CA yet. */
int
cm_submit_sent(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return 0;
}

/* Save CA-specific identifier for our submitted request. */
int
cm_submit_save_ca_cookie(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	free(entry->cm_ca_cookie);
	entry->cm_ca_cookie = strdup(entry->cm_key_storage_location);
	if (entry->cm_ca_cookie == NULL) {
		cm_log(1, "Out of memory.\n");
		return ENOMEM;
	}
	return 0;
}

/* Pick up after a CSR has been "submitted", in case we haven't yet gotten a
 * decision about it. */
struct cm_submit_state *
cm_submit_resume(struct cm_store_entry *entry)
{
	struct cm_submit_state *state;
	state = cm_submit_start(entry);
	cm_submit_save_ca_cookie(entry, state);
	return state;
}

/* Check if an attempt to get status has succeeded. */
int
cm_submit_status_ready(struct cm_store_entry *entry,
		       struct cm_submit_state *state)
{
	ssize_t i, remainder;
	char *p;
	p = state->msg;
	remainder = sizeof(state->msg) - 1;
	while ((i = read(state->fd, p, remainder)) > 0) {
		p += i;
		remainder -= i;
	}
	*p = '\0';
	close(state->fd);
	state->fd = -1;
	waitpid(state->pid, &state->status, 0);
	state->pid = -1;
	free(entry->cm_cert);
	entry->cm_cert = strdup(state->msg);
	return 0;
}

/* Check if the certificate was issued. */
int
cm_submit_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->pid == -1) {
		if (!WIFEXITED(state->status) ||
		    (WEXITSTATUS(state->status) != 0)) {
			return -1;
		}
	}
	if ((strstr(state->msg, "-----BEGIN CERTIFICATE-----") != NULL) &&
	    (strstr(state->msg, "-----END CERTIFICATE-----") != NULL)) {
		return 0;
	}
	return -1;
}

/* Check if we need to make another request to actually retrieve the cert. */
int
cm_submit_needs_retrieval(struct cm_store_entry *entry,
			  struct cm_submit_state *state)
{
	return -1; /* already have data, no additional retrieval step needed */
}

/* Done talking to the CA. */
void
cm_submit_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}
