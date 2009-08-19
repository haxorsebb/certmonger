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
#include <pk11pub.h>
#include <keyhi.h>
#include <keythi.h>
#include <cryptohi.h>
#include <cert.h>

#include <talloc.h>

#include "csrgen.h"
#include "csrgen-int.h"
#include "keygen.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_csrgen_state {
	struct cm_csrgen_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, count, status;
};

static void
cm_csrgen_n_main(int fd, struct cm_store_entry *entry)
{
	FILE *status;
	SECStatus error;
	SECKEYPrivateKeyList *privkeys;
	SECKEYPrivateKeyListNode *node;
	SECKEYPrivateKey *privkey;
	SECKEYPublicKey *pubkey;
	CK_MECHANISM_TYPE mech;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	PK11SlotInfo *slot;
	enum cm_key_algorithm cm_key_algorithm;
	CERTSubjectPublicKeyInfo *spki;
	CERTCertificateRequest *req;
	CERTSignedData sreq;
	CERTName *name;
	const char *token, *keyname;
	PLArenaPool *arena;
	SECItem ereq, esreq;
	PRErrorCode ec;
	char *b64, *p, *q;
	SECOidData *sigoid;

	/* Allocate an arena pool and a place to write status updates. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Out of memory?.\n");
		_exit(1);
	}
	status = fdopen(fd, "w");
	if (status == NULL) {
		cm_log(1, "Internal error: %s.\n", strerror(errno));
		_exit(1);
	}
	/* Start up NSS and open the database. */
	error = NSS_Init(entry->cm_key_storage_location);
	if (error != SECSuccess) {
		cm_log(1, "Error opening database '%s'.\n",
		       entry->cm_key_storage_location);
		_exit(1);
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
	/* Create the request. */
	if (!entry->cm_template_default &&
	    (entry->cm_template_subject != NULL) &&
	    (strlen(entry->cm_template_subject) != 0)) {
		name = CERT_AsciiToName(entry->cm_template_subject);
	} else {
		name = CERT_AsciiToName("CN=localhost");
	}
	pubkey = SECKEY_ConvertToPublicKey(privkey);
	if (pubkey == NULL) {
		ec = PR_GetError();
		if (ec == 0) {
			cm_log(1, "Error retrieving public key.\n");
		} else {
			cm_log(1, "Error retrieving public key: %s.\n",
			       PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT));
		}
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(2);
	}
	spki = SECKEY_CreateSubjectPublicKeyInfo(pubkey);
	if (spki == NULL) {
		ec = PR_GetError();
		if (ec == 0) {
			cm_log(1, "Error building spki.\n");
		} else {
			cm_log(1, "Error building spki: %s.\n",
			       PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT));
		}
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(2);
	}
	req = CERT_CreateCertificateRequest(name, spki, NULL);
	if (req == NULL) {
		ec = PR_GetError();
		if (ec == 0) {
			cm_log(1, "Error building request.\n");
		} else {
			cm_log(1, "Error building request: %s.\n",
			       PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT));
		}
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(2);
	}
	req->arena = arena;
	req->subjectPublicKeyInfo = *spki;
	if (SEC_ASN1EncodeInteger(arena, &req->version,
				  SEC_CERTIFICATE_REQUEST_VERSION) !=
	    &req->version) {
		cm_log(1, "Error encoding request version.\n");
	}
	/* Encode the request. */
	if (SEC_ASN1EncodeItem(arena, &ereq, req,
			       CERT_CertificateRequestTemplate) !=
	    &ereq) {
		cm_log(1, "Error encoding request.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(2);
	}
	/* Sign the request using the private key. */
	sigoid = SECOID_FindOIDByTag(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION); /* XXX */
	memset(&sreq, 0, sizeof(sreq));
	sreq.data = ereq;
	if (SECOID_SetAlgorithmID(arena, &sreq.signatureAlgorithm,
				  sigoid->offset, NULL) != SECSuccess) {
		cm_log(1, "Error setting up algorithm ID.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(2);
	}
	if (SEC_SignData(&sreq.signature, sreq.data.data, sreq.data.len,
			 privkey, sigoid->offset) != SECSuccess) {
		cm_log(1, "Error signing request.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(2);
	}
	/* Encode the signed request. */
	sreq.signature.len *= 8;
	if (SEC_ASN1EncodeItem(arena, &esreq, &sreq,
			       CERT_SignedDataTemplate) !=
	    &esreq) {
		cm_log(1, "Error encoding signed request.\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(2);
	}
	/* Encode the request into base-64 and pass it to our caller. */
	b64 = NSSBase64_EncodeItem(arena, NULL, -1, &esreq);
	if (b64 != NULL) {
		fprintf(status, "-----BEGIN NEW CERTIFICATE REQUEST-----\n");
		p = b64;
		while (*p != '\0') {
			q = p + strcspn(p, "\r\n");
			fprintf(status, "%.*s\n", (int) (q - p), p);
			p = q + strspn(q, "\r\n");
		}
		fprintf(status, "-----END NEW CERTIFICATE REQUEST-----\n");
		SECKEY_DestroyPublicKey(pubkey);
		SECKEY_DestroyPrivateKeyList(privkeys);
		PK11_FreeSlotList(slotlist);
		error = NSS_Shutdown();
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		fclose(status);
		_exit(0);
	}
	/* Clean up.  We're not really doing anything here yet. */
	SECKEY_DestroyPublicKey(pubkey);
	SECKEY_DestroyPrivateKeyList(privkeys);
	PK11_FreeSlotList(slotlist);
	error = NSS_Shutdown();
	if (error != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	fclose(status);
	_exit(2);
}

/* Check if a CSR is ready. */
static int
cm_csrgen_n_ready(struct cm_store_entry *entry, struct cm_csrgen_state *state)
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

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_csrgen_n_get_fd(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	return state->fd;
}

/* Save the CSR to the entry. */
static int
cm_csrgen_n_save_csr(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state)
{
	if (state->pid == -1) {
		if (!WIFEXITED(state->status) ||
		    (WEXITSTATUS(state->status) != 0)) {
			return -1;
		}
		talloc_free(entry->cm_csr);
		entry->cm_csr = talloc_strdup(entry, state->msg);
		if (entry->cm_csr == NULL) {
			return ENOMEM;
		}
	}
	return 0;
}

/* Clean up after CSR generation. */
static void
cm_csrgen_n_done(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Start CSR generation using template information in the entry. */
struct cm_csrgen_state *
cm_csrgen_n_start(struct cm_store_entry *entry)
{
	int fds[2];
	long flags;
	struct cm_csrgen_state *state;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = &cm_csrgen_n_ready;
		state->pvt.get_fd = &cm_csrgen_n_get_fd;
		state->pvt.save_csr = &cm_csrgen_n_save_csr;
		state->pvt.done = &cm_csrgen_n_done;
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
				cm_csrgen_n_main(fds[1], entry);
				_exit(0);
				break;
			default:
				state->fd = fds[0];
				flags = fcntl(state->fd, F_GETFL);
				fcntl(state->fd, F_SETFL, flags | O_NONBLOCK);
				close(fds[1]);
				break;
			}
		}
	}
	return state;
}
