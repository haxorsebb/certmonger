#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <keythi.h>
#include <cert.h>

#include "keygen.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_csrgen_state {
	char msg[0x10000];
	pid_t pid;
	int fd, status;
};

static void
cm_csrgen_main(int fd, struct cm_store_entry *entry)
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
	CERTName *name;
	const char *token, *keyname;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(1);
	}
	/* Start up NSS and open the database. */
	error = NSS_Init(entry->cm_key_storage_location);
	if (error != SECSuccess) {
		fprintf(status, "Error opening database '%s'.\n",
			entry->cm_key_storage_location);
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
		fprintf(status, "Unknown key type.\n");
		cm_log(1, "Unknown key type.\n");
		_exit(2);
		break;
	}
	/* Find the token that contains our key pair. */
	slotlist = PK11_GetAllTokens(mech, PR_TRUE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		fprintf(status, "Error locating slot for CSR generation.\n");
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
		fprintf(status, "Error locating slot for key generation.\n");
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
	/* Create the request. */
	if (entry->cm_template_subject != NULL) {
		name = CERT_AsciiToName(entry->cm_template_subject);
	} else {
		name = NULL;
	}
	pubkey = SECKEY_ConvertToPublicKey(privkey);
	spki = SECKEY_CreateSubjectPublicKeyInfo(pubkey);
	req = CERT_CreateCertificateRequest(name, spki, NULL);
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

/* Start CSR generation using template information in the entry. */
struct cm_csrgen_state *
cm_csrgen_start(struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_csrgen_state *state;
	state = malloc(sizeof(*state));
	if (state != NULL) {
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
				cm_csrgen_main(fds[1], entry);
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

/* Check if a CSR is ready. */
int
cm_csrgen_ready(struct cm_store_entry *entry, struct cm_csrgen_state *state)
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
	return 0;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_csrgen_get_fd(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	return state->fd;
}

/* Save the CSR to the entry. */
int
cm_csrgen_save_csr(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	if (state->pid == -1) {
		if (!WIFEXITED(state->status) ||
		    (WEXITSTATUS(state->status) != 0)) {
			return -1;
		}
		free(entry->cm_csr);
		entry->cm_csr = strdup(state->msg);
		if (entry->cm_csr == NULL) {
			return ENOMEM;
		}
	}
	return 0;
}

/* Clean up after CSR generation. */
void
cm_csrgen_done(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}
