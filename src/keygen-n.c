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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <prerror.h>

#include <talloc.h>

#include "keygen.h"
#include "keygen-int.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_keygen_state {
	struct cm_keygen_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, count, status;
};

static void
cm_keygen_n_main(int fd, struct cm_store_entry *entry)
{
	FILE *status;
	enum cm_key_algorithm cm_key_algorithm;
	int cm_key_size, cm_requested_key_size;
	CK_MECHANISM_TYPE mech;
	SECStatus error;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	PK11SlotInfo *slot = NULL;
	PK11RSAGenParams rsa_params;
	void *params;
	SECKEYPrivateKey *privkey;
	SECKEYPublicKey *pubkey;
	PRErrorCode ec;
	const char *es, *token;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(1);
	}
	/* Start up NSS and open the database. */
	error = NSS_InitReadWrite(entry->cm_key_storage_location);
	if (error != SECSuccess) {
		fprintf(status, "Error initializing database '%s'.\n",
			entry->cm_key_storage_location);
		cm_log(1, "Error initializing database '%s'.\n",
		       entry->cm_key_storage_location);
		_exit(1);
	}
	/* Handle defaults. */
	if (entry->cm_key_type_default) {
		cm_key_algorithm = CM_DEFAULT_PUBKEY_TYPE;
		cm_requested_key_size = CM_DEFAULT_PUBKEY_SIZE;
	} else {
		cm_key_algorithm = entry->cm_key_type.cm_key_algorithm;
		cm_requested_key_size = entry->cm_key_type.cm_key_size;
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
	/* Find the tokens that we might use for key generation. */
	slotlist = PK11_GetAllTokens(mech, PR_TRUE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		fprintf(status, "Error locating slot for key generation.\n");
		cm_log(1, "Error locating slot for key generation.\n");
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
		_exit(2);
	}
	/* Select the optimum key size. */
	cm_key_size = PK11_GetBestKeyLength(slot, mech);
	if (cm_key_size > 0) {
		if ((entry->cm_key_type_default == 0) &&
		    (cm_key_size != cm_requested_key_size)) {
			cm_log(1,
			       "Overriding requested key size of %d with %d.\n",
			       cm_requested_key_size, cm_key_size);
		}
	} else {
		if (cm_requested_key_size > 0) {
			cm_key_size = cm_requested_key_size;
		} else {
			cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
		}
	}
	/* Initialize the key generation parameters. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		memset(&rsa_params, 0, sizeof(rsa_params));
		rsa_params.keySizeInBits = cm_key_size;
		rsa_params.pe = CM_DEFAULT_RSA_MODULUS;
		params = &rsa_params;
		break;
	default:
		params = NULL;
		break;
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
	/* Generate the key pair. */
	pubkey = NULL;
	privkey = PK11_GenerateKeyPair(slot, mech, params, &pubkey,
				       PR_TRUE, PR_TRUE, NULL);
	if (privkey == NULL) {
		ec = PR_GetError();
		if (ec != 0) {
			es = PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Error generating key pair: %s.\n", es);
		} else {
			cm_log(1, "Error generating key pair.\n");
		}
		_exit(2);
	}
	/* Attach the specified nickname to the key. */
	error = PK11_SetPrivateKeyNickname(privkey, entry->cm_key_nickname);
	if (error != SECSuccess) {
		cm_log(1, "Error setting nickname on private key.\n");
	}
	error = PK11_SetPublicKeyNickname(pubkey, entry->cm_key_nickname);
	if (error != SECSuccess) {
		cm_log(1, "Error setting nickname on public key.\n");
	}
	/* Record the token name if we didn't already have one. */
	if ((entry->cm_key_token == NULL) ||
	    (strlen(entry->cm_key_token) == 0)) {
		talloc_free(entry->cm_key_token);
		entry->cm_key_token = talloc_strdup(entry, token);
		if (entry->cm_key_token == NULL) {
			cm_log(1, "Error recording token name.\n");
		}
	}
	SECKEY_DestroyPrivateKey(privkey);
	SECKEY_DestroyPublicKey(pubkey);
	PK11_FreeSlotList(slotlist);
	error = NSS_Shutdown();
	if (error != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	fclose(status);
}

/* Check if the keypair is ready. */
static int
cm_keygen_n_ready(struct cm_store_entry *entry, struct cm_keygen_state *state)
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
cm_keygen_n_get_fd(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	return state->fd;
}

/* Tell us if the keypair was saved to the location specified in the entry. */
static int
cm_keygen_n_saved_keypair(struct cm_store_entry *entry,
		          struct cm_keygen_state *state)
{

	if (WIFEXITED(state->status) && (WEXITSTATUS(state->status) == 0)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
static void
cm_keygen_n_done(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *
cm_keygen_n_start(struct cm_store_entry *entry)
{
	int fds[2];
	long flags;
	struct cm_keygen_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_keygen_n_ready;
		state->pvt.get_fd = cm_keygen_n_get_fd;
		state->pvt.saved_keypair = cm_keygen_n_saved_keypair;
		state->pvt.done = cm_keygen_n_done;
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
				cm_keygen_n_main(fds[1], entry);
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
