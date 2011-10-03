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
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"

#define PRIVKEY_LIST_EMPTY(l) PRIVKEY_LIST_END(PRIVKEY_LIST_HEAD(l), l)

struct cm_keygen_state {
	struct cm_keygen_state_pvt pvt;
	struct cm_subproc_state *subproc;
};
struct cm_keygen_n_settings {
	int readwrite:1;
};

static int
cm_keygen_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	FILE *status;
	enum cm_key_algorithm cm_key_algorithm;
	int cm_key_size, cm_requested_key_size, readwrite;
	CK_MECHANISM_TYPE mech;
	SECStatus error;
	NSSInitContext *ctx;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	PK11SlotInfo *slot = NULL, *islot;
	PK11RSAGenParams rsa_params;
	void *params;
	SECKEYPrivateKey *privkey, *delkey;
	SECKEYPrivateKeyList *privkeys;
	SECKEYPrivateKeyListNode *node;
	SECKEYPublicKey *pubkey;
	PRErrorCode ec;
	const char *es, *token, *keyname;
	char *pin;
	struct cm_keygen_n_settings *settings;
	struct cm_pin_cb_data cb_data;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Start up NSS and open the database. */
	settings = userdata;
	readwrite = settings->readwrite;
	ctx = NSS_InitContext(entry->cm_key_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	if (ctx == NULL) {
		fprintf(status, "Error initializing database '%s'.\n",
			entry->cm_key_storage_location);
		cm_log(1, "Error initializing database '%s'.\n",
		       entry->cm_key_storage_location);
		_exit(CM_STATUS_ERROR_INITIALIZING);
	}
	/* Handle the key size. */
	cm_key_algorithm = entry->cm_key_type.cm_key_gen_algorithm;
	if (cm_key_algorithm == cm_key_unspecified) {
		cm_key_algorithm = CM_DEFAULT_PUBKEY_TYPE;
	}
	cm_key_size = entry->cm_key_type.cm_key_gen_size;
	if (cm_key_size <= 0) {
		cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
	}
	cm_requested_key_size = entry->cm_key_type.cm_key_gen_size;
	/* Convert our key type to a mechanism. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;
	default:
		fprintf(status, "Unknown or unsupported key type.\n");
		cm_log(1, "Unknown or unsupported key type.\n");
		_exit(CM_STATUS_ERROR_INTERNAL);
		break;
	}
	/* Find the tokens that we might use for key generation. */
	slotlist = PK11_GetAllTokens(mech, PR_TRUE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		fprintf(status, "Error locating token for key generation.\n");
		cm_log(1, "Error locating token for key generation.\n");
		_exit(CM_STATUS_ERROR_NO_TOKEN);
	}
	/* Walk the list looking for the requested slot, or the first one if
	 * none was requested. */
	slot = NULL;
	islot = PK11_GetInternalSlot();
	for (sle = slotlist->head;
	     ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		if (sle->slot == islot) {
			cm_log(3, "Skipping NSS internal slot (%s).\n",
			       PK11_GetTokenName(sle->slot));
			goto next_slot;
		}
		token = PK11_GetTokenName(sle->slot);
		if (token != NULL) {
			cm_log(3, "Found token '%s'.\n", token);
		} else {
			cm_log(3, "Found unnamed token.\n");
		}
		if ((entry->cm_key_token == NULL) ||
		    (strlen(entry->cm_key_token) == 0) ||
		    ((token != NULL) &&
		     (strcmp(entry->cm_key_token, token) == 0))) {
			slot = sle->slot;
			break;
		}
next_slot:
		if (sle == slotlist->tail) {
			break;
		}
	}
	PK11_FreeSlot(islot);
	if (slot == NULL) {
		fprintf(status, "Error locating token for key generation.\n");
		cm_log(1, "Error locating token for key generation.\n");
		_exit(CM_STATUS_ERROR_NO_TOKEN);
	}
	/* Select the optimum key size. */
	cm_key_size = PK11_GetBestKeyLength(slot, mech);
	if (cm_key_size > 0) {
		if (cm_key_size != cm_requested_key_size) {
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
	/* Be ready to count our uses of a PIN. */
	memset(&cb_data, 0, sizeof(cb_data));
	cb_data.entry = entry;
	cb_data.n_attempts = 0;
	pin = NULL;
	/* If we're supposed to be using a PIN, and we're offered a chance to
	 * set one, do it now. */
	if (readwrite) {
		if (PK11_NeedUserInit(slot)) {
			if (cm_pin_read_for_key(entry, &pin) != 0) {
				cm_log(1, "Error reading PIN to assign "
				       "to storage slot, skipping.\n");
				PK11_FreeSlotList(slotlist);
				error = NSS_ShutdownContext(ctx);
				if (error != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(CM_STATUS_ERROR_AUTH);
			}
			PK11_InitPin(slot, NULL, pin ? pin : "");
			if (PK11_NeedUserInit(slot)) {
				cm_log(1, "Key generation slot still "
				       "needs user PIN to be set.\n");
				PK11_FreeSlotList(slotlist);
				error = NSS_ShutdownContext(ctx);
				if (error != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(CM_STATUS_ERROR_AUTH);
			}
			/* We're authenticated now, so count this as a use of
			 * the PIN. */
			if ((pin != NULL) && (strlen(pin) > 0)) {
				cb_data.n_attempts++;
			}
		}
	}
	/* Now log in, if we have to. */
	if (cm_pin_read_for_key(entry, &pin) != 0) {
		cm_log(1, "Error reading PIN for key store, "
		       "failing to generate CSR.\n");
		PK11_FreeSlotList(slotlist);
		error = NSS_ShutdownContext(ctx);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_STATUS_ERROR_AUTH);
	}
	PK11_SetPasswordFunc(&cm_pin_read_for_key_nss_cb);
	error = PK11_Authenticate(slot, PR_TRUE, &cb_data);
	if (error != SECSuccess) {
		cm_log(1, "Error authenticating to key store.\n");
		PK11_FreeSlotList(slotlist);
		error = NSS_ShutdownContext(ctx);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_STATUS_ERROR_AUTH);
	}
	if ((pin != NULL) &&
	    (strlen(pin) > 0) &&
	    (cb_data.n_attempts == 0)) {
		cm_log(1, "PIN was not needed to auth to key "
		       "store, though one was provided. "
		       "Treating this as an error.\n");
		PK11_FreeSlotList(slotlist);
		error = NSS_ShutdownContext(ctx);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_STATUS_ERROR_AUTH);
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
		_exit(CM_STATUS_ERROR_INTERNAL);
	}
	/* Try to remove any keys with conflicting names. */
	privkeys = PK11_ListPrivKeysInSlot(slot, entry->cm_key_nickname, NULL);
	while ((privkeys != NULL) && !PRIVKEY_LIST_EMPTY(privkeys)) {
		delkey = NULL;
		for (node = PRIVKEY_LIST_HEAD(privkeys);
		     !PRIVKEY_LIST_EMPTY(privkeys) &&
		     !PRIVKEY_LIST_END(node, privkeys);
		     node = PRIVKEY_LIST_NEXT(node)) {
			keyname = PK11_GetPrivateKeyNickname(node->key);
			if ((keyname != NULL) &&
			    (entry->cm_key_nickname != NULL) &&
			    (strcmp(keyname, entry->cm_key_nickname) == 0)) {
				/* Avoid stealing the key reference from the
				 * list. */
				delkey = SECKEY_CopyPrivateKey(node->key);
				break;
			}
		}
		SECKEY_DestroyPrivateKeyList(privkeys);
		if (delkey != NULL) {
			PK11_DeleteTokenPrivateKey(delkey, PR_TRUE);
			/* If we found at least one key before, scan again. */
			privkeys = PK11_ListPrivKeysInSlot(slot,
							   entry->cm_key_nickname,
							   NULL);
		} else {
			privkeys = NULL;
		}
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
	SECKEY_DestroyPrivateKey(privkey);
	SECKEY_DestroyPublicKey(pubkey);
	PK11_FreeSlotList(slotlist);
	error = NSS_ShutdownContext(ctx);
	if (error != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	fclose(status);
	return 0;
}

/* Check if the keypair is ready. */
static int
cm_keygen_n_ready(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_keygen_n_get_fd(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Tell us if the keypair was saved to the location specified in the entry. */
static int
cm_keygen_n_saved_keypair(struct cm_store_entry *entry,
		          struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Tell us if we need a new/correct PIN to use the key store. */
static int
cm_keygen_n_need_pin(struct cm_store_entry *entry,
		     struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to generate the key. */
static int
cm_keygen_n_need_token(struct cm_store_entry *entry,
		       struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
static void
cm_keygen_n_done(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *
cm_keygen_n_start(struct cm_store_entry *entry)
{
	struct cm_keygen_state *state;
	struct cm_keygen_n_settings settings = {
		.readwrite = 1,
	};
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_keygen_n_ready;
		state->pvt.get_fd = cm_keygen_n_get_fd;
		state->pvt.saved_keypair = cm_keygen_n_saved_keypair;
		state->pvt.need_pin = cm_keygen_n_need_pin;
		state->pvt.need_token = cm_keygen_n_need_token;
		state->pvt.done = cm_keygen_n_done;
		state->subproc = cm_subproc_start(cm_keygen_n_main,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
