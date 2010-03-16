/*
 * Copyright (C) 2009,2010 Red Hat, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <keyhi.h>
#include <keythi.h>
#include <pk11pub.h>
#include <prerror.h>

#include <talloc.h>

#include "keyiread.h"
#include "keyiread-int.h"
#include "keyiread-n.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"

#ifndef PRIVKEY_LIST_EMPTY
#define PRIVKEY_LIST_EMPTY(l) PRIVKEY_LIST_END(PRIVKEY_LIST_HEAD(l), l)
#endif

struct cm_keyiread_state {
	struct cm_keyiread_state_pvt pvt;
	struct cm_subproc_state *subproc;
};
struct cm_keyiread_n_settings {
	int readwrite:1;
};

SECKEYPrivateKey *
cm_keyiread_n_get_private_key(struct cm_store_entry *entry, int readwrite)
{
	const char *token, *nickname;
	PLArenaPool *arena;
	SECStatus error;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	PK11SlotInfo *slot;
	SECKEYPrivateKeyList *keys;
	SECKEYPrivateKeyListNode *knode;
	SECKEYPrivateKey *key;
	CK_MECHANISM_TYPE mech;
	CERTCertList *certs;
	CERTCertListNode *cnode;
	CERTCertificate *cert;
	int n_login_attempts, n_login_success;

	/* Open the database. */
	error = readwrite ? NSS_InitReadWrite(entry->cm_key_storage_location) :
			    NSS_Init(entry->cm_key_storage_location);
	if (error != SECSuccess) {
		cm_log(1, "Unable to open NSS database '%s'.\n",
		       entry->cm_key_storage_location);
		_exit(CM_STATUS_ERROR_INITIALIZING);
	}

	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Out of memory opening database '%s'.\n",
		       entry->cm_key_storage_location);
		if (NSS_Shutdown() != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_STATUS_ERROR_INITIALIZING);
	}

	/* Find the tokens that we might use for key storage. */
	mech = 0;
	slotlist = PK11_GetAllTokens(mech, PR_FALSE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		cm_log(1, "Error locating token to be used for key storage.\n");
		if (NSS_Shutdown() != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_STATUS_ERROR_NO_TOKEN);
	}

	/* Walk the list looking for the requested token, or look at all of
	 * them if none specifically was requested. */
	key = NULL;
	slot = NULL;
	PK11_SetPasswordFunc(&cm_pin_cb_key);
	n_login_attempts = 0;
	n_login_success = 0;
	for (sle = slotlist->head;
	     ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		/* Read the token's name. */
		slot = sle->slot;
		token = PK11_GetTokenName(slot);
		if (token != NULL) {
			cm_log(3, "Found token '%s'.\n", token);
		}

		/* If this is the wrong token, move on. */
		if ((entry->cm_key_token != NULL) &&
		    (strlen(entry->cm_key_token) > 0) &&
		    (strcmp(entry->cm_key_token, token) != 0)) {
			cm_log(1, "Token is named \"%s\", not \"%s\".\n",
			       token, entry->cm_key_token);
			goto next_slot;
		}

		/* Try to log in, if we have to. */
		if (PK11_NeedLogin(slot) || !PK11_IsFriendly(slot)) {
			n_login_attempts++;
			error = PK11_Authenticate(slot, PR_TRUE, entry);
			if (error != SECSuccess) {
				cm_log(1, "Error authenticating to token "
				       "\"%s\".\n", token);
				goto next_slot;
			}
			n_login_success++;
		}

		/* Walk the list of private keys in the token, looking at each
		 * one to see if it matches the specified nickname. */
		keys = PK11_ListPrivKeysInSlot(slot, entry->cm_key_nickname,
					       NULL);
		if (keys != NULL) {
			for (knode = PRIVKEY_LIST_HEAD(keys);
			     !PRIVKEY_LIST_EMPTY(keys) &&
			     !PRIVKEY_LIST_END(knode, keys);
			     knode = PRIVKEY_LIST_NEXT(knode)) {
				cm_log(3, "Located the key.\n");
				key = SECKEY_CopyPrivateKey(knode->key);
				break;
			}
			SECKEY_DestroyPrivateKeyList(keys);
		}

		/* Walk the list of certificates in the token, looking at each
		 * one to see if it matches the specified nickname and has a
		 * private key associated with it. */
		if (key == NULL) {
			certs = PK11_ListCertsInSlot(slot);
		} else {
			certs = NULL;
		}
		if (certs != NULL) {
			for (cnode = CERT_LIST_HEAD(certs);
			     !CERT_LIST_EMPTY(certs) &&
			     !CERT_LIST_END(cnode, certs);
			     cnode = CERT_LIST_NEXT(cnode)) {
				nickname = entry->cm_key_nickname;
				cert = cnode->cert;
				if ((nickname != NULL) &&
				    (strcmp(cert->nickname, nickname) == 0)) {
					cm_log(3, "Located a certificate with "
					       "the key's nickname (\"%s\").\n",
					       nickname);
					key = PK11_FindPrivateKeyFromCert(slot,
									  cert,
									  NULL);
					if (key != NULL) {
						cm_log(3, "Located its private "
						       "key.\n");
						break;
					}
				}
			}
			CERT_DestroyCertList(certs);
		}

next_slot:
		/* If this was the last token, stop walking. */
		if (sle == slotlist->tail) {
			break;
		}
	}

	PK11_FreeSlotList(slotlist);

	if (key == NULL) {
		cm_log(1, "Error locating key.\n");
	}

	PORT_FreeArena(arena, PR_TRUE);

	/* If we tried to log into a token and failed, flag that error. */
	if (n_login_attempts < n_login_success) {
		_exit(CM_STATUS_ERROR_AUTH);
	}

	return key;
}

static int
cm_keyiread_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	SECKEYPrivateKey *key;
	SECKEYPublicKey *pubkey;
	PK11SlotInfo *slot;
	const char *alg, *name;
	int status = 1, size, readwrite;
	FILE *fp;
	struct cm_keyiread_n_settings *settings;

	/* Open the status descriptor for stdio. */
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		cm_log(1, "Unable to initialize I/O.\n");
		_exit(CM_STATUS_ERROR_INTERNAL);
	}

	/* Read the key. */
	settings = userdata;
	readwrite = settings->readwrite;
	key = cm_keyiread_n_get_private_key(entry, readwrite);
	alg = "";
	size = 0;
	if (key != NULL) {
		switch (SECKEY_GetPrivateKeyType(key)) {
		case rsaKey:
			cm_log(3, "Key is an RSA key.\n");
			alg = "RSA";
			break;
		case dsaKey:
			cm_log(3, "Key is a DSA key.\n");
			alg = "DSA";
			break;
		case nullKey:
		default:
			cm_log(3, "Key is of an unknown type.\n");
			break;
		}
		slot = PK11_GetSlotFromPrivateKey(key);
		if (slot != NULL) {
			name = PK11_GetTokenName(slot);
			if ((name != NULL) && (strlen(name) == 0)) {
				name = NULL;
			}
		} else {
			name = NULL;
		}
		if (strlen(alg) > 0) {
			pubkey = SECKEY_ConvertToPublicKey(key);
			if (pubkey != NULL) {
				size = SECKEY_PublicKeyStrengthInBits(pubkey);
				cm_log(3, "Key size is %d.\n", size);
				fprintf(fp, "%s/%d%s%s\n", alg, size,
					(name != NULL ? "/" : ""),
					(name != NULL ? name : ""));
				status = 0;
				SECKEY_DestroyPublicKey(pubkey);
			} else {
				cm_log(1, "Error converting private key "
				       "to public key.\n");
			}
		}
		SECKEY_DestroyPrivateKey(key);
	}
	fclose(fp);
	if (NSS_Shutdown() != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	if (status != 0) {
		_exit(status);
	}
	return 0;
}

/* Check if something changed, for example we finished reading the data we need
 * from the key data. */
static int
cm_keyiread_n_ready(struct cm_store_entry *entry,
		    struct cm_keyiread_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Check if we were able to successfully read the key information. */
static int
cm_keyiread_n_finished_reading(struct cm_store_entry *entry,
			       struct cm_keyiread_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Check if we need a PIN (or a new PIN) to access the key information. */
static int
cm_keyiread_n_need_pin(struct cm_store_entry *entry,
		       struct cm_keyiread_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_keyiread_n_get_fd(struct cm_store_entry *entry,
		     struct cm_keyiread_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Clean up after reading the key info. */
static void
cm_keyiread_n_done(struct cm_store_entry *entry,
		   struct cm_keyiread_state *state)
{
	if (state->subproc != NULL) {
		cm_keyiread_read_data_from_buffer(entry,
						  cm_subproc_get_msg(entry,
						  		     state->subproc,
								     NULL));
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}

/* Start reading the key info from the configured location. */
struct cm_keyiread_state *
cm_keyiread_n_start(struct cm_store_entry *entry)
{
	struct cm_keyiread_state *state;
	struct cm_keyiread_n_settings settings = {
		.readwrite = 0,
	};
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		cm_log(1, "Wrong read method: can only read keys "
		       "from an NSS database.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.finished_reading = cm_keyiread_n_finished_reading;
		state->pvt.need_pin = cm_keyiread_n_need_pin;
		state->pvt.ready = cm_keyiread_n_ready;
		state->pvt.get_fd= cm_keyiread_n_get_fd;
		state->pvt.done= cm_keyiread_n_done;
		state->subproc = cm_subproc_start(cm_keyiread_n_main,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
