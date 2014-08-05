/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014 Red Hat, Inc.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pqg.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <keythi.h>
#include <prerror.h>
#include <secerr.h>

#include <talloc.h>

#include "keygen.h"
#include "keygen-int.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "util-n.h"

#define PRIVKEY_LIST_EMPTY(l) PRIVKEY_LIST_END(PRIVKEY_LIST_HEAD(l), l)

struct cm_keygen_state {
	struct cm_keygen_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};
struct cm_keygen_n_settings {
	unsigned int readwrite:1;
};

#ifdef CM_ENABLE_DSA
static int
pqg_size(int key_size)
{
	if (key_size < 512) {
		key_size = 512;
	}
	if (key_size < 1024) {
		key_size = howmany(key_size, 64) * 64;
	}
	if (key_size > 1024) {
		key_size = howmany(key_size, 1024) * 1024;
	}
	if (key_size > 3072) {
		key_size = 3072;
	}
	return key_size;
}
#endif

static int
cm_keygen_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	FILE *status;
	enum cm_key_algorithm cm_key_algorithm;
	int cm_key_size, cm_requested_key_size, readwrite, ec;
	CK_MECHANISM_TYPE mech, pmech;
	SECStatus error;
	NSSInitContext *ctx;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	PK11SlotInfo *slot = NULL;
	PK11RSAGenParams rsa_params;
#ifdef CM_ENABLE_DSA
	PQGParams *pqg_params = NULL;
	PQGVerify *pqg_verify;
	SECStatus pqg_ok;
	SECKEYPQGParams dsa_params;
#endif
	SECItem *spki;
	CERTSubjectPublicKeyInfo *pubkeyinfo;
	void *params;
#ifdef CM_ENABLE_EC
	SECOidData *ecurve;
	SECItem ec_params;
#endif
	SECKEYPrivateKey *privkey, *delkey;
	SECKEYPrivateKeyList *privkeys;
	SECKEYPrivateKeyListNode *node;
	SECKEYPublicKey *pubkey;
	const char *es, *token, *keyname, *reason;
	char *pin, *pubhex, *pubihex;
	struct cm_keygen_n_settings *settings;
	struct cm_pin_cb_data cb_data;
	int retry, generated_size;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	/* Start up NSS and open the database. */
	settings = userdata;
	readwrite = settings->readwrite;
	errno = 0;
	ctx = NSS_InitContext(entry->cm_key_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	ec = PORT_GetError();
	if (ctx == NULL) {
		if ((ec == SEC_ERROR_BAD_DATABASE) && readwrite) {
			switch (errno) {
			case EACCES:
			case EPERM:
				ec = PR_NO_ACCESS_RIGHTS_ERROR;
				break;
			default:
				/* Sigh.  Not a lot of detail.  Check if we
				 * succeed in read-only mode, which we'll
				 * interpret as lack of write permissions. */
				ctx = NSS_InitContext(entry->cm_key_storage_location,
						      NULL, NULL, NULL, NULL,
						      NSS_INIT_READONLY |
						      NSS_INIT_NOROOTINIT |
						      NSS_INIT_NOMODDB);
				if (ctx != NULL) {
					error = NSS_ShutdownContext(ctx);
					if (error != SECSuccess) {
						cm_log(1, "Error shutting down "
						       "NSS.\n");
					}
					ctx = NULL;
					ec = PR_NO_ACCESS_RIGHTS_ERROR;
				}
				break;
			}
		}
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			fprintf(status, "Error initializing database "
				"'%s': %s.\n",
				entry->cm_key_storage_location, es);
			cm_log(1, "Error initializing database '%s': %s.\n",
			       entry->cm_key_storage_location, es);
		} else {
			fprintf(status, "Error initializing database '%s'.\n",
				entry->cm_key_storage_location);
			cm_log(1, "Error initializing database '%s'.\n",
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
		pmech = CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		cm_requested_key_size = pqg_size(cm_requested_key_size);
		mech = CKM_DSA_KEY_PAIR_GEN;
		pmech = CKM_DSA_PARAMETER_GEN;
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		mech = CKM_EC_KEY_PAIR_GEN;
		pmech = CKM_EC_KEY_PAIR_GEN;
		break;
#endif
	default:
		fprintf(status, "Unknown or unsupported key type.\n");
		cm_log(1, "Unknown or unsupported key type.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		break;
	}
	/* Find the tokens that we might use for key generation. */
	slotlist = PK11_GetAllTokens(mech, PR_TRUE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		fprintf(status, "Error locating token for key generation.\n");
		cm_log(1, "Error locating token for key generation.\n");
		_exit(CM_SUB_STATUS_ERROR_NO_TOKEN);
	}
	/* Walk the list looking for the requested slot, or the first one if
	 * none was requested. */
	slot = NULL;
	for (sle = slotlist->head;
	     ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		if (PK11_IsInternal(sle->slot) &&
		    !PK11_IsInternalKeySlot(sle->slot)) {
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
	if (slot == NULL) {
		fprintf(status, "Error locating token for key generation.\n");
		cm_log(1, "Error locating token for key generation.\n");
		_exit(CM_SUB_STATUS_ERROR_NO_TOKEN);
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
				_exit(CM_SUB_STATUS_ERROR_AUTH);
			}
			PK11_InitPin(slot, NULL, pin ? pin : "");
			ec = PORT_GetError();
			if (ec != 0) {
				es = PR_ErrorToName(ec);
			} else {
				es = NULL;
			}
			if (PK11_NeedUserInit(slot)) {
				if (es != NULL) {
					cm_log(1, "Key generation slot still "
					       "needs user PIN to be set: "
					       "%s.\n", es);
				} else {
					cm_log(1, "Key generation slot still "
					       "needs user PIN to be set.\n");
				}
				PK11_FreeSlotList(slotlist);
				error = NSS_ShutdownContext(ctx);
				if (error != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				switch (ec) {
				case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
					_exit(CM_SUB_STATUS_ERROR_PERMS);
					break;
				default:
					_exit(CM_SUB_STATUS_ERROR_AUTH);
					break;
				}
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
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}
	PK11_SetPasswordFunc(&cm_pin_read_for_key_nss_cb);
	error = PK11_Authenticate(slot, PR_TRUE, &cb_data);
	ec = PORT_GetError();
	if (error != SECSuccess) {
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Error authenticating to key store: %s.\n",
			       es);
		} else {
			cm_log(1, "Error authenticating to key store.\n");
		}
		PK11_FreeSlotList(slotlist);
		error = NSS_ShutdownContext(ctx);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_SUB_STATUS_ERROR_AUTH);
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
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}
	/* Select an initial key size. */
	if (cm_requested_key_size == 0) {
		cm_requested_key_size = CM_DEFAULT_PUBKEY_SIZE;
	}
	cm_key_size = cm_requested_key_size;
retry_gen:
	/* Initialize the parameters. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		/* no parameters */
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		cm_log(1, "Generating domain parameters.\n");
		pqg_ok = SECFailure;
		cm_key_size = pqg_size(cm_key_size);
		retry = 0;
		while (pqg_ok == SECFailure) {
			pqg_params = NULL;
			pqg_verify = NULL;
			while (PK11_PQG_ParamGenV2(cm_key_size,
						   0,
						   64,
						   &pqg_params,
						   &pqg_verify) != SECSuccess) {
				ec = PORT_GetError();
				if (ec != 0) {
					es = PR_ErrorToName(ec);
				} else {
					es = NULL;
				}
				if (es != NULL) {
					cm_log(1,
					       "Error generating params: %s.\n",
					       es);
				} else {
					cm_log(1, "Error generating params.\n");
				}
				if ((ec != SEC_ERROR_BAD_DATA) || (++retry > 10)) {
					PK11_FreeSlotList(slotlist);
					error = NSS_ShutdownContext(ctx);
					if (error != SECSuccess) {
						cm_log(1, "Error shutting down NSS.\n");
					}
					_exit(CM_SUB_STATUS_INTERNAL_ERROR);
				}
				cm_log(1, "Trying again.\n");
				pqg_params = NULL;
				pqg_verify = NULL;
			}
			if (PK11_PQG_VerifyParams(pqg_params, pqg_verify,
						  &pqg_ok) != SECSuccess) {
				ec = PORT_GetError();
				if (ec != 0) {
					es = PR_ErrorToName(ec);
				} else {
					es = NULL;
				}
				if (es != NULL) {
					cm_log(1,
					       "Error verifying params: %s.\n",
					       es);
				} else {
					cm_log(1, "Error verifying params.\n");
				}
				if (++retry > 10) {
					PK11_FreeSlotList(slotlist);
					error = NSS_ShutdownContext(ctx);
					if (error != SECSuccess) {
						cm_log(1, "Error shutting down NSS.\n");
					}
					_exit(CM_SUB_STATUS_INTERNAL_ERROR);
				}
			}
			if (pqg_ok == SECFailure) {
				cm_log(1, "Params are bad.  Retrying.\n");
			}
		}
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		/* no parameters to generate */
		break;
#endif
	default:
		params = NULL;
		break;
	}
	/* Initialize the key generation parameters. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		memset(&rsa_params, 0, sizeof(rsa_params));
		rsa_params.keySizeInBits = cm_key_size;
		rsa_params.pe = CM_DEFAULT_RSA_EXPONENT;
		params = &rsa_params;
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		memset(&dsa_params, 0, sizeof(dsa_params));
		PK11_PQG_GetPrimeFromParams(pqg_params, &dsa_params.prime);
		PK11_PQG_GetSubPrimeFromParams(pqg_params, &dsa_params.subPrime);
		PK11_PQG_GetBaseFromParams(pqg_params, &dsa_params.base);
		params = &dsa_params;
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		memset(&ec_params, 0, sizeof(ec_params));
		if (cm_key_size <= 256)
			ecurve = SECOID_FindOIDByTag(SEC_OID_ANSIX962_EC_PRIME256V1);
		else if (cm_key_size <= 384)
			ecurve = SECOID_FindOIDByTag(SEC_OID_SECG_EC_SECP384R1);
		else
			ecurve = SECOID_FindOIDByTag(SEC_OID_SECG_EC_SECP521R1);
		SEC_ASN1EncodeItem(NULL, &ec_params,
				   &ecurve->oid, SEC_ObjectIDTemplate);
		params = &ec_params;
		break;
#endif
	default:
		params = NULL;
		break;
	}
	/* Generate the key pair. */
	cm_log(1, "Generating key pair.\n");
	pubkey = NULL;
	privkey = PK11_GenerateKeyPair(slot, mech, params, &pubkey,
				       PR_TRUE, PR_TRUE, NULL);
	/* If we're just a bit(s?) short (as opposed to cut off at an arbitrary
	 * limit that's less than 90% of what we asked for), try again. */
	generated_size = SECKEY_PublicKeyStrengthInBits(pubkey);
	if ((generated_size < cm_key_size) &&
	    (generated_size > (cm_key_size * 9 / 10))) {
		cm_log(1, "Ended up with %d instead of %d.  Retrying.\n",
		       SECKEY_PublicKeyStrengthInBits(pubkey), cm_key_size);
		goto retry_gen;
	}
	/* Retry with the optimum key size. */
	if (privkey == NULL) {
		cm_key_size = PK11_GetBestKeyLength(slot, pmech);
		if (cm_key_size != cm_requested_key_size) {
			cm_log(1,
			       "Overriding requested key size of %d with %d.\n",
			       cm_requested_key_size, cm_key_size);
			goto retry_gen;
		}
		ec = PORT_GetError();
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Error generating key pair: %s.\n", es);
		} else {
			cm_log(1, "Error generating key pair.\n");
		}
		switch (ec) {
		case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
			_exit(CM_SUB_STATUS_ERROR_PERMS);
			break;
		default:
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			break;
		}
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
		ec = PORT_GetError();
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Error setting nickname on private key: "
			       "%s.\n", es);
		} else {
			cm_log(1, "Error setting nickname on private key.\n");
		}
		switch (ec) {
		case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
			_exit(CM_SUB_STATUS_ERROR_PERMS);
			break;
		default:
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			break;
		}
	}
	/* Encode the public key to hex, and print it. */
	spki = SECKEY_EncodeDERSubjectPublicKeyInfo(pubkey);
	if (spki != NULL) {
		pubihex = cm_store_hex_from_bin(NULL, spki->data,
						spki->len);
		SECITEM_FreeItem(spki, PR_TRUE);
	} else {
		pubihex = "";
	}
	pubkeyinfo = SECKEY_CreateSubjectPublicKeyInfo(pubkey);
	if (pubkeyinfo != NULL) {
		pubhex = cm_store_hex_from_bin(NULL,
					       pubkeyinfo->subjectPublicKey.data,
					       pubkeyinfo->subjectPublicKey.len / 8);
		SECKEY_DestroySubjectPublicKeyInfo(pubkeyinfo);
	} else {
		pubhex = "";
	}
	fprintf(status, "%s\n%s\n", pubihex, pubhex);
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
cm_keygen_n_ready(struct cm_keygen_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_keygen_n_get_fd(struct cm_keygen_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Tell us if the keypair was saved to the location specified in the entry. */
static int
cm_keygen_n_saved_keypair(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Tell us if we don't have permissions. */
static int
cm_keygen_n_need_perms(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_PERMS)) {
		return 0;
	}
	return -1;
}

/* Tell us if we need a new/correct PIN to use the key store. */
static int
cm_keygen_n_need_pin(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to generate the key. */
static int
cm_keygen_n_need_token(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
static void
cm_keygen_n_done(struct cm_keygen_state *state)
{
	const char *pubkey_info, *p;
	int len;

	if (state->subproc != NULL) {
		pubkey_info = cm_subproc_get_msg(state->subproc, NULL);
		if (pubkey_info != NULL) {
			len = strcspn(pubkey_info, "\r\n");
			state->entry->cm_key_pubkey_info =
				talloc_strndup(state->entry, pubkey_info, len);
			p = pubkey_info + len;
			p += strspn(p, "\r\n");
			len = strcspn(p, "\r\n");
			state->entry->cm_key_pubkey =
				talloc_strndup(state->entry, p, len);
		} else {
			state->entry->cm_key_pubkey_info = NULL;
			state->entry->cm_key_pubkey = NULL;
		}
		cm_subproc_done(state->subproc);
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
		state->pvt.need_perms = cm_keygen_n_need_perms;
		state->pvt.need_pin = cm_keygen_n_need_pin;
		state->pvt.need_token = cm_keygen_n_need_token;
		state->pvt.done = cm_keygen_n_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_keygen_n_main, state,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
