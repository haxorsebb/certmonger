/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include <cert.h>
#include <certdb.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secpkcs7.h>

#include <krb5.h>

#include <talloc.h>

#include "store-int.h"
#include "keyiread-n.h"
#include "log.h"
#include "pin.h"
#include "prefs-n.h"
#include "store.h"
#include "submit.h"
#include "submit-e.h"
#include "submit-int.h"
#include "submit-u.h"
#include "subproc.h"
#include "util-n.h"
#include "util-o.h"

#define PRIVKEY_LIST_EMPTY(l) PRIVKEY_LIST_END(PRIVKEY_LIST_HEAD(l), l)
#define WINDOW (24 * 60 * 60 * PR_USEC_PER_SEC)

SECOidTag
cm_submit_n_tag_from_nid(int nid)
{
	ASN1_OBJECT *obj;
	SECItem oid;

	obj = OBJ_nid2obj(nid);
	if (obj != NULL) {
		memset(&oid, 0, sizeof(oid));
		oid.data = (unsigned char *) obj->data;
		oid.len = obj->length;
		return SECOID_FindOIDTag(&oid);
	} else {
		return SEC_OID_UNKNOWN;
	}
}

int
cm_submit_n_nid_from_tag(SECOidTag tag)
{
	SECOidData *oid = SECOID_FindOIDByTag(tag);
	ASN1_OBJECT obj;

	memset(&obj, 0, sizeof(obj));
	obj.data = oid->oid.data;
	obj.length = oid->oid.len;
	return OBJ_obj2nid(&obj);
}

static SECItem *
try_to_decode(void *parent, PLArenaPool *arena, SECItem *item,
	      SECKEYPrivateKey *privkey)
{
	SECOidTag tag;
	SECItem *ret = NULL, param, *parameters;
	ASN1_OBJECT *algorithm;
	int nid, padding;
	CK_MECHANISM_TYPE mech;
	ASN1_STRING *params = NULL;
	PKCS7 *p7 = NULL;
	PKCS7_RECIP_INFO *p7i = NULL;
	BIGNUM *exponent = NULL;
	EVP_PKEY *pkey = NULL;
	BIO *out;
	RSA *rsa = NULL;
	char buf[BUFSIZ];
	const unsigned char *u;
	unsigned char *enc_key, *dec, *reenc;
	unsigned int enc_key_len, dec_len;
	ssize_t reenc_len;
	long error, l;

	/* Do the standard parse and sanity checking. */
	u = item->data;
	p7 = d2i_PKCS7(NULL, &u, item->len);
	if (p7 == NULL) {
		cm_log(1, "Error decoding PKCS#7 enveloped data: %s\n",
		       cm_store_base64_from_bin(NULL, item->data, item->len));
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		goto done;
	}
	if (!PKCS7_type_is_enveloped(p7)) {
		cm_log(1, "PKCS#7 data is not enveloped data.\n");
		goto done;
	}
	if (sk_PKCS7_RECIP_INFO_num(p7->d.enveloped->recipientinfo) != 1) {
		cm_log(1, "PKCS#7 enveloped data is for %d recipients.\n",
		       sk_PKCS7_RECIP_INFO_num(p7->d.enveloped->recipientinfo));
		goto done;
	}
	p7i = sk_PKCS7_RECIP_INFO_value(p7->d.enveloped->recipientinfo, 0);
	if ((p7i->key_enc_algor == NULL) ||
	    (p7i->key_enc_algor->parameter == NULL)) {
		cm_log(1, "PKCS#7 recipient info is missing parameters.\n");
		goto done;
	}

	/* Try to decrypt the bulk key using the private key. */
	algorithm = p7i->key_enc_algor->algorithm;
	nid = OBJ_obj2nid(algorithm);
	tag = cm_submit_n_tag_from_nid(nid);
	mech = PK11_AlgtagToMechanism(tag);
	if (p7i->key_enc_algor->parameter->type == V_ASN1_OCTET_STRING) {
		params = p7i->key_enc_algor->parameter->value.octet_string;
		memset(&param, 0, sizeof(param));
		param.data = M_ASN1_STRING_data(params);
		param.len = M_ASN1_STRING_length(params);
		parameters = &param;
	} else {
		parameters = NULL;
	}
	enc_key = M_ASN1_STRING_data(p7i->enc_key);
	enc_key_len = M_ASN1_STRING_length(p7i->enc_key);
	dec_len = enc_key_len + BUFSIZ;
	dec = talloc_size(parent, dec_len);
	if (parameters == NULL) {
		if (PK11_PrivDecryptPKCS1(privkey,
					  dec, &dec_len, dec_len,
					  enc_key, enc_key_len) != SECSuccess) {
			cm_log(1, "Error decrypting bulk key: %s.\n",
			       PR_ErrorToName(PORT_GetError()));
			goto done;
		}
	} else {
#ifdef HAVE_PK11_PRIVDECRYPT
		if (PK11_PrivDecrypt(privkey, mech, parameters,
				     dec, &dec_len, dec_len,
				     enc_key, enc_key_len) != SECSuccess) {
			cm_log(1, "Error decrypting bulk key: %s.\n",
			       PR_ErrorToName(PORT_GetError()));
			goto done;
		}
#else
		cm_log(1, "Error decrypting bulk key: "
		       "the version of NSS we were built with does not "
		       "support decryption with specified parameters\n");
		goto done;
#endif
	}

	/* Generate a dummy key to use when re-encrypting the bulk key using
	 * OpenSSL so that we can decrypt it again, and with it the payload. */
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		cm_log(1, "Error allocating new key.\n");
		goto done;
	}
	exponent = BN_new();
	if (exponent == NULL) {
		cm_log(1, "Error setting up exponent.\n");
		goto done;
	}
	BN_set_word(exponent, CM_DEFAULT_RSA_EXPONENT);
	rsa = RSA_new();
	if (rsa == NULL) {
		cm_log(1, "Error allocating new RSA key.\n");
		goto done;
	}
retry_gen:
	if (RSA_generate_key_ex(rsa, CM_DEFAULT_PUBKEY_SIZE, exponent, NULL) != 1) {
		cm_log(1, "Error generating key.\n");
		goto done;
	}
	if (RSA_check_key(rsa) != 1) { /* should be unnecessary */
		cm_log(1, "Key fails checks.  Retrying.\n");
		goto retry_gen;
	}
	EVP_PKEY_set1_RSA(pkey, rsa);

	/* Encrypt the bulk key.  We're about to decrypt it again, so do it the
	 * simplest way that we can. */
	reenc_len = dec_len + RSA_size(rsa);
	reenc = talloc_size(parent, reenc_len);
	padding = RSA_PKCS1_PADDING;
	reenc_len = RSA_public_encrypt(dec_len, dec, reenc, rsa, padding);
	if (reenc_len < 0) {
		cm_log(1, "Error reencrypting.\n");
		goto retry_gen;
	}

	/* Set the new encrypted bulk key. */
	p7i->key_enc_algor->algorithm = OBJ_dup(OBJ_nid2obj(NID_rsaEncryption));
	ASN1_TYPE_set(p7i->key_enc_algor->parameter, V_ASN1_NULL, NULL);
	M_ASN1_OCTET_STRING_set(p7i->enc_key, reenc, reenc_len);

	/* And now, finally, decrypt the payload. */
	out = BIO_new(BIO_s_mem());
	if (out == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	if (PKCS7_decrypt(p7, pkey, NULL, out, 0) == 1) {
		u = NULL;
		l = BIO_get_mem_data(out, &u);
		cm_log(1, "Succeeded in decrypting enveloped data.\n");
		if (u != NULL) {
			ret = SECITEM_AllocItem(arena, NULL, l + 1);
			if (ret != NULL) {
				memcpy(ret->data, u, l + 1);
				ret->data[l] = '\0';
				ret->len = l;
			}
		}
	}

done:
	if (ret == NULL) {
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
	}
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	if (exponent != NULL) {
		BN_free(exponent);
	}
	if (p7 != NULL) {
		PKCS7_free(p7);
	}
	return ret;
}

void
cm_submit_n_decrypt_envelope(const unsigned char *envelope,
			     size_t length,
			     void *decrypt_userdata,
			     unsigned char **payload,
			     size_t *payload_length)
{
	const char *token, *reason, *es;
	char *pin;
	PLArenaPool *arena = NULL;
	SECStatus error;
	NSSInitContext *ctx = NULL;
	PK11SlotInfo *slot;
	PK11SlotList *slotlist = NULL;
	PK11SlotListElement *sle;
	SECKEYPrivateKeyList *keylist = NULL;
	SECKEYPrivateKeyListNode *kle = NULL;
	CK_MECHANISM_TYPE mech;
	SECItem item, *plain;
	struct cm_pin_cb_data cb_data;
	int n_tokens, ec;
	struct cm_submit_decrypt_envelope_args *args = decrypt_userdata;

	util_o_init();
	ERR_load_crypto_strings();

	/* Open the database. */
	ctx = NSS_InitContext(args->entry->cm_key_storage_location,
			      NULL, NULL, NULL, NULL,
			      NSS_INIT_READONLY |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	if (ctx == NULL) {
		ec = PORT_GetError();
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Unable to open NSS database '%s': %s.\n",
			       args->entry->cm_key_storage_location, es);
		} else {
			cm_log(1, "Unable to open NSS database '%s'.\n",
			       args->entry->cm_key_storage_location);
		}
		goto done;
	}
	reason = util_n_fips_hook();
	if (reason != NULL) {
		cm_log(1, "Error putting NSS into FIPS mode: %s\n", reason);
		goto done;
	}

	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Out of memory opening database '%s'.\n",
		       args->entry->cm_key_storage_location);
		goto done;
	}

	/* Find the tokens that we might use for key storage. */
	mech = 0;
	slotlist = PK11_GetAllTokens(mech, PR_FALSE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		cm_log(1, "Error locating token to be used for key storage.\n");
		goto done;
	}

	/* Walk the list looking for the requested token, or look at all of
	 * them if none specifically was requested. */
	pin = NULL;
	if (cm_pin_read_for_key(args->entry, &pin) != 0) {
		cm_log(1, "Error reading PIN for key storage.\n");
		goto done;
	}
	PK11_SetPasswordFunc(&cm_pin_read_for_cert_nss_cb);
	n_tokens = 0;
	/* In practice, the internal slot is either a non-storage slot (in
	 * non-FIPS mode) or the database slot (in FIPS mode), and we only want
	 * to skip over the one that can't be used to store things. */
	for (sle = slotlist->head;
	     (sle != NULL) && (sle->slot != NULL);
	     sle = sle->next) {
		slot = sle->slot;
		if (PK11_IsInternal(slot) &&
		    !PK11_IsInternalKeySlot(slot)) {
			cm_log(3, "Skipping NSS internal slot (%s).\n",
			       PK11_GetTokenName(slot));
			goto next_slot;
		}
		/* Read the token's name. */
		token = PK11_GetTokenName(slot);
		if (token != NULL) {
			cm_log(3, "Found token '%s'.\n", token);
		} else {
			cm_log(3, "Found unnamed token.\n");
		}

		/* If this is the wrong token, move on. */
		if ((args->entry->cm_key_token != NULL) &&
		    (strlen(args->entry->cm_key_token) > 0) &&
		    ((token == NULL) ||
		     (strcmp(args->entry->cm_key_token, token) != 0))) {
			if (token != NULL) {
				cm_log(1,
				       "Token is named \"%s\", not \"%s\", "
				       "skipping.\n",
				       token, args->entry->cm_key_token);
			} else {
				cm_log(1,
				       "Token is unnamed, not \"%s\", "
				       "skipping.\n",
				       args->entry->cm_key_token);
			}
			goto next_slot;
		}
		n_tokens++;

		/* Set up args for the PIN callback. */
		memset(&cb_data, 0, sizeof(cb_data));
		cb_data.entry = args->entry;
		cb_data.n_attempts = 0;

		/* Now log in, if we have to. */
		if (cm_pin_read_for_key(args->entry, &pin) != 0) {
			cm_log(1, "Error reading PIN for key storage "
			       "token \"%s\", skipping.\n", token);
			goto done;
		}
		error = PK11_Authenticate(slot, PR_TRUE, &cb_data);
		if (error != SECSuccess) {
			cm_log(1, "Error authenticating to token "
			       "\"%s\".\n", token);
			goto done;
		}
		break;

next_slot:
		/* If this was the last token, stop walking. */
		slot = NULL;
		if (sle == slotlist->tail) {
			break;
		}
	}

	/* Now that we're logged in, try to decrypt the enveloped data. */
	plain = NULL;
	if (slot != NULL) {
		keylist = PK11_ListPrivKeysInSlot(slot, NULL, NULL);
		if (keylist != NULL) {
			memset(&item, 0, sizeof(item));
			item.data = talloc_memdup(args->entry, envelope,
						  length);
			item.len = length;
			for (kle = PRIVKEY_LIST_HEAD(keylist);
			     !PRIVKEY_LIST_EMPTY(keylist) &&
			     !PRIVKEY_LIST_END(kle, keylist);
			     kle = PRIVKEY_LIST_NEXT(kle)) {
				plain = try_to_decode(args->entry, arena, &item,
						      kle->key);
				if (plain != NULL) {
					break;
				}
			}
		}
	}
	if (plain == NULL) {
		cm_log(1, "Error decrypting enveloped data: %s.\n",
		       PR_ErrorToName(PORT_GetError()) ?: "(unknown error)");
		goto done;
	}

	cm_log(1, "Succeeded in decrypting enveloped data.\n");
	*payload = talloc_size(args->entry, plain->len + 1);
	if (*payload != NULL) {
		memcpy(*payload, plain->data, plain->len);
		(*payload)[plain->len] = '\0';
		*payload_length = plain->len;
	}

done:
	if (keylist != NULL) {
		SECKEY_DestroyPrivateKeyList(keylist);
	}
	if (slotlist != NULL) {
		PK11_FreeSlotList(slotlist);
	}
	if (arena != NULL) {
		PORT_FreeArena(arena, PR_TRUE);
	}
	if (ctx != NULL) {
		error = NSS_ShutdownContext(ctx);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
	}
}
