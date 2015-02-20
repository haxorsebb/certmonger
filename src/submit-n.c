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

#include <openssl/err.h>
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

static PRBool
decryption_allowed(SECAlgorithmID *algid, PK11SymKey *bulkkey)
{
	return PR_TRUE;
}

static SEC_PKCS7ContentInfo *
try_to_decode(void *parent, SECItem *item, SECKEYPrivateKey *pkey)
{
	SEC_PKCS7ContentInfo *ret = NULL;
	CERTCertificate *cert = NULL, **certs = NULL;
	CERTCertificateRequest *req = NULL;
	CERTSubjectPublicKeyInfo *spki = NULL;
	CERTValidity *validity = NULL;
	SECKEYPublicKey *pubkey = NULL;
	CERTName *name = NULL;
	CERTSignedData sdata;
	SECOidData *oid;
	SECItem sitem, ditem, *sder;
	PKCS7 *p7 = NULL;
	PKCS7_RECIP_INFO *p7i = NULL;
	X509 *x = NULL;
	char buf[BUFSIZ], *n;
	const unsigned char *u;
	unsigned char *p;
	int len;
	long error;

	memset(&sitem, 0, sizeof(sitem));
	memset(&sdata, 0, sizeof(sdata));
	memset(&ditem, 0, sizeof(ditem));
	pubkey = SECKEY_ConvertToPublicKey(pkey);
	if (pubkey == NULL) {
		cm_log(1, "Failure obtaining public key: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	spki = SECKEY_CreateSubjectPublicKeyInfo(pubkey);
	if (spki == NULL) {
		cm_log(1, "Failure creating dummy SPKI: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	n = talloc_asprintf(parent, "cn=%.*s", 64,
			    cm_store_hex_from_bin(parent,
						  spki->subjectPublicKey.data,
						  spki->subjectPublicKey.len));
	name = CERT_AsciiToName(n);
	if (name == NULL) {
		goto done;
	}
	req = CERT_CreateCertificateRequest(name, spki, NULL);
	if (req == NULL) {
		cm_log(1, "Failure creating dummy CSR: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	validity = CERT_CreateValidity(PR_Now() - WINDOW, PR_Now() + WINDOW);
	if (validity == NULL) {
		cm_log(1, "Failure creating validity: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	cert = CERT_CreateCertificate(1, name, validity, req);
	if (cert == NULL) {
		cm_log(1, "Error encoding dummy certificate: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	SEC_ASN1EncodeInteger(NULL, &cert->version, 2);
	oid = SECOID_FindOIDByTag(cm_prefs_nss_sig_alg(pkey));
	if (SECOID_SetAlgorithmID(NULL, &cert->signature,
				  oid->offset, NULL) != SECSuccess) {
		cm_log(1, "Unable to set signature algorithm ID: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	cert->issuer = *name;
	cert->subject = *name;
	cert->subjectPublicKeyInfo = req->subjectPublicKeyInfo;
	if (SEC_ASN1EncodeItem(NULL, &sdata.data, cert,
			       CERT_CertificateTemplate) != &sdata.data) {
		cm_log(1, "Error encoding dummy certificate: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	if (SECOID_SetAlgorithmID(NULL, &sdata.signatureAlgorithm,
				  oid->offset, NULL) != SECSuccess) {
		cm_log(1, "Unable to set signature algorithm ID: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	if (SEC_SignData(&sdata.signature, sdata.data.data, sdata.data.len,
			 pkey, oid->offset) != SECSuccess) {
		cm_log(1, "Error signing dummy certificate: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	sdata.signature.len *= 8;
	if (SEC_ASN1EncodeItem(NULL, &sitem, &sdata,
			       CERT_SignedDataTemplate) != &sitem) {
		cm_log(1, "Error encoding signed dummy certificate: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	u = sitem.data;
	x = d2i_X509(NULL, &u, sitem.len);
	if (x == NULL) {
		cm_log(1, "Error decoding signed dummy certificate: %s\n",
		       cm_store_base64_from_bin(NULL, sitem.data, sitem.len));
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		goto done;
	}
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
	PKCS7_RECIP_INFO_set(p7i, x);
	len = i2d_PKCS7(p7, NULL);
	if (SECITEM_AllocItem(NULL, &ditem, len) != &ditem) {
		cm_log(1, "Error allocating memory.\n");
		goto done;
	}
	p = ditem.data;
	if (i2d_PKCS7(p7, &p) == len) {
		ditem.len = len;
	} else {
		cm_log(1, "Error encoding dummy enveloped-data.\n");
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		goto done;
	}
	sder = &sitem;
	if (CERT_ImportCerts(CERT_GetDefaultCertDB(), certUsageEmailRecipient,
			     1, &sder, &certs, PR_FALSE, PR_FALSE,
			     NULL) != SECSuccess) {
		cm_log(1, "Error importing dummy certificate.\n");
		goto done;
	}
	ret = SEC_PKCS7DecodeItem(&ditem, NULL, NULL, NULL, NULL, NULL, NULL,
				  decryption_allowed);
done:
	if (x != NULL) {
		X509_free(x);
	}
	if (p7 != NULL) {
		PKCS7_free(p7);
	}
	if (sdata.data.data != NULL) {
		SECITEM_FreeItem(&sdata.data, PR_FALSE);
	}
	if (ditem.data != NULL) {
		SECITEM_FreeItem(&ditem, PR_FALSE);
	}
	if (sitem.data != NULL) {
		SECITEM_FreeItem(&sitem, PR_FALSE);
	}
	if (certs != NULL) {
		CERT_DestroyCertificate(certs[0]);
		PORT_Free(certs);
	}
	if (cert != NULL) {
		CERT_DestroyCertificate(cert);
	}
	if (validity != NULL) {
		CERT_DestroyValidity(validity);
	}
	if (req != NULL) {
		CERT_DestroyCertificateRequest(req);
	}
	if (spki != NULL) {
		SECKEY_DestroySubjectPublicKeyInfo(spki);
	}
	if (pubkey != NULL) {
		SECKEY_DestroyPublicKey(pubkey);
	}
	if (name != NULL) {
		CERT_DestroyName(name);
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
	SEC_PKCS7ContentInfo *ci = NULL;

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
				ci = try_to_decode(args->entry, &item,
						   kle->key);
				if (ci != NULL) {
					break;
				}
			}
		}
	}
	if (ci == NULL) {
		cm_log(1, "Error decrypting enveloped data: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}

	/* Recover the plaintext. */
	plain = SEC_PKCS7GetContent(ci);
	if (plain == NULL) {
		cm_log(1, "Error retrieving plain: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		goto done;
	}
	cm_log(1, "Succeeded in decrypting enveloped data.\n");
	*payload = talloc_size(args->entry, item.len + 1);
	if (*payload != NULL) {
		memcpy(*payload, item.data, item.len);
		(*payload)[item.len] = '\0';
		*payload_length = item.len;
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
