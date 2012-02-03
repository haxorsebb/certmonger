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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>
#include <prerror.h>

#include <krb5.h>

#include <talloc.h>

#include "certext.h"
#include "certext-n.h"
#include "certread.h"
#include "certread-int.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"

struct cm_certread_state {
	struct cm_certread_state_pvt pvt;
	struct cm_subproc_state *subproc;
};
struct cm_certread_n_settings {
	int readwrite:1;
};

static int
cm_certread_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	int status = 1, readwrite;
	const char *token;
	char *pin;
	PLArenaPool *arena;
	SECStatus error;
	NSSInitContext *ctx;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	CERTCertList *certs;
	CERTCertListNode *node;
	CERTCertificate *cert;
	CK_MECHANISM_TYPE mech;
	struct cm_certread_n_settings *settings;
	struct cm_pin_cb_data cb_data;
	PRTime before_a, after_a, before_b, after_b;
	FILE *fp;
	/* Open the status descriptor for stdio. */
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		cm_log(1, "Unable to initialize I/O.\n");
		_exit(1);
	}
	/* Open the database. */
	settings = userdata;
	readwrite = settings->readwrite;
	ctx = NSS_InitContext(entry->cm_cert_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	if (ctx == NULL) {
		cm_log(1, "Unable to open NSS database.\n");
		_exit(1);
	}
	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Error opening database '%s'.\n",
		       entry->cm_cert_storage_location);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(ENOMEM);
	}
	/* Find the tokens that we might use for cert storage. */
	mech = CKM_RSA_X_509;
	slotlist = PK11_GetAllTokens(mech, PR_FALSE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		cm_log(1, "Error getting list of tokens.\n");
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}
	/* Walk the list looking for the requested slot, or the first one if
	 * none was requested. */
	cert = NULL;
	if (cm_pin_read_for_cert(entry, &pin) != 0) {
		cm_log(1, "Error reading PIN for cert db.\n");
		_exit(CM_STATUS_ERROR_AUTH);
	}
	PK11_SetPasswordFunc(&cm_pin_read_for_cert_nss_cb);
	for (sle = slotlist->head;
	     ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		/* Log the slot's name. */
		token = PK11_GetTokenName(sle->slot);
		if (token != NULL) {
			cm_log(3, "Found token '%s'.\n", token);
		} else {
			cm_log(3, "Found unnamed token.\n");
		}
		/* If we're looking for a specific slot, and this isn't it,
		 * keep going. */
		if ((entry->cm_cert_token != NULL) &&
		    (strlen(entry->cm_cert_token) != 0) &&
		    ((token == NULL) ||
		     (strcmp(entry->cm_cert_token, token) != 0))) {
			if (token != NULL) {
				cm_log(1,
				       "Token is named \"%s\", not \"%s\", "
				       "skipping.\n",
				       token, entry->cm_cert_token);
			} else {
				cm_log(1,
				       "Token is unnamed, not \"%s\", "
				       "skipping.\n",
				       entry->cm_cert_token);
			}
			goto next_slot;
		}
		/* Be ready to count our uses of a PIN. */
		memset(&cb_data, 0, sizeof(cb_data));
		cb_data.entry = entry;
		cb_data.n_attempts = 0;
		/* If we're supposed to be using a PIN, and we're offered a
		 * chance to set one, do it now. */
		if (readwrite) {
			if (PK11_NeedUserInit(sle->slot)) {
				if (cm_pin_read_for_cert(entry, &pin) != 0) {
					cm_log(1, "Error reading PIN to assign "
					       "to storage slot, skipping.\n");
					goto next_slot;
				}
				PK11_InitPin(sle->slot, NULL, pin);
				if (PK11_NeedUserInit(sle->slot)) {
					cm_log(1, "Cert storage slot still "
					       "needs user PIN to be set.\n");
					goto next_slot;
				}
				/* We're authenticated now, so count this as a
				 * use of the PIN. */
				cb_data.n_attempts++;
			}
		}
		/* If we need to log in in order to read certificates, do so. */
		if (PK11_NeedLogin(sle->slot)) {
			if (cm_pin_read_for_cert(entry, &pin) != 0) {
				cm_log(1, "Error reading PIN for cert db, "
				       "skipping.\n");
				goto next_slot;
			}
			error = PK11_Authenticate(sle->slot, PR_TRUE, &cb_data);
			if (error != SECSuccess) {
				cm_log(1, "Error authenticating to cert db.\n");
				goto next_slot;
			}
			if ((pin != NULL) &&
			    (strlen(pin) > 0) &&
			    (cb_data.n_attempts == 0)) {
				cm_log(1, "PIN was not needed to auth to cert "
				       "db, though one was provided. "
				       "Treating this as an error.\n");
				goto next_slot;
			}
		}
		/* Walk the list of certificates in the slot, looking for one
		 * which matches the specified nickname. */
		certs = PK11_ListCertsInSlot(sle->slot);
		if (certs != NULL) {
			for (node = CERT_LIST_HEAD(certs);
			     !CERT_LIST_EMPTY(certs) &&
			     !CERT_LIST_END(node, certs);
			     node = CERT_LIST_NEXT(node)) {
				if (strcmp(node->cert->nickname,
					   entry->cm_cert_nickname) == 0) {
					cm_log(3, "Located the certificate "
					       "\"%s\".\n",
					       entry->cm_cert_nickname);
					if (entry->cm_cert_token == NULL) {
						entry->cm_cert_token =
							talloc_strdup(entry,
								      token);
					}
					if (cert == NULL) {
						cert = CERT_DupCertificate(node->cert);
					} else {
						if ((CERT_GetCertTimes(node->cert, &before_a, &after_a) == SECSuccess) &&
						    (CERT_GetCertTimes(cert, &before_b, &after_b) == SECSuccess) &&
						    (after_a > after_b)) {
							cm_log(3, "Located a newer certificate "
							       "\"%s\".\n",
							       entry->cm_cert_nickname);
							if (readwrite &&
							    (before_a > before_b)) {
								error = SEC_DeletePermCertificate(cert);
								if (error != SECSuccess) {
									cm_log(3, "Error deleting old certificate: %s.\n",
									       PR_ErrorToString(error, PR_LANGUAGE_I_DEFAULT));
								}
							}
							CERT_DestroyCertificate(cert);
							cert = CERT_DupCertificate(node->cert);
						}
					}
				}
			}
			CERT_DestroyCertList(certs);
		}
next_slot:
		if (sle == slotlist->tail) {
			break;
		}
	}

	if (cert == NULL) {
		cm_log(1, "Error locating certificate.\n");
		PK11_FreeSlotList(slotlist);
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}
	cm_certread_n_parse(entry, cert->derCert.data, cert->derCert.len);
	cm_certread_write_data_to_pipe(entry, fp);
	fclose(fp);
	CERT_DestroyCertificate(cert);
	PK11_FreeSlotList(slotlist);
	PORT_FreeArena(arena, PR_TRUE);
	if (NSS_ShutdownContext(ctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	if (status != 0) {
		_exit(status);
	}
	return 0;
}

/* Parse the certificate in the entry, and refresh the certificate-based
 * fields. */
void
cm_certread_n_parse(struct cm_store_entry *entry,
		    unsigned char *der_cert, unsigned int der_cert_len)
{
	PLArenaPool *arena;
	SECItem item, *items;
	CERTCertificate *cert, **certs;
	NSSInitContext *ctx;
	char *p;
	const char *nl;
	unsigned int i;

	/* Initialize the library. */
	ctx = NSS_InitContext(CM_DEFAULT_CERT_STORAGE_LOCATION,
			      NULL, NULL, NULL, NULL,
			      NSS_INIT_NOCERTDB |
			      NSS_INIT_READONLY |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	if (ctx == NULL) {
		cm_log(1, "Unable to initialize NSS.\n");
		_exit(1);
	}
	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Error opening database '%s'.\n",
		       entry->cm_cert_storage_location);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(ENOMEM);
	}
	/* Decode the certificate. */
	item.data = der_cert;
	item.len = der_cert_len;
	items = &item;
	certs = NULL;
	if ((CERT_ImportCerts(CERT_GetDefaultCertDB(), 0,
			      1, &items, &certs, PR_FALSE, PR_FALSE,
			      "temp") != SECSuccess) ||
	    (certs == NULL)) {
		cm_log(1, "Error decoding certificate.\n");
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(1);
	}
	cert = certs[0];
	/* Pick out the interesting bits. */
	/* Issuer name */
	talloc_free(entry->cm_cert_issuer);
	entry->cm_cert_issuer = talloc_strdup(entry, cert->issuerName);
	/* Serial number */
	talloc_free(entry->cm_cert_serial);
	item = cert->serialNumber;
	entry->cm_cert_serial = talloc_zero_size(entry, item.len * 2 + 1);
	for (i = 0; i < item.len; i++) {
		sprintf(entry->cm_cert_serial + i * 2, "%02x",
			item.data[i] & 0xff);
	}
	/* Subject name */
	talloc_free(entry->cm_cert_subject);
	entry->cm_cert_subject = talloc_strdup(entry, cert->subjectName);
	/* Subject Public Key Info, encoded into a blob. */
	talloc_free(entry->cm_cert_spki);
	if (SEC_ASN1EncodeItem(arena, items, &cert->subjectPublicKeyInfo,
			       CERT_SubjectPublicKeyInfoTemplate) != items) {
		cm_log(1, "Error encoding subjectPublicKeyInfo.\n");
		CERT_DestroyCertArray(certs, 1);
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(1);
	}
	entry->cm_cert_spki = talloc_zero_size(entry, items->len * 2 + 1);
	for (i = 0; i < items->len; i++) {
		sprintf(entry->cm_cert_spki + i * 2, "%02x",
			items->data[i] & 0xff);
	}
	/* Not-before date. */
	p = talloc_strndup(entry, (char *) cert->validity.notBefore.data,
			   cert->validity.notBefore.len);
	if (p != NULL) {
		entry->cm_cert_not_before = cm_store_time_from_timestamp(p);
	} else {
		entry->cm_cert_not_before = 0;
	}
	/* Not-after date. */
	p = talloc_strndup(entry, (char *) cert->validity.notAfter.data,
			   cert->validity.notAfter.len);
	if (p != NULL) {
		entry->cm_cert_not_after = cm_store_time_from_timestamp(p);
	} else {
		entry->cm_cert_not_after = 0;
	}
	/* Hostname from subjectAltName extension. */
	talloc_free(entry->cm_cert_hostname);
	entry->cm_cert_hostname = NULL;
	/* Email address from subjectAltName extension. */
	talloc_free(entry->cm_cert_email);
	entry->cm_cert_email = NULL;
	/* Principal name from subjectAltName extension. */
	talloc_free(entry->cm_cert_principal);
	entry->cm_cert_principal = NULL;
	/* Key usage from keyUsage extension. */
	talloc_free(entry->cm_cert_ku);
	entry->cm_cert_ku = NULL;
	/* Extended key usage from extendedKeyUsage extension. */
	talloc_free(entry->cm_cert_eku);
	entry->cm_cert_eku = NULL;
	/* Parse the extensions. */
	cm_certext_read_extensions(entry, arena, cert->extensions);
	/* The certificate itself. */
	p = NSSBase64_EncodeItem(arena, NULL, 0, &cert->derCert);
	if (p != NULL) {
		i = strlen(p);
		if ((i > 0) && (p[i - 1] != '\n')) {
			nl = "\n";
		} else {
			nl = "";
		}
		talloc_free(entry->cm_cert);
		p = talloc_asprintf(entry, "%s%s%s%s",
				    "-----BEGIN CERTIFICATE-----\n",
				    p, nl,
				    "-----END CERTIFICATE-----\n");
		entry->cm_cert = p;
	}
	/* Clean up. */
	CERT_DestroyCertArray(certs, 1);
	PORT_FreeArena(arena, PR_TRUE);
	if (NSS_ShutdownContext(ctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
}

/* Check if something changed, for example we finished reading the data we need
 * from the cert. */
static int
cm_certread_n_ready(struct cm_store_entry *entry,
		    struct cm_certread_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certread_n_get_fd(struct cm_store_entry *entry,
		     struct cm_certread_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Clean up after reading the certificate. */
static void
cm_certread_n_done(struct cm_store_entry *entry,
		   struct cm_certread_state *state)
{
	if (state->subproc != NULL) {
		cm_certread_read_data_from_buffer(entry,
						  cm_subproc_get_msg(entry,
								     state->subproc,
								     NULL));
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}

/* Start reading the certificate from the configured location. */
struct cm_certread_state *
cm_certread_n_start(struct cm_store_entry *entry)
{
	struct cm_certread_state *state;
	struct cm_certread_n_settings settings = {
		.readwrite = 1,
	};
	if (entry->cm_cert_storage_type != cm_cert_storage_nssdb) {
		cm_log(1, "Wrong read method: can only read certificates "
		       "from an NSS database.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_certread_n_ready;
		state->pvt.get_fd= cm_certread_n_get_fd;
		state->pvt.done= cm_certread_n_done;
		state->subproc = cm_subproc_start(cm_certread_n_main,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
