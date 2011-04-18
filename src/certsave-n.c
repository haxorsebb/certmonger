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
#include <stdlib.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>
#include <prerror.h>

#include <talloc.h>

#include "certsave.h"
#include "certsave-int.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"

struct cm_certsave_state {
	struct cm_certsave_state_pvt pvt;
	struct cm_subproc_state *subproc;
};
struct cm_certsave_n_settings {
	unsigned int readwrite:1;
};

static int
cm_certsave_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	int status = 1, readwrite, i;
	PLArenaPool *arena;
	SECStatus error;
	SECItem *item, subject, nickname, newsubj, newnick, label;
	char *p, *q, *pin;
	const char *token;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	CK_MECHANISM_TYPE mech;
	CERTSignedData scert;
	CERTCertificate cert;
	PK11GenericObject *obj, *objlist;
	CK_OBJECT_CLASS objclass;
	CK_CERTIFICATE_TYPE objtype;
	CK_BBOOL objtoken;
	CK_ATTRIBUTE *objtemplate;
	struct cm_certsave_n_settings *settings;
	/* Open the database. */
	settings = userdata;
	readwrite = settings->readwrite;
	error = readwrite ? NSS_InitReadWrite(entry->cm_cert_storage_location) :
			    NSS_Init(entry->cm_cert_storage_location);
	if (error != SECSuccess) {
		cm_log(1, "Unable to open NSS database '%s'.\n",
		       entry->cm_cert_storage_location);
	} else {
		/* Allocate a memory pool. */
		arena = PORT_NewArena(sizeof(double));
		if (arena == NULL) {
			cm_log(1, "Error opening database '%s'.\n",
			       entry->cm_cert_storage_location);
			if (NSS_Shutdown() != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(ENOMEM);
		}
		/* Find the tokens that we might use for cert storage. */
		mech = 0;
		slotlist = PK11_GetAllTokens(mech, PR_FALSE, PR_FALSE, NULL);
		if (slotlist == NULL) {
			cm_log(1, "Error getting list of tokens.\n");
			PORT_FreeArena(arena, PR_TRUE);
			if (NSS_Shutdown() != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(2);
		}
		/* Find the data between the header and footer. */
		p = entry->cm_cert;
		q = NULL;
		if (p != NULL) {
			while (strncmp(p, "-----BEGIN ", 11) == 0) {
				p += strcspn(p, "\r\n");
				p += strspn(p, "\r\n");
			}
			q = strstr(p, "-----END");
		}
		if ((q == NULL) || (*p == '\0')) {
			cm_log(1, "Unable to parse certificate.\n");
			PK11_FreeSlotList(slotlist);
			PORT_FreeArena(arena, PR_TRUE);
			if (NSS_Shutdown() != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(1);
		}
		/* Handle the base64 decode. */
		item = NSSBase64_DecodeBuffer(arena, NULL, p, q - p);
		if (item == NULL) {
			cm_log(1, "Unable to decode certificate "
			       "into buffer.\n");
			PK11_FreeSlotList(slotlist);
			PORT_FreeArena(arena, PR_TRUE);
			if (NSS_Shutdown() != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(1);
		}
		/* Parse the certificate. */
		memset(&scert, 0, sizeof(scert));
		memset(&cert, 0, sizeof(cert));
		if (SEC_ASN1DecodeItem(arena, &scert,
				       CERT_SignedDataTemplate,
				       item) != SECSuccess) {
			cm_log(1, "Error decoding certificate (1).\n");
			goto next_slot;
		}
		if (SEC_ASN1DecodeItem(arena, &cert,
				       CERT_CertificateTemplate,
				       &scert.data) != SECSuccess) {
			cm_log(1, "Error decoding certificate (2).\n");
			goto next_slot;
		}
		/* Walk the list looking for the requested slot, or the first
		 * one if none was requested. */
		if (cm_pin_read_for_cert(entry, &pin) != 0) {
			cm_log(1, "Error reading PIN for cert db.\n");
			PK11_FreeSlotList(slotlist);
			PORT_FreeArena(arena, PR_TRUE);
			if (NSS_Shutdown() != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
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
			/* If we're looking for a specific slot, and this isn't
			 * it, keep going. */
			if ((entry->cm_cert_token != NULL) &&
			    (strlen(entry->cm_cert_token) != 0) &&
			    ((token == NULL) ||
			     (strcmp(entry->cm_cert_token, token) != 0))) {
				if (token != NULL) {
					cm_log(1,
					       "Token is named \"%s\", "
					       "not \"%s\".\n",
					       token, entry->cm_key_token);
				} else {
					cm_log(1,
					       "Token is unnamed, "
					       "not \"%s\".\n",
					       entry->cm_key_token);
				}
				goto next_slot;
			}
			/* If we're supposed to be using a PIN, and we're
			 * offered a chance to set one, do it now. */
			if (PK11_NeedUserInit(sle->slot)) {
				if (cm_pin_read_for_cert(entry, &pin) != 0) {
					cm_log(1, "Error reading PIN to assign "
					       "to storage slot \"%s\", "
					       "skipping.\n", token);
					goto next_slot;
				}
				if (pin != NULL) {
					PK11_InitPin(sle->slot, NULL, pin);
					if (PK11_NeedUserInit(sle->slot)) {
						cm_log(1,
						       "Cert storage slot "
						       "\"%s\" still needs "
						       "user PIN to be set.\n",
						       token);
					}
				}
			}
			/* If we need to log in in order to use the token, do
			 * so. */
			if (PK11_NeedLogin(sle->slot)) {
				if (cm_pin_read_for_cert(entry, &pin) != 0) {
					cm_log(1, "Error reading PIN for cert "
					       "db, skipping.\n");
					goto next_slot;
				}
				error = PK11_Authenticate(sle->slot, PR_TRUE,
							  entry);
				if (error != SECSuccess) {
					cm_log(1, "Error authenticating to "
					       "cert db.\n");
					goto next_slot;
				}
			}
			/* Look for potential problems. */
			newsubj = cert.derSubject;
			newnick.data = entry->cm_cert_nickname;
			newnick.len = strlen(entry->cm_cert_nickname);
			objlist = PK11_FindGenericObjects(sle->slot,
							  CKO_CERTIFICATE);
			obj = objlist;
			while (obj != NULL) {
				memset(&subject, 0, sizeof(subject));
				memset(&nickname, 0, sizeof(nickname));
				if (PK11_ReadRawAttribute(PK11_TypeGeneric,
							  obj,
							  CKA_SUBJECT,
							  &subject) !=
				    SECSuccess) {
					continue;
				}
				if (PK11_ReadRawAttribute(PK11_TypeGeneric,
							  obj,
							  CKA_LABEL,
							  &nickname) !=
				    SECSuccess) {
					SECITEM_FreeItem(&subject, PR_FALSE);
					continue;
				}
				/* We have a potential problem if:
				 * a) there's a certificate with the same
				 *    subject but a different nickname */
				if (SECITEM_ItemsAreEqual(&subject,
							  &newsubj) &&
				    !SECITEM_ItemsAreEqual(&nickname,
							   &newnick)) {
					cm_log(1,
					       "Certificate with nickname "
					       "\"%.*s\" has the same subject "
					       "as certificate to be nicknamed "
					       "\"%s\".\n",
					       nickname.len, nickname.data,
					       entry->cm_cert_nickname);
					PK11_DestroyGenericObjects(objlist);
					goto next_slot;
				}
				/* b) there's a certificate with the same
				 *    nickname */
				if (SECITEM_ItemsAreEqual(&nickname,
							  &newnick)) {
					memset(&label, 0, sizeof(label));
					label.data = PORT_ArenaZAlloc(arena,
								      newnick.len + 32);
					if (label.data == NULL) {
						cm_log(1, "Out of memory.\n");
						PK11_DestroyGenericObjects(objlist);
						goto next_slot;
					}
					sprintf(label.data, "%.*s #2",
						newnick.len,
						newnick.data);
					label.len = strlen(label.data);
					if (PK11_WriteRawAttribute(PK11_TypeGeneric,
								   obj,
								   CKA_LABEL,
								   &label) ==
					    SECSuccess) {
						cm_log(1,
						       "Renamed certificate "
						       "with nickname "
						       "\"%.*s\" to \"%.*s\".\n",
						       nickname.len,
						       nickname.data,
						       label.len,
						       label.data);
						break;
					} else {
						cm_log(1, "Error "
						       "renaming certificate "
						       "with nickname "
						       "\"%.*s\": %s.\n",
						       nickname.len,
						       nickname.data,
						       PR_ErrorToString(PORT_GetError(),
									PR_LANGUAGE_I_DEFAULT));
						PK11_DestroyGenericObjects(objlist);
						goto next_slot;
					}
				}
				SECITEM_FreeItem(&subject, PR_FALSE);
				SECITEM_FreeItem(&nickname, PR_FALSE);
				obj = PK11_GetNextGenericObject(obj);
			}
			PK11_DestroyGenericObjects(objlist);
			/* Add the certificate. */
			objtemplate = PORT_ArenaZAlloc(arena,
						       8 * sizeof(*objtemplate));
			if (objtemplate == NULL) {
				cm_log(1, "Out of memory.\n");
				goto next_slot;
			}
			objclass = CKO_CERTIFICATE;
			objtemplate[0].type = CKA_CLASS;
			objtemplate[0].pValue = &objclass;
			objtemplate[0].ulValueLen = sizeof(objclass);
			objtoken = CK_TRUE;
			objtemplate[1].type = CKA_TOKEN;
			objtemplate[1].pValue = &objtoken;
			objtemplate[1].ulValueLen = sizeof(objtoken);
			objtype = CKC_X_509;
			objtemplate[2].type = CKA_CERTIFICATE_TYPE;
			objtemplate[2].pValue = &objtype;
			objtemplate[2].ulValueLen = sizeof(objtype);
			objtemplate[3].type = CKA_ISSUER;
			objtemplate[3].pValue = cert.derIssuer.data,
			objtemplate[3].ulValueLen = cert.derIssuer.len,
			objtemplate[4].type = CKA_SERIAL_NUMBER;
			objtemplate[4].pValue = cert.serialNumber.data,
			objtemplate[4].ulValueLen = cert.serialNumber.len,
			objtemplate[5].type = CKA_SUBJECT;
			objtemplate[5].pValue = cert.derSubject.data;
			objtemplate[5].ulValueLen = cert.derSubject.len;
			objtemplate[6].type =  CKA_LABEL;
			objtemplate[6].pValue = entry->cm_cert_nickname;
			objtemplate[6].ulValueLen = strlen(entry->cm_cert_nickname);
			objtemplate[7].type =  CKA_VALUE;
			objtemplate[7].pValue = item->data;
			objtemplate[7].ulValueLen = item->len;
			obj = PK11_CreateGenericObject(sle->slot,
						       objtemplate,
						       8,
						       PR_TRUE);
			if (obj != NULL) {
				PK11_DestroyGenericObject(obj);
				status = 0;
			} else {
				cm_log(0, "Error saving certificate \"%s\" "
				       "to token \"%s\": %s.\n",
				       entry->cm_cert_nickname,
				       token,
				       PR_ErrorToString(PORT_GetError(),
						        PR_LANGUAGE_I_DEFAULT));
				goto next_slot;
			}
			break;
next_slot:
			if (sle == slotlist->tail) {
				break;
			}
		}
		PK11_FreeSlotList(slotlist);
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_Shutdown() != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
	}
	if (status != 0) {
		_exit(status);
	}
	return 0;
}

/* Check if something changed, for example we finished saving the cert. */
static int
cm_certsave_n_ready(struct cm_store_entry *entry,
		    struct cm_certsave_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certsave_n_get_fd(struct cm_store_entry *entry,
		     struct cm_certsave_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Check if we saved the certificate -- the child exited with status 0. */
static int
cm_certsave_n_saved(struct cm_store_entry *entry,
		    struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
		return -1;
	}
	return 0;
}

/* Clean up after saving the certificate. */
static void
cm_certsave_n_done(struct cm_store_entry *entry,
		   struct cm_certsave_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}

/* Start writing the certificate from the entry to the configured location. */
struct cm_certsave_state *
cm_certsave_n_start(struct cm_store_entry *entry)
{
	struct cm_certsave_state *state;
	struct cm_certsave_n_settings settings = {
		.readwrite = 1,
	};
	if (entry->cm_cert_storage_type != cm_cert_storage_nssdb) {
		cm_log(1, "Wrong save method: can only save certificates "
		       "to an NSS database.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_certsave_n_ready;
		state->pvt.get_fd= cm_certsave_n_get_fd;
		state->pvt.saved= cm_certsave_n_saved;
		state->pvt.done= cm_certsave_n_done;
		state->subproc = cm_subproc_start(cm_certsave_n_main,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
