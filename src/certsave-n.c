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
	SECItem *item, subject;
	char *p, *q;
	NSSInitContext *ctx;
	CERTCertDBHandle *certdb;
	CERTCertList *certlist;
	CERTCertificate **returned, cert;
	CERTSignedData csdata;
	CERTCertListNode *node;
	struct cm_certsave_n_settings *settings;
	/* Open the database. */
	settings = userdata;
	readwrite = settings->readwrite;
	ctx = NSS_InitContext(entry->cm_cert_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	if (ctx == NULL) {
		cm_log(1, "Unable to open NSS database '%s'.\n",
		       entry->cm_cert_storage_location);
	} else {
		/* Allocate a memory pool. */
		arena = PORT_NewArena(sizeof(double));
		if (arena == NULL) {
			cm_log(1, "Error opening database '%s'.\n",
			       entry->cm_cert_storage_location);
			if (NSS_ShutdownContext(ctx) != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(CM_STATUS_INTERNAL);
		}
		certdb = CERT_GetDefaultCertDB();
		if (certdb != NULL) {
			/* Strip the header and footer. */
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
				PORT_FreeArena(arena, PR_TRUE);
				if (NSS_ShutdownContext(ctx) != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(CM_STATUS_INTERNAL);
			}
			/* Handle the base64 decode. */
			item = NSSBase64_DecodeBuffer(arena, NULL, p, q - p);
			if (item == NULL) {
				cm_log(1, "Unable to decode certificate "
				       "into buffer.\n");
				PORT_FreeArena(arena, PR_TRUE);
				if (NSS_ShutdownContext(ctx) != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(CM_STATUS_INTERNAL);
			}
			/* Do a "shallow" decode to pull out the subject name
			 * so that we can check for a conflict. */
			memset(&csdata, 0, sizeof(csdata));
			if (SEC_ASN1DecodeItem(arena, &csdata,
					       CERT_SignedDataTemplate,
					       item) != SECSuccess) {
				cm_log(1, "Unable to decode certificate "
				       "signed data into buffer.\n");
				PORT_FreeArena(arena, PR_TRUE);
				if (NSS_ShutdownContext(ctx) != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(CM_STATUS_INTERNAL);
			}
			memset(&cert, 0, sizeof(cert));
			if (SEC_ASN1DecodeItem(arena, &cert,
					       CERT_CertificateTemplate,
					       &csdata.data) != SECSuccess) {
				cm_log(1, "Unable to decode certificate "
				       "data into buffer.\n");
				PORT_FreeArena(arena, PR_TRUE);
				if (NSS_ShutdownContext(ctx) != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(CM_STATUS_INTERNAL);
			}
			subject = cert.derSubject;
			/* Ask NSS if there would be a conflict. */
			if (SEC_CertNicknameConflict(entry->cm_cert_nickname,
						     &subject,
						     certdb)) {
				/* Delete the certificate that's already there
				 * with the nickname we want, otherwise our
				 * cert with a different subject name will be
				 * discarded. */
				certlist = PK11_FindCertsFromNickname(entry->cm_cert_nickname,
								      NULL);
				if (certlist != NULL) {
					/* Look for certs with different
					 * subject names. */
					for (node = CERT_LIST_HEAD(certlist);
					     (node != NULL) &&
					     !CERT_LIST_EMPTY(certlist) &&
					     !CERT_LIST_END(node, certlist);
					     node = CERT_LIST_NEXT(node)) {
						if (!SECITEM_ItemsAreEqual(&subject,
									   &node->cert->derSubject)) {
							cm_log(3, "Found a "
							       "certificate "
							       "with the same "
							       "nickname but "
							       "different "
							       "subject, "
							       "removing "
							       "certificate "
							       "\"%s\" with "
							       "subject "
							       "\"%s\".\n",
							       node->cert->nickname,
							       node->cert->subjectName ?
							       node->cert->subjectName :
							       "");
							SEC_DeletePermCertificate(node->cert);
						}
					}
					CERT_DestroyCertList(certlist);
				}
			} else {
				cm_log(3, "No duplicate nickname entries.\n");
			}
			/* This certificate's subject may already be present
			 * with a different nickname.  Delete those, too. */
			certlist = CERT_CreateSubjectCertList(NULL, certdb,
							      &subject,
							      PR_FALSE,
							      PR_FALSE);
			if (certlist != NULL) {
				/* Look for certs with different nicknames. */
				i = 0;
				for (node = CERT_LIST_HEAD(certlist);
				     (node != NULL) &&
				     !CERT_LIST_EMPTY(certlist) &&
				     !CERT_LIST_END(node, certlist);
				     node = CERT_LIST_NEXT(node)) {
					if ((node->cert->nickname != NULL) &&
					    (strcmp(entry->cm_cert_nickname,
						    node->cert->nickname) != 0)) {
						i++;
						cm_log(3, "Found a "
						       "certificate with a "
						       "different nickname but "
						       "the same subject, "
						       "removing certificate "
						       "\"%s\" with subject "
						       "\"%s\".\n",
						       node->cert->nickname,
						       node->cert->subjectName ?
						       node->cert->subjectName :
						       "");
						SEC_DeletePermCertificate(node->cert);
					}
				}
				if (i == 0) {
					cm_log(3, "No duplicate subject name entries.\n");
				}
				CERT_DestroyCertList(certlist);
			} else {
				cm_log(3, "No duplicate subject name entries.\n");
			}
			/* Import the certificate. */
			returned = NULL;
			error = CERT_ImportCerts(certdb,
						 certUsageUserCertImport,
						 1, &item, &returned,
						 PR_TRUE,
						 PR_FALSE,
						 entry->cm_cert_nickname);
			if (error == SECSuccess) {
				cm_log(1, "Imported certificate \"%s\", got "
				       "nickname \"%s\".\n",
				       entry->cm_cert_nickname,
				       returned[0]->nickname);
				status = 0;
			} else {
				cm_log(0, "Error importing certificate "
				       "into NSSDB \"%s\": %s.\n",
				       entry->cm_cert_storage_location,
				       PR_ErrorToString(error,
							PR_LANGUAGE_I_DEFAULT));
			}
			if (returned != NULL) {
				CERT_DestroyCertArray(returned, 1);
			}
		} else {
			cm_log(1, "Error getting handle to default NSS DB.\n");
		}
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
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
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_STATUS_SAVED)) {
		return -1;
	}
	return 0;
}

/* Check if we failed because the subject was already there with a different
 * nickname. */
static int
cm_certsave_n_conflict_subject(struct cm_store_entry *entry,
			       struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_STATUS_SUBJECT_CONFLICT)) {
		return -1;
	}
	return 0;
}

/* Check if we failed because the nickname was already taken by a different
 * subject . */
static int
cm_certsave_n_conflict_nickname(struct cm_store_entry *entry,
			        struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_STATUS_NICKNAME_CONFLICT)) {
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
		state->pvt.get_fd = cm_certsave_n_get_fd;
		state->pvt.saved = cm_certsave_n_saved;
		state->pvt.conflict_subject = cm_certsave_n_conflict_subject;
		state->pvt.conflict_nickname = cm_certsave_n_conflict_nickname;
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
