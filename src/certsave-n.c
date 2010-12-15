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
	int readwrite:1;
};

static int
cm_certsave_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	int status = 1, readwrite;
	PLArenaPool *arena;
	SECStatus error;
	SECItem *item;
	char *p, *q;
	CERTCertDBHandle *certdb;
	CERTCertList *certlist;
	CERTCertListNode *node;
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
		certdb = CERT_GetDefaultCertDB();
		if (certdb != NULL) {
			/* Handle the base64 decode. */
			p = entry->cm_cert;
			q = NULL;
			while (strncmp(p, "-----BEGIN ", 11) == 0) {
				p += strcspn(p, "\r\n");
				p += strspn(p, "\r\n");
			}
			q = strstr(p, "-----END");
			if ((p == NULL) || (q == NULL)) {
				cm_log(1, "Unable to parse certificate.\n");
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
				PORT_FreeArena(arena, PR_TRUE);
				if (NSS_Shutdown() != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(1);
			}
			error = CERT_ImportCerts(certdb,
						 certUsageUserCertImport,
						 1, &item, NULL, PR_TRUE,
						 PR_FALSE,
						 entry->cm_cert_nickname);
			if (error == SECSuccess) {
				status = 0;
			} else {
				certlist = PK11_FindCertsFromNickname(entry->cm_cert_nickname, NULL);
				if (certlist != NULL) {
					/* Delete the existing cert. */
					for (node = CERT_LIST_HEAD(certlist);
					     !CERT_LIST_EMPTY(certlist) &&
					     !CERT_LIST_END(node, certlist);
					     node = CERT_LIST_NEXT(node)) {
						SEC_DeletePermCertificate(node->cert);
					}
					CERT_DestroyCertList(certlist);
					/* Try again. */
					error = CERT_ImportCerts(certdb,
								 certUsageUserCertImport,
								 1, &item, NULL,
								 PR_TRUE,
								 PR_FALSE,
								 entry->cm_cert_nickname);
					if (error == SECSuccess) {
						status = 0;
					}
				}
				if (error != SECSuccess) {
					cm_log(1, "Error importing certificate "
					       "into NSSDB: %s.\n",
					       PR_ErrorToString(error,
								PR_LANGUAGE_I_DEFAULT));
				}
			}
		} else {
			cm_log(1, "Error getting handle to default NSS DB.\n");
		}
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
