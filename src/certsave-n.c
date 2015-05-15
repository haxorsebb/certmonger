/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014,2015 Red Hat, Inc.
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
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certdb.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secerr.h>

#include <talloc.h>

#include "certsave.h"
#include "certsave-int.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "util-n.h"

#define PRIVKEY_LIST_EMPTY(l) PRIVKEY_LIST_END(PRIVKEY_LIST_HEAD(l), l)

struct cm_certsave_state {
	struct cm_certsave_state_pvt pvt;
	struct cm_subproc_state *subproc;
	struct cm_store_entry *entry;
};
struct cm_certsave_n_settings {
	unsigned int readwrite:1;
};

static SECKEYPrivateKey **
add_privkey_to_list(SECKEYPrivateKey **list, SECKEYPrivateKey *key)
{
	SECKEYPrivateKey **newlist;
	int i;

	if (key != NULL) {
		for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
			if (list[i] == key) {
				SECKEY_DestroyPrivateKey(key);
				break;
			}
		}
		if ((list == NULL) || (list[i] == NULL)) {
			newlist = malloc(sizeof(newlist[0]) * (i + 2));
			if (newlist != NULL) {
				memcpy(newlist, list, sizeof(newlist[0]) * i);
				newlist[i] = key;
				newlist[i + 1] = NULL;
				list = newlist;
			}
		}
	}
	return list;
}

static int
cm_certsave_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	int status = CM_CERTSAVE_STATUS_INTERNAL_ERROR, readwrite, i, ec;
	PRBool have_trust;
	PLArenaPool *arena;
	SECStatus error;
	SECItem *item, subject;
	char *p, *q, *pin;
	const char *es;
	NSSInitContext *ctx;
	CERTCertDBHandle *certdb;
	CERTCertList *certlist;
	CERTCertificate **returned, *oldcert, cert;
	CERTCertTrust trust;
	CERTSignedData csdata;
	CERTCertListNode *node;
	SECKEYPrivateKey **privkeys = NULL, *privkey;
	SECKEYPrivateKeyList *privkeylist;
	SECKEYPrivateKeyListNode *knode;
	struct cm_certsave_n_settings *settings;
	struct cm_pin_cb_data cb_data;

	if (entry->cm_cert_storage_location == NULL) {
		cm_log(1, "Error saving certificate: no location "
		       "specified.\n");
		_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
	}
	if (entry->cm_cert_nickname == NULL) {
		cm_log(1, "Error saving certificate: no nickname "
		       "specified.\n");
		_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
	}

	/* Open the database. */
	settings = userdata;
	readwrite = settings->readwrite;
	errno = 0;
	ctx = NSS_InitContext(entry->cm_cert_storage_location,
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
			cm_log(1, "Unable to open NSS database '%s': %s.\n",
			       entry->cm_cert_storage_location, es);
		} else {
			cm_log(1, "Unable to open NSS database '%s'.\n",
			       entry->cm_cert_storage_location);
		}
		switch (ec) {
		case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
			status = CM_CERTSAVE_STATUS_PERMS;
			break;
		default:
			status = CM_CERTSAVE_STATUS_INITIALIZING;
			break;
		}
	} else {
		/* We don't try to force FIPS mode here, as it seems to get in
		 * the way of saving the certificate. */

		/* Allocate a memory pool. */
		arena = PORT_NewArena(sizeof(double));
		if (arena == NULL) {
			cm_log(1, "Error opening database '%s'.\n",
			       entry->cm_cert_storage_location);
			if (NSS_ShutdownContext(ctx) != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
		}
		/* Be ready to count our uses of a PIN. */
		memset(&cb_data, 0, sizeof(cb_data));
		cb_data.entry = entry;
		cb_data.n_attempts = 0;
		pin = NULL;
		if (cm_pin_read_for_key(entry, &pin) != 0) {
			cm_log(1, "Error reading PIN for key store, "
			       "failing to save certificate.\n");
			PORT_FreeArena(arena, PR_TRUE);
			error = NSS_ShutdownContext(ctx);
			if (error != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(CM_CERTSAVE_STATUS_AUTH);
		}
		/* Set a PIN if we're supposed to be using one and aren't using
		 * one yet in this database. */
		if (PK11_NeedUserInit(PK11_GetInternalKeySlot())) {
			PK11_InitPin(PK11_GetInternalKeySlot(), NULL,
				     pin ? pin : "");
			ec = PORT_GetError();
			if (ec != 0) {
				es = PR_ErrorToName(ec);
			} else {
				es = NULL;
			}
			if (PK11_NeedUserInit(PK11_GetInternalKeySlot())) {
				if (es != NULL) {
					cm_log(1, "Key storage slot still "
					       "needs user PIN to be set: "
					       "%s.\n", es);
				} else {
					cm_log(1, "Key storage slot still "
					       "needs user PIN to be set.\n");
				}
				PORT_FreeArena(arena, PR_TRUE);
				error = NSS_ShutdownContext(ctx);
				if (error != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				switch (ec) {
				case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
					_exit(CM_CERTSAVE_STATUS_PERMS);
					break;
				default:
					_exit(CM_CERTSAVE_STATUS_AUTH);
					break;
				}
			}
			/* We're authenticated now, so count this as a use of
			 * the PIN. */
			if ((pin != NULL) && (strlen(pin) > 0)) {
				cb_data.n_attempts++;
			}
		}
		/* Log in, if case we need to muck around with the key
		 * database. */
		PK11_SetPasswordFunc(&cm_pin_read_for_key_nss_cb);
		error = PK11_Authenticate(PK11_GetInternalKeySlot(), PR_TRUE,
					  &cb_data);
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
			PORT_FreeArena(arena, PR_TRUE);
			error = NSS_ShutdownContext(ctx);
			if (error != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(CM_CERTSAVE_STATUS_AUTH);
		}
		if ((pin != NULL) &&
		    (strlen(pin) > 0) &&
		    (cb_data.n_attempts == 0)) {
			cm_log(1, "PIN was not needed to auth to key "
			       "store, though one was provided. "
			       "Treating this as an error.\n");
			PORT_FreeArena(arena, PR_TRUE);
			error = NSS_ShutdownContext(ctx);
			if (error != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(CM_CERTSAVE_STATUS_AUTH);
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
				_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
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
				_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
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
				_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
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
				_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
			}
			subject = cert.derSubject;
			/* Ask NSS if there would be a conflict. */
			have_trust = PR_FALSE;
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
					 * subject names but the same nickname,
					 * because they've got to go. */
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
							/* Get a handle for
							 * this certificate's
							 * private key, in case
							 * we need to remove
							 * it. */
							privkey = PK11_FindKeyByAnyCert(node->cert, NULL);
							privkeys = add_privkey_to_list(privkeys, privkey);
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
				/* Look for certs with different nicknames but
				 * the same subject name, because those have
				 * got to go. */
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
						/* Get a handle for this
						 * certificate's private key,
						 * in case we need to remove
						 * it. */
						privkey = PK11_FindKeyByAnyCert(node->cert, NULL);
						privkeys = add_privkey_to_list(privkeys, privkey);
						SEC_DeletePermCertificate(node->cert);
					} else {
						/* Same nickname, and we
						 * already know it has the same
						 * subject name.  Save its
						 * trust. */
						if (!have_trust) {
							if (CERT_GetCertTrust(node->cert,
									      &trust) == SECSuccess) {
								have_trust = PR_TRUE;
							}
						}
					}
				}
				if (i == 0) {
					cm_log(3, "No duplicate subject name entries.\n");
				}
				CERT_DestroyCertList(certlist);
			} else {
				cm_log(3, "No duplicate subject name entries.\n");
			}
			/* Make one more attempt at finding an existing trust
			 * value. */
			if (!have_trust) {
				oldcert = PK11_FindCertFromNickname(entry->cm_cert_nickname, NULL);
				if (oldcert != NULL) {
					if (CERT_GetCertTrust(oldcert,
							      &trust) == SECSuccess) {
						have_trust = PR_TRUE;
					}
					CERT_DestroyCertificate(oldcert);
				}
			}
			/* Import the certificate. */
			returned = NULL;
			error = CERT_ImportCerts(certdb,
						 certUsageUserCertImport,
						 1, &item, &returned,
						 PR_TRUE,
						 PR_FALSE,
						 entry->cm_cert_nickname);
			ec = PORT_GetError();
			if (error == SECSuccess) {
				cm_log(1, "Imported certificate \"%s\", got "
				       "nickname \"%s\".\n",
				       entry->cm_cert_nickname,
				       returned[0]->nickname);
				status = 0;
				/* Set the trust on the new certificate,
				 * perhaps matching the trust on an
				 * already-present certificate with the same
				 * nickname. */
				if (!have_trust) {
					memset(&trust, 0, sizeof(trust));
					trust.sslFlags = CERTDB_USER;
					trust.emailFlags = CERTDB_USER;
					trust.objectSigningFlags = CERTDB_USER;
				}
				error = CERT_ChangeCertTrust(certdb,
							     returned[0],
							     &trust);
				ec = PORT_GetError();
				if (error != SECSuccess) {
					if (ec != 0) {
						es = PR_ErrorToName(ec);
					} else {
						es = NULL;
					}
					if (es != NULL) {
						cm_log(0, "Error setting trust "
						       "on certificate \"%s\": "
						       "%s.\n",
						       entry->cm_cert_nickname, es);
					} else {
						cm_log(0, "Error setting trust "
						       "on certificate \"%s\".\n",
						       entry->cm_cert_nickname);
					}
				}
				/* Delete any other certificates that are there
				 * with the same nickname.  While NSS's
				 * database allows duplicates so long as they
				 * have the same subject name and nickname,
				 * several APIs and many applications can't
				 * dependably find the right one among more
				 * than one.  So bye-bye, old certificates. */
				certlist = PK11_FindCertsFromNickname(entry->cm_cert_nickname,
								      NULL);
				if (certlist != NULL) {
					/* Look for certs with contents. */
					for (node = CERT_LIST_HEAD(certlist);
					     (node != NULL) &&
					     !CERT_LIST_EMPTY(certlist) &&
					     !CERT_LIST_END(node, certlist);
					     node = CERT_LIST_NEXT(node)) {
						if (!SECITEM_ItemsAreEqual(item,
									   &node->cert->derCert)) {
							cm_log(3, "Found a "
							       "certificate "
							       "with the same "
							       "nickname and "
							       "subject, but "
							       "different "
							       "contents, "
							       "removing it.\n");
							/* Get a handle for
							 * this certificate's
							 * private key, in case
							 * we need to remove
							 * it. */
							privkey = PK11_FindKeyByAnyCert(node->cert, NULL);
							privkeys = add_privkey_to_list(privkeys, privkey);
							SEC_DeletePermCertificate(node->cert);
						}
					}
					CERT_DestroyCertList(certlist);
				}
			} else {
				if (ec != 0) {
					es = PR_ErrorToName(ec);
				} else {
					es = NULL;
				}
				if (es != NULL) {
					cm_log(0, "Error importing certificate "
					       "into NSSDB \"%s\": %s.\n",
					       entry->cm_cert_storage_location,
					       es);
				} else {
					cm_log(0, "Error importing certificate "
					       "into NSSDB \"%s\".\n",
					       entry->cm_cert_storage_location);
				}
				switch (ec) {
				case PR_NO_ACCESS_RIGHTS_ERROR: /* ACCES/PERM */
					status = CM_CERTSAVE_STATUS_PERMS;
					break;
				default:
					status = CM_CERTSAVE_STATUS_INTERNAL_ERROR;
					break;
				}
			}
			/* If we managed to import the certificate, mark its
			 * key for having its nickname removed. */
			if ((returned != NULL) && (returned[0] != NULL)) {
				privkey = PK11_FindKeyByAnyCert(returned[0], NULL);
				privkeys = add_privkey_to_list(privkeys, privkey);
				CERT_DestroyCertArray(returned, 1);
			}
			/* In case we're rekeying, but failed, mark the
			 * candidate key for name-clearing or removal, too. */
			if ((entry->cm_key_next_marker != NULL) &&
			    (strlen(entry->cm_key_next_marker) > 0)) {
				p = util_build_next_nickname(entry->cm_key_nickname,
							     entry->cm_key_next_marker);
				privkeylist = PK11_ListPrivKeysInSlot(PK11_GetInternalKeySlot(), p, NULL);
				if (privkeylist != NULL) {
					for (knode = PRIVKEY_LIST_HEAD(privkeylist);
					     !PRIVKEY_LIST_EMPTY(privkeylist) &&
					     !PRIVKEY_LIST_END(knode, privkeylist);
					     knode = PRIVKEY_LIST_NEXT(knode)) {
						q = PK11_GetPrivateKeyNickname(knode->key);
						if ((q != NULL) &&
						    (strcmp(p, q) == 0)) {
							privkey = SECKEY_CopyPrivateKey(knode->key);
							privkeys = add_privkey_to_list(privkeys, privkey);
							break;
						}
					}
					SECKEY_DestroyPrivateKeyList(privkeylist);
				}
			}
			if (privkeys != NULL) {
				/* Check if any certificates are still using
				 * the keys that correspond to certificates
				 * that we removed. */
				for (i = 0; privkeys[i] != NULL; i++) {
					privkey = privkeys[i];
					oldcert = PK11_GetCertFromPrivateKey(privkey);
					if (!entry->cm_key_preserve && (oldcert == NULL)) {
						/* We're not preserving
						 * orphaned keys, so remove
						 * this one.  No need to mess
						 * with its nickname first. */
						PK11_DeleteTokenPrivateKey(privkey, PR_FALSE);
						if (error == SECSuccess) {
							cm_log(3, "Removed old key.\n");
						} else {
							ec = PORT_GetError();
							if (ec != 0) {
								es = PR_ErrorToName(ec);
							} else {
								es = NULL;
							}
							if (es != NULL) {
								cm_log(0, "Failed "
								       "to remove "
								       "old key: "
								       "%s.\n", es);
							} else {
								cm_log(0, "Failed "
								       "to remove "
								       "old key.\n");
							}
						}
					} else {
						/* Remove the explicit
						 * nickname, so that the key
						 * will have to be found using
						 * the certificate's nickname,
						 * and certutil will display
						 * the matching certificate's
						 * nickname when it's asked to
						 * list the keys in the
						 * database. */
						error = PK11_SetPrivateKeyNickname(privkey, "");
						if (error == SECSuccess) {
							cm_log(3, "Removed "
							       "name from old "
							       "key.\n");
						} else {
							ec = PORT_GetError();
							if (ec != 0) {
								es = PR_ErrorToName(ec);
							} else {
								es = NULL;
							}
							if (es != NULL) {
								cm_log(0, "Failed "
								       "to unname "
								       "old key: "
								       "%s.\n", es);
							} else {
								cm_log(0, "Failed "
								       "to unname "
								       "old key.\n");
							}
						}
					}
					SECKEY_DestroyPrivateKey(privkey);
					if (oldcert != NULL) {
						CERT_DestroyCertificate(oldcert);
					}
				}
				free(privkeys);
			}
		} else {
			cm_log(1, "Error getting handle to default NSS DB.\n");
		}
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		/* Fixup the ownership and permissions on the key and
		 * certificate databases. */
		util_set_db_entry_key_owner(entry->cm_key_storage_location, entry);
		util_set_db_entry_cert_owner(entry->cm_cert_storage_location, entry);
	}
	if (status != 0) {
		_exit(status);
	}
	return 0;
}

/* Check if something changed, for example we finished saving the cert. */
static int
cm_certsave_n_ready(struct cm_certsave_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certsave_n_get_fd(struct cm_certsave_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Check if we saved the certificate -- the child exited with status 0. */
static int
cm_certsave_n_saved(struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_CERTSAVE_STATUS_SAVED)) {
		return -1;
	}
	if ((state->entry->cm_key_next_marker != NULL) &&
	    (strlen(state->entry->cm_key_next_marker) > 0)) {
		state->entry->cm_key_requested_count =
			state->entry->cm_key_next_requested_count;
		state->entry->cm_key_next_requested_count = 0;
		state->entry->cm_key_generated_date =
			state->entry->cm_key_next_generated_date;
		state->entry->cm_key_next_generated_date = 0;
		state->entry->cm_key_issued_count = 1;
	} else {
		state->entry->cm_key_issued_count++;
	}
	state->entry->cm_key_next_marker = NULL;
	return 0;
}

/* Check if we failed because the subject was already there with a different
 * nickname. */
static int
cm_certsave_n_conflict_subject(struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_CERTSAVE_STATUS_SUBJECT_CONFLICT)) {
		return -1;
	}
	return 0;
}

/* Check if we failed because the nickname was already taken by a different
 * subject . */
static int
cm_certsave_n_conflict_nickname(struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_CERTSAVE_STATUS_NICKNAME_CONFLICT)) {
		return -1;
	}
	return 0;
}

/* Check if we failed because we couldn't read or write to the storage
 * location. */
static int
cm_certsave_n_permissions_error(struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) ||
	    (WEXITSTATUS(status) != CM_CERTSAVE_STATUS_PERMS)) {
		return -1;
	}
	return 0;
}

/* Check if we failed because the right token wasn't present. */
static int
cm_certsave_n_token_error(struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) ||
	    (WEXITSTATUS(status) != CM_CERTSAVE_STATUS_NO_TOKEN)) {
		return -1;
	}
	return 0;
}

/* Check if we failed because we didn't have the right PIN or password to
 * access the storage location. */
static int
cm_certsave_n_pin_error(struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) ||
	    (WEXITSTATUS(status) != CM_CERTSAVE_STATUS_AUTH)) {
		return -1;
	}
	return 0;
}

/* Clean up after saving the certificate. */
static void
cm_certsave_n_done(struct cm_certsave_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
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
		state->pvt.permissions_error = cm_certsave_n_permissions_error;
		state->pvt.token_error = cm_certsave_n_token_error;
		state->pvt.pin_error = cm_certsave_n_pin_error;
		state->pvt.done= cm_certsave_n_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_certsave_n_main, state,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
