/*
 * Copyright (C) 2014 Red Hat, Inc.
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
#include <string.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secerr.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include <talloc.h>
#include <tevent.h>

struct cm_context;
struct cm_certsave_state;
#include "casave.h"
#include "certsave-int.h"
#include "cm.h"
#include "iterate.h"
#include "log.h"
#include "prefs.h"
#include "store-int.h"
#include "submit-e.h"
#include "subproc.h"
#include "tdbus.h"
#include "util.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

struct cm_casave_state {
	void *parent;
	struct cm_store_ca *ca;
	struct cm_subproc_state *subproc;
	struct cm_context *context;
	struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int);
	int (*get_n_cas)(struct cm_context *);
	struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int);
	int (*get_n_entries)(struct cm_context *);
	const char *file, *nssdb;
	struct cm_savecert {
		enum cert_level { root, other_root, other } level;
		char *nickname;
		char *cert;
	} **certs;
};

/* Save the list of certificates to the database. */
static int
cm_casave_main_n(int fd, struct cm_store_ca *ca, struct cm_store_entry *e,
		 void *data)
{
	struct cm_casave_state *state = data;
	FILE *fp;
	NSSInitContext *ctx;
	SECStatus err;
	CERTCertificate *decoded, *found, **imported = NULL;
	CERTCertTrust trust;
	CERTCertDBHandle *certdb;
	SECItem *items[2];
	PRUint32 flags;
	const char *es, *ttrust;
	char *package, *p;
	int i, ec;

	fp = fdopen(fd, "w");
	if (fp == NULL) {
		return CM_CERTSAVE_STATUS_INTERNAL_ERROR;
	}
	if (state->certs != NULL) {
		ctx = NSS_InitContext(state->nssdb, NULL, NULL, NULL, NULL, 0);
		ec = PORT_GetError();
		if (ctx == NULL) {
			if (ec == SEC_ERROR_BAD_DATABASE) {
				switch (errno) {
				case EACCES:
				case EPERM:
					ec = PR_NO_ACCESS_RIGHTS_ERROR;
					break;
				default:
					flags = NSS_INIT_READONLY |
						NSS_INIT_NOROOTINIT |
						NSS_INIT_NOMODDB;
					/* Sigh.  Not a lot of detail.  Check
					 * if we succeed in read-only mode,
					 * which we'll interpret as lack of
					 * write permissions. */
					ctx = NSS_InitContext(state->nssdb,
							      NULL, NULL,
							      NULL, NULL,
							      flags);
					if (ctx != NULL) {
						err = NSS_ShutdownContext(ctx);
						if (err != SECSuccess) {
							cm_log(1, "Error "
							       "shutting down "
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
				cm_log(1, "Unable to open NSS database '%s': "
				       "%s.\n", state->nssdb, es);
			} else {
				cm_log(1, "Unable to open NSS database '%s'.\n",
				       state->nssdb);
			}
			switch (ec) {
			case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
				fclose(fp);
				return CM_CERTSAVE_STATUS_PERMS;
				break;
			default:
				fclose(fp);
				return CM_CERTSAVE_STATUS_INTERNAL_ERROR;
				break;
			}
		}
		certdb = CERT_GetDefaultCertDB();
		for (i = 0; state->certs[i] != NULL; i++) {
			package = state->certs[i]->cert;
			decoded = CERT_DecodeCertFromPackage(package,
							     strlen(package));
			p = state->certs[i]->nickname;
			ttrust = ",,";
			switch (state->certs[i]->level) {
			case root:
			case other_root:
				ttrust = cm_prefs_nss_ca_trust();
				if (ttrust == NULL) {
					ttrust = "CT,C,C";
				}
				break;
			case other:
				ttrust = cm_prefs_nss_other_trust();
				if (ttrust == NULL) {
					ttrust = ",,";
				}
				break;
			}
			memset(&trust, 0, sizeof(trust));
			CERT_DecodeTrustString(&trust, ttrust);
			if (decoded != NULL) {
				found = CERT_FindCertByDERCert(certdb,
							       &decoded->derCert);
				if (found != NULL) {
					items[0] = &found->derCert;
					items[1] = NULL;
					if (CERT_ImportCerts(certdb,
							     certUsageSSLCA,
							     1, items,
							     &imported,
							     PR_TRUE, PR_FALSE,
							     p) != SECSuccess) {
						ec = PORT_GetError();
						if (ec != 0) {
							es = PR_ErrorToName(ec);
						} else {
							es = NULL;
						}
						if (es != NULL) {
							cm_log(1, "Error "
							       "importing '%s':"
							       " %s.\n",
							       p, es);
						} else {
							cm_log(1, "Error "
							       "importing '%s'"
							       ".\n", p);
						}
						break;
					} else {
						cm_log(3, "Wrote '%s' to "
						       "database '%s'.\n",
						       p, state->nssdb);
						CERT_ChangeCertTrust(certdb,
								     imported[0],
								     &trust);
						CERT_DestroyCertificate(imported[0]);
					}
					CERT_DestroyCertificate(found);
				} else{
					cm_log(3, "Temporary certificate '%s' "
					       "not found in '%s'.\n",
					       p, state->nssdb);
				}
				CERT_DestroyCertificate(decoded);
			} else{
				cm_log(3, "Error decoding certificate '%s'.\n",
				       p);
			}
		}
		err = NSS_ShutdownContext(ctx);
		if (err != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
			fclose(fp);
			return CM_CERTSAVE_STATUS_INTERNAL_ERROR;
		}
	}
	fclose(fp);
	return 0;
}

/* Save the list of certificates to the file. */
static int
cm_casave_main_o(int fd, struct cm_store_ca *ca, struct cm_store_entry *e,
		 void *data)
{
	struct cm_casave_state *state = data;
	FILE *fp, *bundle;
	int i;

	fp = fdopen(fd, "w");
	if (fp == NULL) {
		return CM_CERTSAVE_STATUS_INTERNAL_ERROR;
	}
	if (state->certs != NULL) {
		bundle = fopen(state->file, "w");
		if (bundle == NULL) {
			switch (errno) {
			case EACCES:
			case EPERM:
				fclose(fp);
				return CM_CERTSAVE_STATUS_PERMS;
				break;
			default:
				fclose(fp);
				return CM_CERTSAVE_STATUS_INTERNAL_ERROR;
				break;
			}
		}
		for (i = 0; state->certs[i] != NULL; i++) {
			fprintf(bundle, "%s", state->certs[i]->cert);
			cm_log(3, "Wrote '%s' to file '%s'.\n",
			       state->certs[i]->nickname, state->file);
		}
		fclose(bundle);
	}
	fclose(fp);
	return 0;
}

static struct cm_store_ca *
ca_for_entry(struct cm_store_entry *e, struct cm_casave_state *state)
{
	struct cm_store_ca *ca;
	int i;

	if (e->cm_ca_nickname != NULL) {
		for (i = 0; i < (*state->get_n_cas)(state->context); i++) {
			ca = (*state->get_ca_by_index)(state->context, i);
			if (strcmp(e->cm_ca_nickname, ca->cm_nickname) == 0) {
				return ca;
			}
		}
	}
	return NULL;
}

static void
add_string(void *parent, char ***dest, const char *value)
{
	char **tmp;
	int i;

	for (i = 0; ((*dest) != NULL) && ((*dest)[i] != NULL); i++) {
		if (strcmp((*dest)[i], value) == 0) {
			return;
		}
	}
	tmp = talloc_array_ptrtype(parent, tmp, i + 2);
	if (tmp == NULL) {
		printf(_("Out of memory.\n"));
		exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
	}
	if (i > 0) {
		memcpy(tmp, *dest, sizeof(tmp[0]) * i);
	}
	tmp[i++] = talloc_strdup(tmp, value);
	tmp[i] = NULL;
	*dest = tmp;
}

static dbus_bool_t
has_string(char **list, const char *value)
{
	int i;

	for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
		if (strcmp(list[i], value) == 0) {
			return TRUE;
		}
	}
	return FALSE;
}

static void
add_cert(void *parent, struct cm_savecert ***dest, enum cert_level level,
	 const char *nickname, const char *cert)
{
	struct cm_savecert **tmp;
	int i;

	for (i = 0; ((*dest) != NULL) && ((*dest)[i] != NULL); i++) {
		if ((strcmp((*dest)[i]->nickname, nickname) == 0) &&
		    (strcmp((*dest)[i]->cert, cert) == 0)) {
			return;
		}
	}
	tmp = talloc_array_ptrtype(parent, tmp, i + 2);
	if (tmp == NULL) {
		printf(_("Out of memory.\n"));
		exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
	}
	if (i > 0) {
		memcpy(tmp, *dest, sizeof(tmp[0]) * i);
	}
	tmp[i] = talloc_ptrtype(tmp, tmp[i]);
	if (tmp[i] != NULL) {
		memset(tmp[i], 0, sizeof(*(tmp[i])));
		tmp[i]->level = level;
		tmp[i]->nickname = talloc_strdup(tmp, nickname);
		tmp[i]->cert = talloc_strdup(tmp, cert);
		i++;
	}
	tmp[i] = NULL;
	*dest = tmp;
}

static void
add_nickcerts(void *parent, struct cm_savecert ***dest, enum cert_level level,
	      struct cm_nickcert **certs)
{
	int i;

	for (i = 0; ((certs != NULL) && (certs[i] != NULL)); i++) {
		add_cert(parent, dest, level, certs[i]->cm_nickname,
			 certs[i]->cm_cert);
	}
}

/* Build the full list of locations where we'll be saving things.  If we're
 * passed an entry, that's the locations in the entry.  If we're passed a CA,
 * that's the locations in the CA and the locations in all of the entries which
 * refer to the CA. */
static void
build_locations_lists(void *parent, struct cm_casave_state *state,
		      struct cm_store_ca *ca, struct cm_store_entry *e,
		      char ***files, char ***dbs)
{
	struct cm_store_entry *cae = NULL;
	char *dest;
	int i, j;

	if (ca != NULL) {
		/* Collect the list of applicable locations from the CA. */
		if (ca->cm_ca_root_cert_store_files != NULL) {
			for (i = 0;
			     ca->cm_ca_root_cert_store_files[i] != NULL;
			     i++) {
				dest = ca->cm_ca_root_cert_store_files[i];
				add_string(state, files, dest);
			}
		}
		if (ca->cm_ca_other_root_cert_store_files != NULL) {
			for (i = 0;
			     ca->cm_ca_other_root_cert_store_files[i] != NULL;
			     i++) {
				dest = ca->cm_ca_other_root_cert_store_files[i];
				add_string(state, files, dest);
			}
		}
		if (ca->cm_ca_other_cert_store_files != NULL) {
			for (i = 0;
			     ca->cm_ca_other_cert_store_files[i] != NULL;
			     i++) {
				dest = ca->cm_ca_other_cert_store_files[i];
				add_string(state, files, dest);
			}
		}
		if (ca->cm_ca_root_cert_store_nssdbs != NULL) {
			for (i = 0;
			     ca->cm_ca_root_cert_store_nssdbs[i] != NULL;
			     i++) {
				dest = ca->cm_ca_root_cert_store_nssdbs[i];
				add_string(state, dbs, dest);
			}
		}
		if (ca->cm_ca_other_root_cert_store_nssdbs != NULL) {
			for (i = 0;
			     ca->cm_ca_other_root_cert_store_nssdbs[i] != NULL;
			     i++) {
				dest = ca->cm_ca_other_root_cert_store_nssdbs[i];
				add_string(state, dbs, dest);
			}
		}
		if (ca->cm_ca_other_cert_store_nssdbs != NULL) {
			for (i = 0;
			     ca->cm_ca_other_cert_store_nssdbs[i] != NULL;
			     i++) {
				dest = ca->cm_ca_other_cert_store_nssdbs[i];
				add_string(state, dbs, dest);
			}
		}
	}
	/* If we were passed a CA, look for entries that reference the CA. */
	for (j = 0;
	     (ca != NULL) && (j < (*state->get_n_entries)(state->context));
	     j++) {
		/* If this entry uses the passed-in CA, collect the list of
		 * applicable locations from the entry. */
		cae = (*state->get_entry_by_index)(state->context, j);
		if ((cae == NULL) || (cae == e)) {
			continue;
		}
		if (cae->cm_ca_nickname == NULL) {
			continue;
		}
		if (strcmp(cae->cm_ca_nickname, ca->cm_nickname) != 0) {
			continue;
		}
		/* Collect the list of applicable locations from the entry. */
		if (cae->cm_root_cert_store_files != NULL) {
			for (i = 0;
			     cae->cm_root_cert_store_files[i] != NULL;
			     i++) {
				dest = cae->cm_root_cert_store_files[i];
				add_string(state, files, dest);
			}
		}
		if (cae->cm_other_root_cert_store_files != NULL) {
			for (i = 0;
			     cae->cm_other_root_cert_store_files[i] != NULL;
			     i++) {
				dest = cae->cm_other_root_cert_store_files[i];
				add_string(state, files, dest);
			}
		}
		if (cae->cm_other_cert_store_files != NULL) {
			for (i = 0;
			     cae->cm_other_cert_store_files[i] != NULL;
			     i++) {
				add_string(state, files,
					   cae->cm_other_cert_store_files[i]);
			}
		}
		if (cae->cm_root_cert_store_nssdbs != NULL) {
			for (i = 0;
			     cae->cm_root_cert_store_nssdbs[i] != NULL;
			     i++) {
				add_string(state, dbs,
					   cae->cm_root_cert_store_nssdbs[i]);
			}
		}
		if (cae->cm_other_root_cert_store_nssdbs != NULL) {
			for (i = 0;
			     cae->cm_other_root_cert_store_nssdbs[i] != NULL;
			     i++) {
				dest = cae->cm_other_root_cert_store_nssdbs[i];
				add_string(state, dbs, dest);
			}
		}
		if (cae->cm_other_cert_store_nssdbs != NULL) {
			for (i = 0;
			     cae->cm_other_cert_store_nssdbs[i] != NULL;
			     i++) {
				add_string(state, dbs,
					   cae->cm_other_cert_store_nssdbs[i]);
			}
		}
	}
	if (e != NULL) {
		/* Collect the list of applicable locations from the entry. */
		if (e->cm_root_cert_store_files != NULL) {
			for (i = 0;
			     e->cm_root_cert_store_files[i] != NULL;
			     i++) {
				dest = e->cm_root_cert_store_files[i];
				add_string(state, files, dest);
			}
		}
		if (e->cm_other_root_cert_store_files != NULL) {
			for (i = 0;
			     e->cm_other_root_cert_store_files[i] != NULL;
			     i++) {
				dest = e->cm_other_root_cert_store_files[i];
				add_string(state, files, dest);
			}
		}
		if (e->cm_other_cert_store_files != NULL) {
			for (i = 0;
			     e->cm_other_cert_store_files[i] != NULL;
			     i++) {
				add_string(state, files,
					   e->cm_other_cert_store_files[i]);
			}
		}
		if (e->cm_root_cert_store_nssdbs != NULL) {
			for (i = 0;
			     e->cm_root_cert_store_nssdbs[i] != NULL;
			     i++) {
				add_string(state, dbs,
					   e->cm_root_cert_store_nssdbs[i]);
			}
		}
		if (e->cm_other_root_cert_store_nssdbs != NULL) {
			for (i = 0;
			     e->cm_other_root_cert_store_nssdbs[i] != NULL;
			     i++) {
				dest = e->cm_other_root_cert_store_nssdbs[i];
				add_string(state, dbs, dest);
			}
		}
		if (e->cm_other_cert_store_nssdbs != NULL) {
			for (i = 0;
			     e->cm_other_cert_store_nssdbs[i] != NULL;
			     i++) {
				add_string(state, dbs,
					   e->cm_other_cert_store_nssdbs[i]);
			}
		}
	}
}

/* Build the list of certificates that belong in this file.  That's the
 * certificates of any CA which lists the file as a storage location, and of
 * any CA referenced by entries which list the file as a storage location. */
static struct cm_savecert **
build_file_savecerts_list(struct cm_casave_state *state, const char *filename)
{
	struct cm_savecert **ret = NULL;
	struct cm_store_ca *ca;
	struct cm_store_entry *entry;
	int i, j;
	dbus_bool_t have_root, have_other_root, have_other;

	for (i = 0; i < (*state->get_n_cas)(state->context); i++) {
		ca = (*state->get_ca_by_index)(state->context, i);
		have_root = FALSE;
		have_other_root = FALSE;
		have_other = FALSE;
		if (has_string(ca->cm_ca_root_cert_store_files, filename)) {
			add_nickcerts(state, &ret, root, ca->cm_ca_root_certs);
			have_root = TRUE;
		}
		if (has_string(ca->cm_ca_other_root_cert_store_files,
			       filename)) {
			add_nickcerts(state, &ret, other_root,
				      ca->cm_ca_other_root_certs);
			have_other_root = TRUE;
		}
		if (has_string(ca->cm_ca_other_cert_store_files, filename)) {
			add_nickcerts(state, &ret, other,
				      ca->cm_ca_other_certs);
			have_other = TRUE;
		}
		for (j = 0; j < (*state->get_n_entries)(state->context); j++) {
			entry = (*state->get_entry_by_index)(state->context, j);
			if (entry->cm_ca_nickname == NULL) {
				continue;
			}
			if (strcmp(entry->cm_ca_nickname,
				   ca->cm_nickname) != 0) {
				continue;
			}
			if (!have_root &&
			    has_string(entry->cm_root_cert_store_files,
				       filename)) {
				add_nickcerts(state, &ret, root,
					      ca->cm_ca_root_certs);
				have_root = TRUE;
			}
			if (!have_other_root &&
			    has_string(entry->cm_other_root_cert_store_files,
				       filename)) {
				add_nickcerts(state, &ret, other_root,
					      ca->cm_ca_other_root_certs);
				have_other_root = TRUE;
			}
			if (!have_other &&
			    has_string(entry->cm_other_cert_store_files,
				       filename)) {
				add_nickcerts(state, &ret, other,
					      ca->cm_ca_other_certs);
				have_other = TRUE;
			}
			if (have_root && have_other_root && have_other) {
				break;
			}
		}
	}
	return ret;
}

/* Build the list of certificates which we need to store in this database.
 * That's the certificates of the CA, and of the entry's CA. */
static struct cm_savecert **
build_nssdb_savecerts_list(struct cm_casave_state *state,
			   struct cm_store_ca *ca,
			   struct cm_store_entry *entry,
			   const char *nssdb)
{
	struct cm_savecert **ret = NULL;

	if (ca != NULL) {
		if (has_string(ca->cm_ca_root_cert_store_nssdbs, nssdb)) {
			add_nickcerts(state, &ret, root, ca->cm_ca_root_certs);
		}
		if (has_string(ca->cm_ca_other_root_cert_store_nssdbs, nssdb)) {
			add_nickcerts(state, &ret, other_root,
				      ca->cm_ca_other_root_certs);
		}
		if (has_string(ca->cm_ca_other_cert_store_nssdbs, nssdb)) {
			add_nickcerts(state, &ret, other,
				      ca->cm_ca_other_certs);
		}
	}
	if (entry != NULL) {
		ca = ca_for_entry(entry, state);
		if (ca != NULL) {
			if (has_string(entry->cm_root_cert_store_nssdbs,
				       nssdb)) {
				add_nickcerts(state, &ret, root,
					      ca->cm_ca_root_certs);
			} else
			if (has_string(ca->cm_ca_root_cert_store_nssdbs,
				       nssdb)) {
				add_nickcerts(state, &ret, root,
					      ca->cm_ca_root_certs);
			}
			if (has_string(entry->cm_other_root_cert_store_nssdbs,
				       nssdb)) {
				add_nickcerts(state, &ret, other_root,
					      ca->cm_ca_other_root_certs);
			} else
			if (has_string(ca->cm_ca_other_root_cert_store_nssdbs,
				       nssdb)) {
				add_nickcerts(state, &ret, other_root,
					      ca->cm_ca_other_root_certs);
			}
			if (has_string(entry->cm_other_cert_store_nssdbs,
				       nssdb)) {
				add_nickcerts(state, &ret, other,
					      ca->cm_ca_other_certs);
			} else
			if (has_string(ca->cm_ca_other_cert_store_nssdbs,
				       nssdb)) {
				add_nickcerts(state, &ret, other,
					      ca->cm_ca_other_certs);
			}
		}
	}
	return ret;
}

static int
cm_casave_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *e,
	       void *data)
{
	struct cm_casave_state *state = data;
	struct cm_subproc_state *subproc;
	FILE *fp;
	int i, status, length;
	char **files = NULL, **dbs = NULL;
	const char *msg;

	fp = fdopen(fd, "w");
	if (fp == NULL) {
		return CM_CERTSAVE_STATUS_INTERNAL_ERROR;
	}

	/* Build a list of the locations to which we're going to be writing. */
	build_locations_lists(data, state, ca, e, &files, &dbs);

	/* For each file, work out all of the certificates that need to be
	 * saved to it, and save them. */
	for (i = 0; (files != NULL) && (files[i] != NULL); i++) {
		state->file = files[i];
		state->nssdb = NULL;
		state->certs = build_file_savecerts_list(state, state->file);
		subproc = cm_subproc_start(cm_casave_main_o, state, ca, e,
					   state);
		if (subproc == NULL) {
			fprintf(fp, "Error starting to save to file \"%s\".\n",
				state->file);
			fclose(fp);
			_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
		}
		while (cm_subproc_ready(subproc) != 0) {
			fd = cm_subproc_get_fd(subproc);
			cm_waitfor_readable_fd(fd, CM_DELAY_SOON);
		}
		msg = cm_subproc_get_msg(subproc, &length);
		status = cm_subproc_get_exitstatus(subproc);
		if (WIFEXITED(status) && (WEXITSTATUS(status) != 0)) {
			if (length > 0) {
				fprintf(fp, "%.*s", length, msg);
			}
		}
		cm_subproc_done(subproc);
		if (WIFEXITED(status) && (WEXITSTATUS(status) != 0)) {
			fclose(fp);
			_exit(WEXITSTATUS(status));
		}
	}

	/* For each database, work out all of the certificates that need to be
	 * saved to it, and save them. */
	for (i = 0; (dbs != NULL) && (dbs[i] != NULL); i++) {
		state->file = NULL;
		state->nssdb = dbs[i];
		state->certs = build_nssdb_savecerts_list(state, ca, e,
							  state->nssdb);
		subproc = cm_subproc_start(cm_casave_main_n, state, ca, e,
					   state);
		if (subproc == NULL) {
			fprintf(fp,
				"Error starting to save to database \"%s\".\n",
				state->nssdb);
			fclose(fp);
			_exit(CM_CERTSAVE_STATUS_INTERNAL_ERROR);
		}
		while (cm_subproc_ready(subproc) != 0) {
			fd = cm_subproc_get_fd(subproc);
			cm_waitfor_readable_fd(fd, CM_DELAY_SOON);
		}
		msg = cm_subproc_get_msg(subproc, &length);
		status = cm_subproc_get_exitstatus(subproc);
		if (WIFEXITED(status) && (WEXITSTATUS(status) != 0)) {
			if (length > 0) {
				fprintf(fp, "%.*s", length, msg);
			}
		}
		cm_subproc_done(subproc);
		if (WIFEXITED(status) && (WEXITSTATUS(status) != 0)) {
			fclose(fp);
			_exit(WEXITSTATUS(status));
		}
	}

	fclose(fp);
	_exit(0);
}

struct cm_casave_state *
cm_casave_start(struct cm_store_entry *entry, struct cm_store_ca *ca,
		struct cm_context *context,
		struct cm_store_ca *(*get_ca_by_index)(struct cm_context *,
						       int),
		int (*get_n_cas)(struct cm_context *),
		struct cm_store_entry *(*get_e_by_index)(struct cm_context *,
							 int),
		int (*get_n_entries)(struct cm_context *))
{
	struct cm_casave_state *ret;
	void *parent;

	if (entry != NULL) {
		parent = entry;
	} else {
		parent = ca;
	}
	ret = talloc_ptrtype(parent, ret);
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		ret->parent = parent;
		ret->ca = ca;
		ret->context = context;
		ret->get_ca_by_index = get_ca_by_index;
		ret->get_n_cas = get_n_cas;
		ret->get_entry_by_index = get_e_by_index;
		ret->get_n_entries = get_n_entries;
		ret->subproc = cm_subproc_start(cm_casave_main, ret,
						ca, entry, ret);
		if (ret->subproc == NULL) {
			talloc_free(ret);
			return NULL;
		}
	}
	return ret;
}

int
cm_casave_ready(struct cm_casave_state *state)
{
	int ready, length;
	const char *msg;
	char *p;

	ready = cm_subproc_ready(state->subproc);
	if (ready == 0) {
		msg = cm_subproc_get_msg(state->subproc, &length);
		if (msg != NULL) {
			if (state->ca != NULL) {
				talloc_free(state->ca->cm_ca_error);
				p = talloc_strndup(state->ca, msg, length);
				state->ca->cm_ca_error = p;
			}
		} else {
			state->ca->cm_ca_error = NULL;
		}
	}
	return ready;
}

int
cm_casave_get_fd(struct cm_casave_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

int
cm_casave_saved(struct cm_casave_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_CERTSAVE_STATUS_SAVED)) {
		return 0;
	}
	return -1;
}

int
cm_casave_conflict_subject(struct cm_casave_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_CERTSAVE_STATUS_SUBJECT_CONFLICT)) {
		return 0;
	}
	return -1;
}

int
cm_casave_conflict_nickname(struct cm_casave_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_CERTSAVE_STATUS_NICKNAME_CONFLICT)) {
		return 0;
	}
	return -1;
}

int
cm_casave_permissions_error(struct cm_casave_state *state)
{
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_CERTSAVE_STATUS_PERMS)) {
		return 0;
	}
	return -1;
}

void
cm_casave_done(struct cm_casave_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}
