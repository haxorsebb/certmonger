/*
 * Copyright (C) 2009 Red Hat, Inc.
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
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include <dbus/dbus.h>

#include <krb5.h>

#include "cm.h"
#include "oiddict.h"
#include "store.h"
#include "store-int.h"
#include "tdbus.h"
#include "tdbusm.h"

#define N_(_msg) (_msg)
#define _(_msg) (_msg)

#ifdef FORCE_CA
#define GETOPT_CA ""
#define DEFAULT_CA FORCE_CA
#else
#define GETOPT_CA "c:"
#define DEFAULT_CA NULL
#endif

static void help(const char *cmd, const char *category);

static struct {
	DBusConnection *conn;
	void *tctx;
} globals = {
	.conn = NULL,
	.tctx = NULL
};

static char *find_ca_by_name(void *parent, enum cm_tdbus_type bus,
			     const char *nickname);
static char *find_request_by_name(void *parent, enum cm_tdbus_type bus,
				  const char *path);
static char *find_ca_name(void *parent, enum cm_tdbus_type bus,
			  const char *path);
static char *find_request_name(void *parent, enum cm_tdbus_type bus,
			       const char *path);

/* Add a string to a list. */
static void
add_string(void *parent, char ***dest, const char *value)
{
	char **tmp;
	int i;
	for (i = 0; ((*dest) != NULL) && ((*dest)[i] != NULL); i++) {
		continue;
	}
	tmp = talloc_array_ptrtype(parent, tmp, i + 2);
	if (tmp == NULL) {
		printf(_("Error connecting to DBus.\n"));
		exit(1);
	}
	memcpy(tmp, *dest, sizeof(tmp[0]) * i);
	tmp[i] = talloc_strdup(tmp, value);
	i++;
	tmp[i] = NULL;
	*dest = tmp;
}

/* Connect to the bus and set up as much of the request as we can. */
static DBusMessage *
prep_req(enum cm_tdbus_type which,
	 const char *path, const char *interface, const char *method)
{
	DBusMessage *msg;
	if (globals.conn == NULL) {
		switch (which) {
		case cm_tdbus_session:
			globals.conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
			break;
		case cm_tdbus_system:
			globals.conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
			break;
		}
		if (globals.conn == NULL) {
			printf(_("Error connecting to DBus.\n"));
			exit(1);
		}
	}
	msg = dbus_message_new_method_call(CM_DBUS_NAME,
					   path, interface, method);
	if (msg == NULL) {
		printf(_("Error creating DBus request message.\n"));
		exit(1);
	}
	return msg;
}

/* Send our request and return the response.  If there's an error, exit. */
static DBusMessage *
send_req(DBusMessage *req)
{
	DBusMessage *rep;
	DBusError err;
	memset(&err, 0, sizeof(err));
	rep = dbus_connection_send_with_reply_and_block(globals.conn, req,
							30 * 1000, &err);
	if (rep == NULL) {
		if (dbus_error_is_set(&err)) {
			if (err.name != NULL) {
				if (err.message != NULL) {
					printf(_("Error %s: %s\n"), err.name,
					       err.message);
				} else {
					printf(_("Error %s\n"), err.name);
				}
			} else {
				if (err.message != NULL) {
					printf(_("Error: %s\n"), err.message);
				} else {
					printf(_("Received error response from "
						 "local %s service.\n"),
						 CM_DBUS_NAME);
				}
			}
		} else {
			printf(_("No response received from %s service.\n"),
			       CM_DBUS_NAME);
		}
		exit(1);
	}
	dbus_message_unref(req);
	return rep;
}

/* Send the specified, argument-less method call to the named object and return
 * the reply message. */
static DBusMessage *
query_rep(enum cm_tdbus_type which,
	  const char *path, const char *interface, const char *method)
{
	return send_req(prep_req(which, path, interface, method));
}

/* Send the specified, argument-less method call to the named object, and
 * return a sole boolean response. */
static dbus_bool_t
query_rep_b(enum cm_tdbus_type which,
	    const char *path, const char *interface, const char *method,
	    void *parent)
{
	DBusMessage *rep;
	dbus_bool_t b;
	rep = query_rep(which, path, interface, method);
	if (cm_tdbusm_get_b(rep, parent, &b) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return b;
}

/* Send the specified, argument-less method call to the named object, and
 * return the single string from the response. */
static char *
query_rep_s(enum cm_tdbus_type which,
	    const char *path, const char *interface, const char *method,
	    void *parent)
{
	DBusMessage *rep;
	char *s;
	rep = query_rep(which, path, interface, method);
	if (cm_tdbusm_get_s(rep, parent, &s) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return s;
}

/* Send the specified, argument-less method call to the named object, and
 * return the single object path from the response. */
static char *
query_rep_p(enum cm_tdbus_type which,
	    const char *path, const char *interface, const char *method,
	    void *parent)
{
	DBusMessage *rep;
	char *p;
	rep = query_rep(which, path, interface, method);
	if (cm_tdbusm_get_p(rep, parent, &p) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return p;
}

/* Send the specified, argument-less method call to the named object, and
 * return the array of strings from the response. */
static char **
query_rep_as(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *method,
	     void *parent)
{
	DBusMessage *rep;
	char **as;
	rep = query_rep(which, path, interface, method);
	if (cm_tdbusm_get_as(rep, parent, &as) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return as;
}

/* Send the specified, argument-less method call to the named object, and
 * return the array of paths from the response. */
static char **
query_rep_ap(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *method,
	     void *parent)
{
	DBusMessage *rep;
	char **ap;
	rep = query_rep(which, path, interface, method);
	if (cm_tdbusm_get_ap(rep, parent, &ap) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return ap;
}

/* Send the specified, argument-less method call to the named object, and
 * return from two to four strings from the response. */
static void
query_rep_sososos(enum cm_tdbus_type which,
		  const char *path, const char *interface, const char *method,
		  void *parent, char **s1, char **s2, char **s3, char **s4)
{
	DBusMessage *rep;
	rep = query_rep(which, path, interface, method);
	if (cm_tdbusm_get_sososos(rep, parent, s1, s2, s3, s4) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
}

/* Add a new request. */
static int
request(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char subject_default[LINE_MAX];
	char *dbdir = NULL, *token = NULL, *nickname = NULL;
	char *keyfile = NULL, *certfile = NULL, *capath;
	int keysize = 0, auto_renew = 0, c, i;
	char *ca = DEFAULT_CA, *subject = NULL, **eku = NULL, *oid, *id = NULL;
	char **principal = NULL, **dns = NULL, **email = NULL;
	struct cm_tdbusm_dict param[32];
	const struct cm_tdbusm_dict *params[32];
	DBusMessage *req, *rep;
	dbus_bool_t b;
	char *p;
	krb5_context kctx;
	krb5_error_code kret;
	krb5_principal kprincipal;
	char *krealm, *kuprincipal;

	memset(subject_default, '\0', sizeof(subject_default));
	strcpy(subject_default, "CN=");
	if (gethostname(subject_default + 3,
			sizeof(subject_default) - 4) != 0) {
		strcpy(subject_default, "CN=localhost");
	}
	subject = subject_default;

	kctx = NULL;
	if ((kret = krb5_init_context(&kctx)) != 0) {
		kctx = NULL;
		printf(_("Error initializing Kerberos library: %s.\n"),
		       error_message(kret));
		return 1;
	}
	krealm = NULL;
	if ((kret = krb5_get_default_realm(kctx, &krealm)) != 0) {
		printf(_("Error determining default Kerberos realm: %s.\n"),
		       error_message(kret));
		return 1;
	}
	if (krealm == NULL) {
		printf(_("Error determining default Kerberos realm.\n"));
		return 1;
	}

	while ((c = getopt(argc, argv,
			   "d:n:t:k:f:I:g:rN:U:K:D:E:sS" GETOPT_CA)) != -1) {
		switch (c) {
		case 'd':
			dbdir = talloc_strdup(globals.tctx, optarg);
			break;
		case 't':
			token = talloc_strdup(globals.tctx, optarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, optarg);
			break;
		case 'k':
			keyfile = talloc_strdup(globals.tctx, optarg);
			break;
		case 'f':
			certfile = talloc_strdup(globals.tctx, optarg);
			break;
		case 'g':
			keysize = atoi(optarg);
			break;
		case 'I':
			id = talloc_strdup(globals.tctx, optarg);
			break;
		case 'r':
			auto_renew++;
			break;
		case 'c':
			ca = talloc_strdup(globals.tctx, optarg);
			break;
		case 'N':
			subject = talloc_strdup(globals.tctx, optarg);
			break;
		case 'U':
			oid = cm_oid_from_name(globals.tctx, optarg);
			if (strspn(oid, "0123456789.") != strlen(oid)) {
				printf(_("Could not evaluate OID \"%s\".\n"),
				       optarg);
				return 1;
			}
			add_string(globals.tctx, &eku, oid);
			break;
		case 'K':
			kprincipal = NULL;
			if ((kret = krb5_parse_name(kctx, optarg,
						    &kprincipal)) != 0) {
				printf(_("Error parsing Kerberos principal "
				         "name \"%s\": %s.\n"), optarg,
				       error_message(kret));
				return 1;
			}
			kuprincipal = NULL;
			if ((kret = krb5_unparse_name(kctx, kprincipal,
						      &kuprincipal)) != 0) {
				printf(_("Error unparsing Kerberos principal "
				         "name \"%s\": %s.\n"), optarg,
				       error_message(kret));
				return 1;
			}
			add_string(globals.tctx, &principal, kuprincipal);
			krb5_free_principal(kctx, kprincipal);
			break;
		case 'D':
			add_string(globals.tctx, &dns, optarg);
			break;
		case 'E':
			add_string(globals.tctx, &email, optarg);
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		default:
			help(argv0, "request");
			return 1;
		}
	}
	if (((dbdir != NULL) && (nickname == NULL)) ||
	    ((dbdir == NULL) && (nickname != NULL))) {
		printf(_("Database location or nickname specified "
		         "without the other.\n"));
		help(argv0, "request");
		return 1;
	}
	if ((dbdir != NULL) && (certfile != NULL)) {
		printf(_("Database directory and certificate file "
		         "both specified.\n"));
		help(argv0, "request");
		return 1;
	}
	if ((dbdir == NULL) &&
	    (nickname == NULL) &&
	    (certfile == NULL)) {
		printf(_("None of database directory and nickname or "
			 "certificate file specified.\n"));
		help(argv0, "request");
		return 1;
	}
	if ((certfile != NULL) && (keyfile != NULL) &&
	    (strcmp(certfile, keyfile) == 0)) {
		printf(_("Key and certificate can not both be saved to the "
			 "same file.\n"));
		help(argv0, "request");
		return 1;
	}
	i = 0;
	/* If the caller supplied _no_ naming information, substitute our own
	 * defaults. */
	if ((subject == subject_default) &&
	    (eku == NULL) &&
	    (principal == NULL) &&
	    (dns == NULL) &&
	    (email == NULL)) {
		add_string(globals.tctx, &eku, "id-kp-serverAuth");
		add_string(globals.tctx, &principal,
			   talloc_asprintf(globals.tctx,
					   "host/%s@%s", subject + 3, krealm));
		add_string(globals.tctx, &dns, subject + 3);
	}
	if ((dbdir != NULL) && (nickname != NULL)) {
		param[i].key = "KEY_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "NSSDB";
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = dbdir;
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nickname;
		params[i] = &param[i];
		i++;
		if (token != NULL) {
			param[i].key = "KEY_TOKEN";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = token;
			params[i] = &param[i];
			i++;
		}
		param[i].key = "CERT_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "NSSDB";
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = dbdir;
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nickname;
		params[i] = &param[i];
		i++;
		if (token != NULL) {
			param[i].key = "CERT_TOKEN";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = token;
			params[i] = &param[i];
			i++;
		}
	} else
	if (certfile != NULL) {
		if (keyfile != NULL) {
			param[i].key = "KEY_STORAGE";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = "FILE";
			params[i] = &param[i];
			i++;
			param[i].key = "KEY_LOCATION";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = keyfile;
			params[i] = &param[i];
			i++;
		} else {
			param[i].key = "KEY_STORAGE";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = "NONE";
			params[i] = &param[i];
			i++;
		}
		param[i].key = "CERT_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "FILE";
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = certfile;
		params[i] = &param[i];
		i++;
	}
	param[i].key = "TRACK";
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = TRUE;
	params[i] = &param[i];
	i++;
	param[i].key = "RENEW";
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = auto_renew > 0;
	params[i] = &param[i];
	i++;
	if (keysize > 0) {
		param[i].key = "KEY_TYPE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "RSA";
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_SIZE";
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = keysize;
		params[i] = &param[i];
		i++;
	}
	if (id != NULL) {
		param[i].key = "NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = id;
		params[i] = &param[i];
		i++;
	}
	if (ca != NULL) {
		if (ca != NULL) {
			capath = find_ca_by_name(globals.tctx, bus, ca);
			if (capath == NULL) {
				printf(_("No CA with name \"%s\" found.\n"),
				       ca);
				return 1;
			}
		} else {
			capath = NULL;
		}
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = capath;
		params[i] = &param[i];
		i++;
	}
	param[i].key = "SUBJECT";
	param[i].value_type = cm_tdbusm_dict_s;
	param[i].value.s = subject;
	params[i] = &param[i];
	i++;
	if (principal != NULL) {
		param[i].key = "PRINCIPAL";
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = principal;
		params[i] = &param[i];
		i++;
	}
	if (dns != NULL) {
		param[i].key = "DNS";
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = dns;
		params[i] = &param[i];
		i++;
	}
	if (email != NULL) {
		param[i].key = "EMAIL";
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = email;
		params[i] = &param[i];
		i++;
	}
	if (eku != NULL) {
		param[i].key = "EKU";
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = eku;
		params[i] = &param[i];
		i++;
	}
	params[i] = NULL;
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "add_request");
	if (cm_tdbusm_set_d(req, params) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname =  find_request_name(globals.tctx, bus, p);
		printf(_("New signing request \"%s\" added.\n"),
		       nickname ? nickname : p);
	} else {
		printf(_("New signing request could not be added.\n"));
		exit(1);
	}
	return 0;
}

static char *
find_request_name(void *parent, enum cm_tdbus_type bus, const char *path)
{
	return query_rep_s(bus, path, CM_DBUS_REQUEST_INTERFACE, "get_nickname",
			   parent);
}

static char *
find_ca_name(void *parent, enum cm_tdbus_type bus, const char *path)
{
	return query_rep_s(bus, path, CM_DBUS_CA_INTERFACE, "get_nickname",
			   parent);
}

static char *
find_request_by_name(void *parent, enum cm_tdbus_type bus, const char *name)
{
	char **requests;
	int i, which;
	char *thisname;
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", globals.tctx);
	which = -1;
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		thisname = find_request_name(parent, bus, requests[i]);
		if (thisname != NULL) {
			if (strcasecmp(name, thisname) == 0) {
				which = i;
			}
			talloc_free(thisname);
		}
	}
	if (which != -1) {
		return requests[which];
	}
	return NULL;
}

static const char *
find_request_by_storage(void *parent, enum cm_tdbus_type bus,
			const char *dbdir,
			const char *nickname,
			const char *token,
			const char *certfile)
{
	char **requests;
	int i, which;
	char *cert_stype, *cert_sloc, *cert_nick, *cert_tok;
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", globals.tctx);
	which = -1;
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		query_rep_sososos(bus, requests[i],
				  CM_DBUS_REQUEST_INTERFACE,
				  "get_cert_storage_info",
				  parent,
				  &cert_stype, &cert_sloc,
				  &cert_nick, &cert_tok);
		if (strcasecmp(cert_stype, "NSSDB") == 0) {
			if (dbdir == NULL) {
				continue;
			}
			if (strcmp(dbdir, cert_sloc) != 0) {
				continue;
			}
			if (nickname == NULL) {
				continue;
			}
			if (strcmp(nickname, cert_nick) != 0) {
				continue;
			}
			if (token && (strcmp(token, cert_tok) != 0)) {
				continue;
			}
		} else
		if (strcasecmp(cert_stype, "FILE") == 0) {
			if (certfile == NULL) {
				continue;
			}
			if (strcmp(certfile, cert_sloc) != 0) {
				continue;
			}
		}
		if (which != -1) {
			/* Multiple matches? We have to give up. */
			return NULL;
		}
		which = i;
	}
	if (which != -1) {
		return requests[which];
	}
	return NULL;
}

static char *
find_ca_by_name(void *parent, enum cm_tdbus_type bus, const char *name)
{
	char **cas;
	int i, which;
	char *thisname;
	cas = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			   "get_known_cas", globals.tctx);
	which = -1;
	for (i = 0; (cas != NULL) && (cas[i] != NULL); i++) {
		thisname = find_ca_name(parent, bus, cas[i]);
		if (thisname != NULL) {
			if (strcasecmp(name, thisname) == 0) {
				which = i;
			}
			talloc_free(thisname);
		}
	}
	if (which != -1) {
		return cas[which];
	}
	return NULL;
}

static int
add_basic_request(enum cm_tdbus_type bus, char *id,
		  char *dbdir, char *nickname, char *token,
		  char *keyfile, char *certfile,
		  char *ca, dbus_bool_t auto_renew)
{
	DBusMessage *req, *rep;
	int i;
	struct cm_tdbusm_dict param[17];
	const struct cm_tdbusm_dict *params[17];
	dbus_bool_t b;
	char *p;
	i = 0;
	if (id != NULL) {
		param[i].key = "NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = id;
		params[i] = &param[i];
		i++;
	}
	if ((dbdir != NULL) && (nickname != NULL)) {
		param[i].key = "KEY_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "NSSDB";
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = dbdir;
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nickname;
		params[i] = &param[i];
		i++;
		if (token != NULL) {
			param[i].key = "KEY_TOKEN";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = token;
			params[i] = &param[i];
			i++;
		}
		param[i].key = "CERT_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "NSSDB";
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = dbdir;
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nickname;
		params[i] = &param[i];
		i++;
		if (token != NULL) {
			param[i].key = "CERT_TOKEN";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = token;
			params[i] = &param[i];
			i++;
		}
	} else
	if (certfile != NULL) {
		if (keyfile != NULL) {
			param[i].key = "KEY_STORAGE";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = "FILE";
			params[i] = &param[i];
			i++;
			param[i].key = "KEY_LOCATION";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = keyfile;
			params[i] = &param[i];
			i++;
		}
		param[i].key = "CERT_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "FILE";
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = keyfile;
		params[i] = &param[i];
		i++;
	}
	param[i].key = "TRACK";
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = TRUE;
	params[i] = &param[i];
	i++;
	param[i].key = "RENEW";
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = auto_renew > 0;
	params[i] = &param[i];
	i++;
	params[i] = NULL;
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "add_request");
	if (cm_tdbusm_set_d(req, params) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname =  find_request_name(globals.tctx, bus, p);
		printf(_("New tracking request \"%s\" added.\n"),
		       nickname ? nickname : p);
		return 0;
	} else {
		printf(_("New tracking request could not be added.\n"));
		return 1;
	}
}

static int
set_tracking(const char *argv0, const char *category,
	     int argc, char **argv, dbus_bool_t track)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	DBusMessage *req, *rep;
	const char *request;
	struct cm_tdbusm_dict param[4];
	const struct cm_tdbusm_dict *params[5];
	char *dbdir = NULL, *token = NULL, *nickname = NULL;
	char *id = NULL, *new_id = NULL, *new_request;
	char *keyfile = NULL, *certfile = NULL, *ca = DEFAULT_CA;
	dbus_bool_t b;
	int c, auto_renew = 0, i;
	while ((c = getopt(argc, argv,
			   "d:n:t:k:f:g:ri:I:sS" GETOPT_CA)) != -1) {
		switch (c) {
		case 'd':
			dbdir = talloc_strdup(globals.tctx, optarg);
			break;
		case 't':
			token = talloc_strdup(globals.tctx, optarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, optarg);
			break;
		case 'k':
			keyfile = talloc_strdup(globals.tctx, optarg);
			break;
		case 'f':
			certfile = talloc_strdup(globals.tctx, optarg);
			break;
		case 'r':
			if (track) {
				auto_renew++;
			} else {
				help(argv0, category);
				return 1;
			}
			break;
		case 'c':
			if (track) {
				ca = talloc_strdup(globals.tctx, optarg);
			} else {
				help(argv0, category);
				return 1;
			}
			break;
		case 'i':
			id = talloc_strdup(globals.tctx, optarg);
			break;
		case 'I':
			new_id = talloc_strdup(globals.tctx, optarg);
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		default:
			help(argv0, category);
			return 1;
		}
	}
	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id);
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, nickname, token,
						  certfile);
	}
	if (track) {
		if (request != NULL) {
			/* Modify settings for an existing request. */
			i = 0;
			param[i].key = "TRACK";
			param[i].value_type = cm_tdbusm_dict_b;
			param[i].value.b = TRUE;
			params[i] = &param[i];
			i++;
			param[i].key = "RENEW";
			param[i].value_type = cm_tdbusm_dict_b;
			param[i].value.b = auto_renew > 0;
			params[i] = &param[i];
			i++;
			if (new_id != NULL) {
				param[i].key = "NICKNAME";
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = new_id;
				params[i] = &param[i];
				i++;
			}
			params[i] = NULL;
			req = prep_req(bus, request, CM_DBUS_REQUEST_INTERFACE,
				       "modify");
			if (cm_tdbusm_set_d(req, params) != 0) {
				printf(_("Error setting request arguments.\n"));
				exit(1);
			}
			rep = send_req(req);
			if (cm_tdbusm_get_bp(rep, globals.tctx, &b,
					     &new_request) != 0) {
				printf(_("Error parsing server response.\n"));
				exit(1);
			}
			request = new_request;
			dbus_message_unref(rep);
			nickname =  find_request_name(globals.tctx, bus,
						      request);
			if (b) {
				printf(_("Request \"%s\" modified.\n"),
				       nickname ? nickname : request);
				return 0;
			} else {
				printf(_("Request \"%s\" could not be "
					 "modified.\n"),
				       nickname ? nickname : request);
				return 1;
			}
		} else {
			/* Add a new request. */
			if (((dbdir != NULL) && (nickname == NULL)) ||
			    ((dbdir == NULL) && (nickname != NULL))) {
				printf(_("Database location or nickname "
				         "specified without the other.\n"));
				help(argv0, category);
				return 1;
			}
			if ((dbdir != NULL) && (certfile != NULL)) {
				printf(_("Database directory and certificate "
					 "file both specified.\n"));
				help(argv0, category);
				return 1;
			}
			if ((dbdir == NULL) &&
			    (nickname == NULL) &&
			    (certfile == NULL)) {
				printf(_("None of database directory and "
					 "nickname or certificate file "
					 "specified.\n"));
				help(argv0, category);
				return 1;
			}
			return add_basic_request(bus, id,
						 dbdir, nickname, token,
						 keyfile, certfile,
						 ca, (auto_renew > 0));
		}
	} else {
		/* Drop a request. */
		if ((request == NULL) &&
		    (id == NULL) &&
		    (dbdir == NULL) &&
		    (nickname == NULL) &&
		    (certfile == NULL)) {
			help(argv0, category);
			return 1;
		}
		if (request == NULL) {
			printf(_("No request found that matched arguments.\n"));
			return 1;
		}
		req = prep_req(bus, CM_DBUS_BASE_PATH,
			       CM_DBUS_BASE_INTERFACE,
			       "remove_request");
		if (cm_tdbusm_set_p(req, request) != 0) {
			printf(_("Error setting request arguments.\n"));
			exit(1);
		}
		rep = send_req(req);
		if (cm_tdbusm_get_b(rep, globals.tctx, &b) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		nickname = find_request_name(globals.tctx, bus, request);
		if (b) {
			printf(_("Request \"%s\" removed.\n"),
			       nickname ? nickname : request);
			return 0;
		} else {
			printf(_("Request \"%s\" could not be removed.\n"),
			       nickname ? nickname : request);
			return 1;
		}
	}
}

static int
start_tracking(const char *argv0, int argc, char **argv)
{
	return set_tracking(argv0, "start-tracking", argc, argv, TRUE);
}

static int
stop_tracking(const char *argv0, int argc, char **argv)
{
	return set_tracking(argv0, "stop-tracking", argc, argv, FALSE);
}

static int
resubmit(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	DBusMessage *req, *rep;
	const char *request, *capath;
	struct cm_tdbusm_dict param[15];
	const struct cm_tdbusm_dict *params[16];
	char *dbdir = NULL, *token = NULL, *nickname = NULL, *certfile = NULL;
	char *id = NULL, *new_id = NULL, *ca = NULL, *new_request;
	char *subject = NULL, **eku = NULL, *oid = NULL;
	char **principal = NULL, **dns = NULL, **email = NULL;
	dbus_bool_t b;
	int c, i;
	krb5_context kctx;
	krb5_error_code kret;
	krb5_principal kprincipal;
	char *krealm, *kuprincipal;

	kctx = NULL;
	if ((kret = krb5_init_context(&kctx)) != 0) {
		kctx = NULL;
		printf(_("Error initializing Kerberos library: %s.\n"),
		       error_message(kret));
		return 1;
	}
	krealm = NULL;
	if ((kret = krb5_get_default_realm(kctx, &krealm)) != 0) {
		printf(_("Error determining default Kerberos realm: %s.\n"),
		       error_message(kret));
		return 1;
	}
	if (krealm == NULL) {
		printf(_("Error determining default Kerberos realm.\n"));
		return 1;
	}

	while ((c = getopt(argc, argv,
			   "d:n:N:t:U:K:E:D:f:i:I:sS" GETOPT_CA)) != -1) {
		switch (c) {
		case 'd':
			dbdir = talloc_strdup(globals.tctx, optarg);
			break;
		case 't':
			token = talloc_strdup(globals.tctx, optarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, optarg);
			break;
		case 'f':
			certfile = talloc_strdup(globals.tctx, optarg);
			break;
		case 'c':
			ca = talloc_strdup(globals.tctx, optarg);
			break;
		case 'i':
			id = talloc_strdup(globals.tctx, optarg);
			break;
		case 'I':
			new_id = talloc_strdup(globals.tctx, optarg);
			break;
		case 'N':
			subject = talloc_strdup(globals.tctx, optarg);
			break;
		case 'U':
			oid = cm_oid_from_name(globals.tctx, optarg);
			if (strspn(oid, "0123456789.") != strlen(oid)) {
				printf(_("Could not evaluate OID \"%s\".\n"),
				       optarg);
				return 1;
			}
			add_string(globals.tctx, &eku, oid);
			break;
		case 'K':
			kprincipal = NULL;
			if ((kret = krb5_parse_name(kctx, optarg,
						    &kprincipal)) != 0) {
				printf(_("Error parsing Kerberos principal "
				         "name \"%s\": %s.\n"), optarg,
				       error_message(kret));
				return 1;
			}
			kuprincipal = NULL;
			if ((kret = krb5_unparse_name(kctx, kprincipal,
						      &kuprincipal)) != 0) {
				printf(_("Error unparsing Kerberos principal "
				         "name \"%s\": %s.\n"), optarg,
				       error_message(kret));
				return 1;
			}
			add_string(globals.tctx, &principal, kuprincipal);
			krb5_free_principal(kctx, kprincipal);
			break;
		case 'D':
			add_string(globals.tctx, &dns, optarg);
			break;
		case 'E':
			add_string(globals.tctx, &email, optarg);
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		default:
			help(argv0, "resubmit");
			return 1;
		}
	}
	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id);
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, nickname, token,
						  certfile);
	}
	if (request == NULL) {
		if (((dbdir != NULL) && (nickname == NULL)) ||
		    ((dbdir == NULL) && (nickname != NULL))) {
			printf(_("Database location or nickname "
				 "specified without the other.\n"));
			help(argv0, "resubmit");
			return 1;
		}
		if ((dbdir != NULL) && (certfile != NULL)) {
			printf(_("Database directory and certificate "
				 "file both specified.\n"));
			help(argv0, "resubmit");
			return 1;
		}
		if ((dbdir == NULL) &&
		    (nickname == NULL) &&
		    (certfile == NULL)) {
			printf(_("None of database directory and "
				 "nickname or certificate file "
				 "specified.\n"));
			help(argv0, "resubmit");
			return 1;
		}
		printf(_("No request found that matched arguments.\n"));
		return 1;
	}
	i = 0;
	if (new_id != NULL) {
		param[i].key = "NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = new_id;
		params[i] = &param[i];
		i++;
	}
	if (ca != NULL) {
		capath = find_ca_by_name(globals.tctx, bus, ca);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), ca);
			exit(1);
		}
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = talloc_strdup(globals.tctx, capath);
		params[i] = &param[i];
		i++;
	}
	if (subject != NULL) {
		param[i].key = "SUBJECT";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = subject;
		params[i] = &param[i];
		i++;
	}
	if (principal != NULL) {
		param[i].key = "PRINCIPAL";
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = principal;
		params[i] = &param[i];
		i++;
	}
	if (dns != NULL) {
		param[i].key = "DNS";
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = dns;
		params[i] = &param[i];
		i++;
	}
	if (email != NULL) {
		param[i].key = "EMAIL";
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = email;
		params[i] = &param[i];
		i++;
	}
	if (eku != NULL) {
		param[i].key = "EKU";
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = eku;
		params[i] = &param[i];
		i++;
	}
	params[i] = NULL;
	if (i > 0) {
		req = prep_req(bus, request, CM_DBUS_REQUEST_INTERFACE,
			       "modify");
		if (cm_tdbusm_set_d(req, params) != 0) {
			printf(_("Error setting request arguments.\n"));
			exit(1);
		}
		rep = send_req(req);
		if (cm_tdbusm_get_bp(rep, globals.tctx, &b,
				     &new_request) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		request = new_request;
		dbus_message_unref(rep);
		if (!b) {
			nickname = find_request_name(globals.tctx, bus,
						     request);
			printf(_("Error modifying \"%s\".\n"),
			       nickname ? nickname : request);
			exit(1);
		}
	}
	capath = query_rep_p(bus, request, CM_DBUS_REQUEST_INTERFACE,
			     "get_ca", globals.tctx);
	if (capath != NULL) {
		ca = find_ca_name(globals.tctx, bus, capath);
	} else {
		ca = NULL;
	}
	nickname = find_request_name(globals.tctx, bus, request);
	if (query_rep_b(bus, request, CM_DBUS_REQUEST_INTERFACE, "resubmit",
			globals.tctx)) {
		if (ca != NULL) {
			printf(_("Resubmitting \"%s\" to \"%s\".\n"),
			       nickname ? nickname : request, ca);
		} else {
			printf(_("Resubmitting \"%s\".\n"),
			       nickname ? nickname : request);
		}
		return 0;
	} else {
		if (ca != NULL) {
			printf(_("Error attempting to submit \"%s\" to "
				 "\"%s\".\n"), request, ca);
		} else {
			printf(_("Error attempting to submit \"%s\".\n"),
			       request);
		}
		return 1;
	}
}

static int
list(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	enum cm_state state;
	DBusMessage *rep;
	char **requests, *s, *p, *nickname, *only_ca = DEFAULT_CA, *ca_name;
	dbus_bool_t b;
	char *s1, *s2, *s3, *s4;
	long n1, n2;
	char **as1, **as2, **as3, **as4, t[15];
	int requests_only = 0, tracking_only = 0, c, i, j;
	while ((c = getopt(argc, argv, "rtsS" GETOPT_CA)) != -1) {
		switch (c) {
		case 'c':
			only_ca = optarg;
			break;
		case 'r':
			requests_only++;
			break;
		case 't':
			tracking_only++;
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		default:
			help(argv0, "list");
			return 1;
		}
	}
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", globals.tctx);
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		/* Filter out based on the CA. */
		ca_name = NULL;
		rep = query_rep(bus, requests[i],
				CM_DBUS_REQUEST_INTERFACE, "get_ca");
		if (cm_tdbusm_get_p(rep, globals.tctx, &p) == 0) {
			ca_name = find_ca_name(globals.tctx, bus, p);
		}
		dbus_message_unref(rep);
		if (only_ca != NULL) {
			if (ca_name == NULL) {
				continue;
			}
			if (strcmp(only_ca, ca_name) != 0) {
				continue;
			}
		}
		/* Get the status of this request. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_status");
		if (cm_tdbusm_get_sb(rep, globals.tctx, &s, &b) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		/* Filter out based on the current state. */
		state = cm_store_state_from_string(s);
		switch (state) {
		case CM_INVALID:
			printf(("'%s' is in an invalid state!\n"), s);
			continue;
			break;
		case CM_NEED_KEY_PAIR:
		case CM_GENERATING_KEY_PAIR:
		case CM_HAVE_KEY_PAIR:
		case CM_NEED_CSR:
		case CM_GENERATING_CSR:
		case CM_HAVE_CSR:
		case CM_NEED_TO_SUBMIT:
		case CM_SUBMITTING:
		case CM_NEED_TO_SAVE_CERT:
		case CM_SAVING_CERT:
		case CM_SAVED_CERT:
		case CM_NEED_TO_READ_CERT:
		case CM_READING_CERT:
		case CM_CA_WORKING:
		case CM_CA_REJECTED:
		case CM_CA_UNREACHABLE:
		case CM_NEED_GUIDANCE:
		case CM_NEED_CA:
		case CM_NEWLY_ADDED:
		case CM_NEWLY_ADDED_START_READING_CERT:
		case CM_NEWLY_ADDED_READING_KEYI:
		case CM_NEWLY_ADDED_READING_CERT:
		case CM_NEWLY_ADDED_DECIDING:
			if (tracking_only) {
				continue;
			}
			break;
		case CM_MONITORING:
		case CM_NEED_TO_NOTIFY:
		case CM_NOTIFYING:
			if (requests_only) {
				continue;
			}
			break;
		}
		/* Basic info. */
		nickname = find_request_name(globals.tctx, bus, requests[i]);
		printf(_("Request '%s':\n"), nickname);
		printf(_("\tstatus: %s\n"), s);
		printf(_("\tstuck: %s\n"), b ? "yes" : "no");
		/* Get key/cert storage info. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_key_storage_info");
		if (cm_tdbusm_get_sososos(rep, globals.tctx,
				          &s1, &s2, &s3, &s4) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		printf(_("\tkey pair storage: %s%s%s%s%s%s%s%s%s\n"),
		       strcmp(s1, "NONE") ? _("type=") : "", s1 ? s1 : "",
		       s2 ? _(",location='") : "", s2 ? s2 : "", s2 ? "'" : "",
		       s3 ? _(",nickname=") : "", s3 ? s3 : "",
		       s4 ? _(",token=") : "", s4 ? s4 : "");
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_cert_storage_info");
		if (cm_tdbusm_get_ssosos(rep, globals.tctx,
				         &s1, &s2, &s3, &s4) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		printf(_("\tcertificate: type=%s,location='%s'%s%s%s%s\n"),
		       s1, s2,
		       s3 ? _(",nickname=") : "", s3 ? s3 : "",
		       s4 ? _(",token=") : "", s4 ? s4 : "");
		/* Information from the certificate. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_cert_info");
		if (cm_tdbusm_get_sssnasasasnas(rep, globals.tctx,
						&s1, &s2, &s3, &n1,
						&as1, &as2, &as3,
						&n2, &as4) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		if (ca_name != NULL) {
			printf(_("\tCA: %s\n"), ca_name);
		}
		printf(_("\tissuer: %s\n"), s1);
		printf(_("\tsubject: %s\n"), s3);
		printf(_("\texpires: %s\n"),
		       n1 ? cm_store_timestamp_from_time(n1, t) : _("unknown"));
		for (j = 0; (as1 != NULL) && (as1[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\temail: ") : ",",
			       as1[j],
			       as1[j + 1] ? "" : "\n");
		}
		for (j = 0; (as2 != NULL) && (as2[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\tdns: ") : ",",
			       as2[j],
			       as2[j + 1] ? "" : "\n");
		}
		for (j = 0; (as3 != NULL) && (as3[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\tprincipal name: ") : ",",
			       as3[j],
			       as3[j + 1] ? "" : "\n");
		}
		for (j = 0; (as4 != NULL) && (as4[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\teku: ") : ",",
			       cm_oid_to_name(NULL, as4[j]),
			       as4[j + 1] ? "" : "\n");
		}
		printf(_("\ttrack: %s\n"),
		       query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   "get_monitoring", globals.tctx) ?
		       "yes" : "no");
		printf(_("\tauto-renew: %s\n"),
		       query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   "get_autorenew", globals.tctx) ?
		       "yes" : "no");
	}
	return 0;
}

static int
list_cas(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char **cas, *s, *only_ca = DEFAULT_CA, *ca_name;
	char **as;
	int c, i, j;
	while ((c = getopt(argc, argv, "sS" GETOPT_CA)) != -1) {
		switch (c) {
		case 'c':
			only_ca = optarg;
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		default:
			help(argv0, "list");
			return 1;
		}
	}
	cas = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			   "get_known_cas", globals.tctx);
	for (i = 0; (cas != NULL) && (cas[i] != NULL); i++) {
		/* Filter out based on the CA. */
		ca_name = NULL;
		s = find_ca_name(globals.tctx, bus, cas[i]);
		if (s != NULL) {
			if ((only_ca != NULL) && (strcmp(s, only_ca) != 0)) {
				continue;
			}
		}
		printf(_("CA '%s':\n"), s);
		printf("\tis-default: %s\n",
		       query_rep_b(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   "get_is_default", globals.tctx) ?
		       "yes" : "no");
		s = query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
				"get_type", globals.tctx);
		printf(_("\tca-type: %s\n"), s);
		if (strcmp(s, "EXTERNAL") == 0) {
			printf(_("\thelper-location: %s\n"),
			       query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					   "get_location", globals.tctx));
		} else {
			printf(_("\tnext-serial-number: %s\n"),
			       query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					   "get_serial", globals.tctx));
		}
		as = query_rep_as(bus, cas[i],
				  CM_DBUS_CA_INTERFACE, "get_issuer_names",
				  globals.tctx);
		if (as != NULL) {
			printf(_("\tknown-issuer-names:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
	}
	return 0;
}

static struct {
	const char *verb;
	int (*fn)(const char *, int, char **);
} verbs[] = {
	{"request", request},
	{"start-tracking", start_tracking},
	{"stop-tracking", stop_tracking},
	{"resubmit", resubmit},
	{"list", list},
	{"list-cas", list_cas},
};

static void
help(const char *cmd, const char *category)
{
	unsigned int i, j;
	const char *general_help[] = {
		N_("%s - client certificate enrollment tool\n"),
		NULL,
	};
	const char *request_help[] = {
		N_("Usage: %s request [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR	NSS database for key and cert\n"),
		N_("  -n NAME	nickname for NSS-based storage (only valid with -d)\n"),
		N_("  -t NAME	optional token name for NSS-based storage (only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -k FILE	PEM file for private key\n"),
		N_("  -f FILE	PEM file for certificate (only valid with -k)\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME	nickname to assign to the request\n"),
		N_("  -g SIZE	size of key to be generated if one is not already in place\n"),
		N_("  -r		attempt to refresh the certificate when expiration nears\n"),
#ifndef FORCE_CA
		N_("  -c CA		use the specified CA rather than the default\n"),
#endif
		N_("* Parameters for the signing request:\n"),
		N_("  -N NAME	set requested subject name (default: CN=<hostname>)\n"),
		N_("  -U EXTUSAGE	set requested extended key usage OID\n"),
		N_("  -K NAME	set requested principal name\n"),
		N_("  -D DNSNAME	set requested DNS name\n"),
		N_("  -E EMAIL	set requested email address\n"),
		N_("* Bus options:\n"),
		N_("  -S		connect to the certmonger service on the system bus\n"),
		N_("  -s		connect to the certmonger service on the session bus\n"),
		NULL,
	};
	const char *start_tracking_help[] = {
		N_("Usage: %s start-tracking [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* If modifying an existing request:\n"),
		N_("  -i NAME	nickname of an existing tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR	NSS database for key and cert\n"),
		N_("  -n NAME	nickname for NSS-based storage (only valid with -d)\n"),
		N_("  -t NAME	optional token name for NSS-based storage (only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -k FILE	PEM file for private key\n"),
		N_("  -f FILE	PEM file for certificate (only valid with -k)\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME	nickname to give to tracking request\n"),
		N_("  -r		attempt to renew the certificate when expiration nears\n"),
#ifndef FORCE_CA
		N_("  -c CA		use the specified CA rather than the default\n"),
#endif
		N_("* Bus options:\n"),
		N_("  -S		connect to the certmonger service on the system bus\n"),
		N_("  -s		connect to the certmonger service on the session bus\n"),
		NULL,
	};
	const char *stop_tracking_help[] = {
		N_("Usage: %s stop-tracking [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* By request identifier:\n"),
		N_("  -i NAME	nickname for tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR	NSS database for key and cert\n"),
		N_("  -n NAME	nickname for NSS-based storage (only valid with -d)\n"),
		N_("  -t NAME	optional token name for NSS-based storage (only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -k FILE	PEM file for private key\n"),
		N_("  -f FILE	PEM file for certificate (only valid with -k)\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Bus options:\n"),
		N_("  -S		connect to the certmonger service on the system bus\n"),
		N_("  -s		connect to the certmonger service on the session bus\n"),
		NULL,
	};
	const char *resubmit_help[] = {
		N_("Usage: %s resubmit [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* By request identifier:\n"),
		N_("  -i NAME	nickname for tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR	NSS database for key and cert\n"),
		N_("  -n NAME	nickname for NSS-based storage (only valid with -d)\n"),
		N_("  -t NAME	optional token name for NSS-based storage (only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -f FILE	PEM file for certificate\n"),
		"\n",
		N_("* New parameter values for the signing request:\n"),
		N_("  -N NAME	set requested subject name (default: CN=<hostname>)\n"),
		N_("  -U EXTUSAGE	set requested extended key usage OID\n"),
		N_("  -K NAME	set requested principal name\n"),
		N_("  -D DNSNAME	set requested DNS name\n"),
		N_("  -E EMAIL	set requested email address\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME	new nickname to give to tracking request\n"),
#ifndef FORCE_CA
		N_("  -c CA		use the specified CA rather than the current one\n"),
#endif
		N_("* Bus options:\n"),
		N_("  -S		connect to the certmonger service on the system bus\n"),
		N_("  -s		connect to the certmonger service on the session bus\n"),
		NULL,
	};
	const char *list_help[] = {
		N_("Usage: %s list [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* General options:\n"),
#ifndef FORCE_CA
		N_("  -c CA	list only requests and certs associated with this CA\n"),
#endif
		N_("  -r	list only information about outstanding requests\n"),
		N_("  -t	list only information about tracked certificates\n"),
		N_("* Bus options:\n"),
		N_("  -S	connect to the certmonger service on the system bus\n"),
		N_("  -s	connect to the certmonger service on the session bus\n"),
		NULL,
	};
	const char *list_cas_help[] = {
		N_("Usage: %s list-cas [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
#ifndef FORCE_CA
		N_("* General options:\n"),
		N_("  -c CA	list only information about the CA with this name\n"),
#endif
		N_("* Bus options:\n"),
		N_("  -S	connect to the certmonger service on the system bus\n"),
		N_("  -s	connect to the certmonger service on the session bus\n"),
		NULL,
	};
	struct {
		const char *category;
		const char **msgs;
	} msgs[] = {
		{NULL, general_help},
		{"request", request_help},
		{"start-tracking", start_tracking_help},
		{"stop-tracking", stop_tracking_help},
		{"resubmit", resubmit_help},
		{"list", list_help},
		{"list-cas", list_cas_help},
	};
	for (i = 0; i < sizeof(msgs) / sizeof(msgs[0]); i++) {
		if ((category != NULL) && (msgs[i].category != NULL) &&
		    (strcmp(category, msgs[i].category) != 0)) {
			continue;
		}
		if (i > 0) {
			printf("\n");
		}
		for (j = 0; msgs[i].msgs[j] != NULL; j++) {
			printf(_(msgs[i].msgs[j]), cmd);
		}
	}
}

int
main(int argc, char **argv)
{
	const char *verb, *p;
	unsigned int i;
	p = argv[0];
	if (strchr(p, '/') != NULL) {
		p = strrchr(p, '/') + 1;
	}
	if (argc > 1) {
		verb = argv[1];
		globals.tctx = talloc_new(NULL);
		for (i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
			if (strcmp(verbs[i].verb, verb) == 0) {
				return (*verbs[i].fn)(p, argc - 1, argv + 1);
			}
		}
		talloc_free(globals.tctx);
		globals.tctx = NULL;
		fprintf(stderr, _("%s: unrecognized command\n"), verb);
		if (verb[0] == '-') {
			help(p, NULL);
		}
		return 1;
	} else {
		help(p, NULL);
		return 1;
	}
}
