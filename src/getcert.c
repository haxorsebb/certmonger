/*
 * Copyright (C) 2009,2010,2011,2012 Red Hat, Inc.
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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
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

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif
#define N_(_msg) (_msg)

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
			     const char *nickname, int verbose);
static char *find_request_by_name(void *parent, enum cm_tdbus_type bus,
				  const char *path, int verbose);
static char *find_ca_name(void *parent, enum cm_tdbus_type bus,
			  const char *path, int verbose);
static char *find_request_name(void *parent, enum cm_tdbus_type bus,
			       const char *path, int verbose);

/* Ensure that a pathname is an absolute pathname. */
static char *
ensure_path_is_absolute(void *parent, const char *path)
{
	char buf[PATH_MAX + 1], *ret;
	if (path[0] == '/') {
		return talloc_strdup(parent, path);
	} else {
		if (getcwd(buf, sizeof(buf)) == buf) {
			ret = talloc_asprintf(parent, "%s/%s", buf, path);
			printf(_("Path \"%s\" is not absolute, "
				 "attempting to "
				 "use \"%s\" instead.\n"), path, ret);
			return ret;
		} else {
			printf(_("Path \"%s\" is not absolute, and "
				 "there was an error determining the "
				 "name of the current directory.\n"),
			       path);
			exit(1);
		}
	}
}

/* Ensure that a pathname is a directory. */
static int
ensure_path_is_directory(char *path)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			return 0;
		} else {
			printf(_("Path \"%s\" is not a directory.\n"),
			       path);
			return -1;
		}
	} else {
		printf(_("Path \"%s\": %s.\n"), path, strerror(errno));
		return -1;
	}
}

/* Ensure that a pathname is at least in a directory which exists. */
static int
ensure_parent_is_directory(void *parent, const char *path)
{
	char *tmp, *p;
	tmp = talloc_strdup(parent, path);
	if (tmp != NULL) {
		p = strrchr(tmp, '/');
		if (p != NULL) {
			if (p > tmp) {
				*p = '\0';
			} else {
				*(p + 1) = '\0';
			}
			return ensure_path_is_directory(tmp);
		}
	}
	return -1;
}

/* Ensure that a pathname is a regular file or missing. */
static int
ensure_path_is_regular(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISREG(st.st_mode)) {
			return 0;
		}
	} else {
		if (errno == ENOENT) {
			return 0;
		}
	}
	printf(_("Path \"%s\" is not a regular file.\n"), path);
	return -1;
}

/* Ensure that we have a suitable NSS database location. */
static char *
ensure_nss(void *parent, const char *path, char **nss_scheme)
{
	char *ret;
	*nss_scheme = NULL;
	if (strncmp(path, "sql:", 4) == 0) {
		*nss_scheme = talloc_strdup(parent, "sql");
		path += 4;
	} else
	if (strncmp(path, "dbm:", 4) == 0) {
		*nss_scheme = talloc_strdup(parent, "dbm");
		path += 4;
	} else
	if (strncmp(path, "rdb:", 4) == 0) {
		*nss_scheme = talloc_strdup(parent, "rdb");
		path += 4;
	} else
	if (strncmp(path, "extern:", 7) == 0) {
		*nss_scheme = talloc_strdup(parent, "extern");
		path += 7;
	}
	ret = ensure_path_is_absolute(parent, path);
	if (ret != NULL) {
		ret = cm_store_canonicalize_directory(parent, ret);
	}
	if (ret != NULL) {
		if (ensure_path_is_directory(ret) != 0) {
			ret = NULL;
		}
	}
	if (ret == NULL) {
		exit(1);
	}
	return ret;
}

/* Ensure that we have a suitable location for a PEM file. */
static char *
ensure_pem(void *parent, const char *path)
{
	char *ret;
	ret = ensure_path_is_absolute(parent, path);
	if (ret != NULL) {
		ret = cm_store_canonicalize_directory(parent, ret);
	}
	if (ret != NULL) {
		if (ensure_parent_is_directory(parent, ret) != 0) {
			ret = NULL;
		}
	}
	if (ret != NULL) {
		if (ensure_path_is_regular(ret) != 0) {
			ret = NULL;
		}
	}
	if (ret == NULL) {
		exit(1);
	}
	return ret;
}

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
		printf(_("Out of memory.\n"));
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
			printf(_("Please verify that the message bus (D-Bus) service is running.\n"));
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

/* Try to offer some advice based on the error. */
static enum { hint_unknown, hint_found }
print_hint(const char *error, const char *message)
{
	char *text = NULL;
	void *ctx;
	ctx = talloc_new(NULL);
	text = cm_tdbusm_hint(ctx, error, message);
	if ((text == NULL) &&
	    (strncmp(error, CM_DBUS_ERROR_BASE,
		     strlen(CM_DBUS_ERROR_BASE)) == 0)) {
		text = talloc_asprintf(ctx, "%s\n", _(message));
	}
	if (text != NULL) {
		printf("%s", _(text));
	}
	talloc_free(ctx);
	return text ? hint_found : hint_unknown;
}

/* Send our request and return the response.  If there's an error, exit. */
static DBusMessage *
send_req(DBusMessage *req, int verbose)
{
	DBusMessage *rep;
	DBusError err;
	memset(&err, 0, sizeof(err));
	rep = dbus_connection_send_with_reply_and_block(globals.conn, req,
							30 * 1000, &err);
	if (rep == NULL) {
		if (dbus_error_is_set(&err)) {
			if (err.name != NULL) {
				if ((print_hint(err.name,
						err.message) == hint_unknown) ||
				    verbose) {
					if ((err.message != NULL) && verbose) {
						printf(_("Error %s: %s\n"),
						       err.name,
						       err.message);
					} else {
						printf(_("Error %s\n"),
						       err.name);
					}
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
	  const char *path, const char *interface, const char *method,
	  int verbose)
{
	return send_req(prep_req(which, path, interface, method), verbose);
}

/* Send the specified, argument-less method call to the named object, and
 * return a sole boolean response. */
static dbus_bool_t
query_rep_b(enum cm_tdbus_type which,
	    const char *path, const char *interface, const char *method,
	    int verbose,
	    void *parent)
{
	DBusMessage *rep;
	dbus_bool_t b;
	rep = query_rep(which, path, interface, method, verbose);
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
	    int verbose,
	    void *parent)
{
	DBusMessage *rep;
	char *s;
	rep = query_rep(which, path, interface, method, verbose);
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
	    int verbose,
	    void *parent)
{
	DBusMessage *rep;
	char *p;
	rep = query_rep(which, path, interface, method, verbose);
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
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	char **as;
	rep = query_rep(which, path, interface, method, verbose);
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
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	char **ap;
	rep = query_rep(which, path, interface, method, verbose);
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
		  int verbose,
		  void *parent, char **s1, char **s2, char **s3, char **s4)
{
	DBusMessage *rep;
	rep = query_rep(which, path, interface, method, verbose);
	if (cm_tdbusm_get_sososos(rep, parent, s1, s2, s3, s4) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
}

/* Send a query for the value of the specified property to the named object and
 * return the reply message. */
static DBusMessage *
query_prop(enum cm_tdbus_type which,
	   const char *path, const char *interface, const char *prop,
	   int verbose)
{
	DBusMessage *req;
	req = prep_req(which, path, DBUS_INTERFACE_PROPERTIES, "Get");
	cm_tdbusm_set_ss(req, interface, prop);
	return send_req(req, verbose);
}

/* Read a boolean property. */
static dbus_bool_t
query_prop_b(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *prop,
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	dbus_bool_t b;
	rep = query_prop(which, path, interface, prop, verbose);
	if (cm_tdbusm_get_b(rep, parent, &b) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return b;
}

/* Read a string property. */
static char *
query_prop_s(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *prop,
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	char *s;
	rep = query_prop(which, path, interface, prop, verbose);
	if (cm_tdbusm_get_s(rep, parent, &s) != 0) {
		s = "";
	}
	dbus_message_unref(rep);
	return s;
}

/* Read a path property. */
static char *
query_prop_p(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *prop,
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	char *p;
	rep = query_prop(which, path, interface, prop, verbose);
	if (cm_tdbusm_get_p(rep, parent, &p) != 0) {
		p = "";
	}
	dbus_message_unref(rep);
	return p;
}

/* Read an array-of-strings property. */
static char **
query_prop_as(enum cm_tdbus_type which,
	      const char *path, const char *interface, const char *prop,
	      int verbose,
	      void *parent)
{
	DBusMessage *rep;
	char **as;
	rep = query_prop(which, path, interface, prop, verbose);
	if (cm_tdbusm_get_as(rep, parent, &as) != 0) {
		as = NULL;
	}
	dbus_message_unref(rep);
	return as;
}

/* Add a new request. */
static int
request(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char subject_default[LINE_MAX];
	char *nss_scheme, *dbdir = NULL, *token = NULL, *nickname = NULL;
	char *keyfile = NULL, *certfile = NULL, *capath;
	char *pin = NULL, *pinfile = NULL;
	int keysize = 0, auto_renew = 1, verbose = 0, c, i;
	char *ca = DEFAULT_CA, *subject = NULL, **eku = NULL, *oid, *id = NULL;
	char *profile = NULL;
	char **principal = NULL, **dns = NULL, **email = NULL;
	struct cm_tdbusm_dict param[35];
	const struct cm_tdbusm_dict *params[36];
	DBusMessage *req, *rep;
	dbus_bool_t b;
	char *p;
	krb5_context kctx;
	krb5_error_code kret;
	krb5_principal kprincipal;
	char *krealm, *kuprincipal, *precommand = NULL, *postcommand = NULL;

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
		krealm = NULL;
	}

	opterr = 0;
	while ((c = getopt(argc, argv,
			   ":d:n:t:k:f:I:g:rRN:U:K:D:E:sSp:P:vB:C:T:"
			   GETOPT_CA)) != -1) {
		switch (c) {
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, optarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 't':
			token = talloc_strdup(globals.tctx, optarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, optarg);
			break;
		case 'k':
			keyfile = ensure_pem(globals.tctx, optarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, optarg);
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
		case 'R':
			auto_renew = 0;
			break;
		case 'c':
			ca = talloc_strdup(globals.tctx, optarg);
			break;
		case 'T':
			profile = talloc_strdup(globals.tctx, optarg);
			break;
		case 'N':
			subject = talloc_strdup(globals.tctx, optarg);
			break;
		case 'U':
			oid = cm_oid_from_name(globals.tctx, optarg);
			if ((oid == NULL) ||
			    (strspn(oid, "0123456789.") != strlen(oid))) {
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
		case 'p':
			pinfile = optarg;
			break;
		case 'P':
			pin = optarg;
			break;
		case 'B':
			precommand = optarg;
			break;
		case 'C':
			postcommand = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					"request", optopt);
			} else {
				fprintf(stderr,
					_("%s: invalid option -- '%c'\n"),
					"request", optopt);
			}
			help(argv0, "request");
			return 1;
		}
	}
	if (optind < argc) {
		for (c = optind; c < argc; c++) {
			printf(_("Error: unused extra argument \"%s\".\n"),
			       argv[c]);
		}
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "request");
		return 1;
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
		if (krealm != NULL) {
			add_string(globals.tctx, &principal,
				   talloc_asprintf(globals.tctx,
						   "host/%s@%s",
						   subject + 3, krealm));
		}
		add_string(globals.tctx, &dns, subject + 3);
	}
#ifdef WITH_IPA
	if ((ca != NULL) && (strcmp(ca, "IPA") == 0)) {
		if (principal == NULL) {
			printf(_("The IPA backend requires the use of the "
				 "-K option (principal name) when the "
				 "-N option (subject name) is used.\n"));
			help(argv0, "request");
			return 1;
		}
	}
#endif
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
	if (pin != NULL) {
		param[i].key = "KEY_PIN";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pin;
		params[i] = &param[i];
		i++;
	}
	if (pinfile != NULL) {
		param[i].key = "KEY_PIN_FILE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pinfile;
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
		capath = find_ca_by_name(globals.tctx, bus, ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), ca);
			return 1;
		}
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_p;
		param[i].value.s = capath;
		params[i] = &param[i];
		i++;
	} else {
		capath = NULL;
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
	if (profile != NULL) {
		param[i].key = CM_DBUS_PROP_CA_PROFILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = profile;
		params[i] = &param[i];
		i++;
	}
	if (precommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = precommand;
		params[i] = &param[i];
		i++;
	}
	if (postcommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = postcommand;
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
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname = find_request_name(globals.tctx, bus, p, verbose);
		printf(_("New signing request \"%s\" added.\n"),
		       nickname ? nickname : p);
	} else {
		printf(_("New signing request could not be added.\n"));
		exit(1);
	}
	return 0;
}

static char *
find_request_name(void *parent, enum cm_tdbus_type bus, const char *path,
		  int verbose)
{
	return query_rep_s(bus, path, CM_DBUS_REQUEST_INTERFACE, "get_nickname",
			   verbose, parent);
}

static char *
find_ca_name(void *parent, enum cm_tdbus_type bus, const char *path,
	     int verbose)
{
	return query_rep_s(bus, path, CM_DBUS_CA_INTERFACE, "get_nickname",
			   verbose, parent);
}

static char *
find_request_by_name(void *parent, enum cm_tdbus_type bus, const char *name,
		     int verbose)
{
	char **requests;
	int i, which;
	char *thisname;
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", verbose, globals.tctx);
	which = -1;
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		thisname = find_request_name(parent, bus, requests[i], verbose);
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
			const char *certfile,
			int verbose)
{
	char **requests;
	int i, which;
	char *cert_stype, *cert_sloc, *cert_nick, *cert_tok;
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", verbose, globals.tctx);
	which = -1;
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		query_rep_sososos(bus, requests[i],
				  CM_DBUS_REQUEST_INTERFACE,
				  "get_cert_storage_info",
				  verbose, parent,
				  &cert_stype, &cert_sloc,
				  &cert_nick, &cert_tok);
		if (strcasecmp(cert_stype, "NSSDB") == 0) {
			if (dbdir == NULL) {
				continue;
			}
			if ((cert_sloc == NULL) ||
			    (strcmp(dbdir, cert_sloc) != 0)) {
				continue;
			}
			if (nickname == NULL) {
				continue;
			}
			if ((cert_nick == NULL) ||
			    (strcmp(nickname, cert_nick) != 0)) {
				continue;
			}
			if ((token != NULL) &&
			    ((cert_tok == NULL) ||
			     (strcmp(token, cert_tok) != 0))) {
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
find_ca_by_name(void *parent, enum cm_tdbus_type bus, const char *name,
		int verbose)
{
	char **cas;
	int i, which;
	char *thisname;
	cas = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			   "get_known_cas", verbose, globals.tctx);
	which = -1;
	for (i = 0; (cas != NULL) && (cas[i] != NULL); i++) {
		thisname = find_ca_name(parent, bus, cas[i], verbose);
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
		  char *pin, char *pinfile,
		  char *ca, char *profile,
		  char *precommand, char *postcommand,
		  dbus_bool_t auto_renew_stop, int verbose)
{
	DBusMessage *req, *rep;
	int i;
	struct cm_tdbusm_dict param[22];
	const struct cm_tdbusm_dict *params[23];
	dbus_bool_t b;
	const char *capath;
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
		param[i].value.s = certfile;
		params[i] = &param[i];
		i++;
	}
	if (pin != NULL) {
		param[i].key = "KEY_PIN";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pin;
		params[i] = &param[i];
		i++;
	}
	if (pinfile != NULL) {
		param[i].key = "KEY_PIN_FILE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pinfile;
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
	param[i].value.b = !auto_renew_stop;
	params[i] = &param[i];
	i++;
	if (profile != NULL) {
		param[i].key = CM_DBUS_PROP_CA_PROFILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = profile;
		params[i] = &param[i];
		i++;
	}
	if (precommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = precommand;
		params[i] = &param[i];
		i++;
	}
	if (postcommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = postcommand;
		params[i] = &param[i];
		i++;
	}
	if (ca != NULL) {
		capath = find_ca_by_name(globals.tctx, bus, ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), ca);
			return 1;
		}
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_p;
		param[i].value.s = talloc_strdup(globals.tctx, capath);
		params[i] = &param[i];
		i++;
	} else {
		capath = NULL;
	}
	params[i] = NULL;
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "add_request");
	if (cm_tdbusm_set_d(req, params) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname = find_request_name(globals.tctx, bus, p, verbose);
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
	const char *request, *capath;
	struct cm_tdbusm_dict param[13];
	const struct cm_tdbusm_dict *params[14];
	char *nss_scheme, *dbdir = NULL, *token = NULL, *nickname = NULL;
	char *id = NULL, *new_id = NULL, *new_request;
	char *keyfile = NULL, *certfile = NULL, *ca = DEFAULT_CA;
	char *profile = NULL;
	char *pin = NULL, *pinfile = NULL;
	dbus_bool_t b;
	int c, auto_renew_start = 0, auto_renew_stop = 0, verbose = 0, i;
	char **eku = NULL, *oid;
	char **principal = NULL, **dns = NULL, **email = NULL;
	krb5_context kctx;
	krb5_error_code kret;
	krb5_principal kprincipal;
	char *krealm, *kuprincipal;
	char *precommand = NULL, *postcommand = NULL;

	kctx = NULL;
	if ((kret = krb5_init_context(&kctx)) != 0) {
		kctx = NULL;
		printf(_("Error initializing Kerberos library: %s.\n"),
		       error_message(kret));
		return 1;
	}
	krealm = NULL;
	if ((kret = krb5_get_default_realm(kctx, &krealm)) != 0) {
		krealm = NULL;
	}

	opterr = 0;
	while ((c = getopt(argc, argv,
			   ":d:n:t:k:f:g:p:P:rRi:I:U:K:D:E:sSvB:C:T:"
			   GETOPT_CA)) != -1) {
		switch (c) {
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, optarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 't':
			token = talloc_strdup(globals.tctx, optarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, optarg);
			break;
		case 'k':
			keyfile = ensure_pem(globals.tctx, optarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, optarg);
			break;
		case 'r':
			if (track) {
				auto_renew_start++;
			} else {
				help(argv0, category);
				return 1;
			}
			break;
		case 'R':
			if (track) {
				auto_renew_stop++;
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
		case 'T':
			profile = talloc_strdup(globals.tctx, optarg);
			break;
		case 'i':
			id = talloc_strdup(globals.tctx, optarg);
			break;
		case 'I':
			new_id = talloc_strdup(globals.tctx, optarg);
			break;
		case 'U':
			oid = cm_oid_from_name(globals.tctx, optarg);
			if ((oid == NULL) ||
			    (strspn(oid, "0123456789.") != strlen(oid))) {
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
		case 'p':
			pinfile = optarg;
			break;
		case 'P':
			pin = optarg;
			break;
		case 'B':
			precommand = optarg;
			break;
		case 'C':
			postcommand = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					category, optopt);
			} else {
				fprintf(stderr, _("%s: invalid option -- '%c'\n"),
					category, optopt);
			}
			help(argv0, category);
			return 1;
		}
	}

	krb5_free_context(kctx);

	if (optind < argc) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, category);
		return 1;
	}
	if (((dbdir != NULL) && (nickname == NULL)) ||
	    ((dbdir == NULL) && (nickname != NULL))) {
		printf(_("Database location or nickname specified "
		         "without the other.\n"));
		help(argv0, category);
		return 1;
	}
	if ((dbdir != NULL) && (certfile != NULL)) {
		printf(_("Database directory and certificate file "
		         "both specified.\n"));
		help(argv0, category);
		return 1;
	}
	if ((id == NULL) &&
	    (dbdir == NULL) &&
	    (nickname == NULL) &&
	    (certfile == NULL)) {
		printf(_("None of ID or database directory and nickname or "
			 "certificate file specified.\n"));
		help(argv0, category);
		return 1;
	}
	if ((certfile != NULL) && (keyfile != NULL) &&
	    (strcmp(certfile, keyfile) == 0)) {
		printf(_("Key and certificate can not both be saved to the "
			 "same file.\n"));
		help(argv0, category);
		return 1;
	}
	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id, verbose);
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, nickname, token,
						  certfile, verbose);
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
			if (auto_renew_start || auto_renew_stop) {
				param[i].key = "RENEW";
				param[i].value_type = cm_tdbusm_dict_b;
				param[i].value.b = auto_renew_start > 0;
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
			if (new_id != NULL) {
				param[i].key = "NICKNAME";
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = new_id;
				params[i] = &param[i];
				i++;
			}
			if (pin != NULL) {
				param[i].key = "KEY_PIN";
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = pin;
				params[i] = &param[i];
				i++;
			}
			if (pinfile != NULL) {
				param[i].key = "KEY_PIN_FILE";
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = pinfile;
				params[i] = &param[i];
				i++;
			}
			if (ca != NULL) {
				capath = find_ca_by_name(globals.tctx, bus, ca,
							 verbose);
				if (capath == NULL) {
					printf(_("No CA with name \"%s\" "
					       "found.\n"), ca);
					return 1;
				}
				param[i].key = "CA";
				param[i].value_type = cm_tdbusm_dict_p;
				param[i].value.s = talloc_strdup(globals.tctx,
								 capath);
				params[i] = &param[i];
				i++;
			} else {
				capath = NULL;
			}
			if (profile != NULL) {
				param[i].key = CM_DBUS_PROP_CA_PROFILE;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = profile;
				params[i] = &param[i];
				i++;
			}
			if (precommand != NULL) {
				param[i].key = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = precommand;
				params[i] = &param[i];
				i++;
			}
			if (postcommand != NULL) {
				param[i].key = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = postcommand;
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
			rep = send_req(req, verbose);
			if (cm_tdbusm_get_bp(rep, globals.tctx, &b,
					     &new_request) != 0) {
				printf(_("Error parsing server response.\n"));
				exit(1);
			}
			request = new_request;
			dbus_message_unref(rep);
			nickname = find_request_name(globals.tctx, bus,
						     request, verbose);
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
			if (id != NULL) {
				printf(_("No request found with specified "
					 "nickname.\n"));
				help(argv0, category);
				return 1;
			}
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
			return add_basic_request(bus, new_id,
						 dbdir, nickname, token,
						 keyfile, certfile,
						 pin, pinfile,
						 ca, profile,
						 precommand, postcommand,
						 (auto_renew_stop > 0),
						 verbose);
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
		nickname = find_request_name(globals.tctx, bus, request,
					     verbose);
		req = prep_req(bus, CM_DBUS_BASE_PATH,
			       CM_DBUS_BASE_INTERFACE,
			       "remove_request");
		if (cm_tdbusm_set_p(req, request) != 0) {
			printf(_("Error setting request arguments.\n"));
			exit(1);
		}
		rep = send_req(req, verbose);
		if (cm_tdbusm_get_b(rep, globals.tctx, &b) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
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
	const char *request;
	char *capath;
	struct cm_tdbusm_dict param[18];
	const struct cm_tdbusm_dict *params[19];
	char *dbdir = NULL, *token = NULL, *nickname = NULL, *certfile = NULL;
	char *pin = NULL, *pinfile = NULL;
	char *id = NULL, *new_id = NULL, *ca = NULL, *new_request, *nss_scheme;
	char *subject = NULL, **eku = NULL, *oid = NULL;
	char **principal = NULL, **dns = NULL, **email = NULL;
	char *profile = NULL;
	dbus_bool_t b;
	int verbose = 0, c, i;
	krb5_context kctx;
	krb5_error_code kret;
	krb5_principal kprincipal;
	char *kuprincipal, *precommand = NULL, *postcommand = NULL;

	kctx = NULL;
	if ((kret = krb5_init_context(&kctx)) != 0) {
		kctx = NULL;
		printf(_("Error initializing Kerberos library: %s.\n"),
		       error_message(kret));
		return 1;
	}

	opterr = 0;
	while ((c = getopt(argc, argv,
			   ":d:n:N:t:U:K:E:D:f:i:I:sSp:P:vB:C:T:"
			   GETOPT_CA)) != -1) {
		switch (c) {
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, optarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 't':
			token = talloc_strdup(globals.tctx, optarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, optarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, optarg);
			break;
		case 'c':
			ca = talloc_strdup(globals.tctx, optarg);
			break;
		case 'T':
			profile = talloc_strdup(globals.tctx, optarg);
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
			if ((oid == NULL) ||
			    (strspn(oid, "0123456789.") != strlen(oid))) {
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
		case 'p':
			pinfile = optarg;
			break;
		case 'P':
			pin = optarg;
			break;
		case 'B':
			precommand = optarg;
			break;
		case 'C':
			postcommand = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					"resubmit", optopt);
			} else {
				fprintf(stderr, _("%s: invalid option -- '%c'\n"),
					"resubmit", optopt);
			}
			help(argv0, "resubmit");
			return 1;
		}
	}
	if (optind < argc) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "resubmit");
		return 1;
	}

	krb5_free_context(kctx);

	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id, verbose);
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, nickname, token,
						  certfile, verbose);
	}
	if (request == NULL) {
		if (id != NULL) {
			printf(_("No request found with specified "
				 "nickname.\n"));
			help(argv0, "resubmit");
			return 1;
		}
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
		capath = find_ca_by_name(globals.tctx, bus, ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), ca);
			exit(1);
		}
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_p;
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
	if (pin != NULL) {
		param[i].key = "KEY_PIN";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pin;
		params[i] = &param[i];
		i++;
	}
	if (pinfile != NULL) {
		param[i].key = "KEY_PIN_FILE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pinfile;
		params[i] = &param[i];
		i++;
	}
	if (profile != NULL) {
		param[i].key = CM_DBUS_PROP_CA_PROFILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = profile;
		params[i] = &param[i];
		i++;
	}
	if (precommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = precommand;
		params[i] = &param[i];
		i++;
	}
	if (postcommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = postcommand;
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
		rep = send_req(req, verbose);
		if (cm_tdbusm_get_bp(rep, globals.tctx, &b,
				     &new_request) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		request = new_request;
		dbus_message_unref(rep);
		if (!b) {
			nickname = find_request_name(globals.tctx, bus,
						     request, verbose);
			printf(_("Error modifying \"%s\".\n"),
			       nickname ? nickname : request);
			exit(1);
		}
	}
	rep = query_rep(bus, request,
			CM_DBUS_REQUEST_INTERFACE, "get_ca", verbose);
	if (cm_tdbusm_get_p(rep, globals.tctx, &capath) == 0) {
		ca = find_ca_name(globals.tctx, bus, capath, verbose);
	} else {
		ca = NULL;
	}
	nickname = find_request_name(globals.tctx, bus, request, verbose);
	if (query_rep_b(bus, request, CM_DBUS_REQUEST_INTERFACE, "resubmit",
			verbose, globals.tctx)) {
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
	char *dbdir = NULL, *dbnickname = NULL, *certfile = NULL, *id = NULL;
	char *nss_scheme;
	const char *capath, *request;
	dbus_bool_t b;
	char *s1, *s2, *s3, *s4, *s5, *s6;
	long n1, n2;
	char **as1, **as2, **as3, **as4, t[24];
	int requests_only = 0, tracking_only = 0, verbose = 0, c, i, j;

	opterr = 0;
	while ((c = getopt(argc, argv, ":rtsSvd:n:f:i:" GETOPT_CA)) != -1) {
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
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, optarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 'n':
			dbnickname = talloc_strdup(globals.tctx, optarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, optarg);
			break;
		case 'i':
			id = talloc_strdup(globals.tctx, optarg);
			break;
		case 'v':
			verbose++;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					"list", optopt);
			} else {
				fprintf(stderr, _("%s: invalid option -- '%c'\n"),
					"list", optopt);
			}
			help(argv0, "list");
			return 1;
		}
	}
	if (optind < argc) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "list");
		return 1;
	}
	if (only_ca != NULL) {
		capath = find_ca_by_name(globals.tctx, bus, only_ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), only_ca);
			return 1;
		}
	}
	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id, verbose);
		if (request == NULL) {
			printf(_("No request found with specified "
				 "nickname.\n"));
			return 1;
		}
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, dbnickname, NULL,
						  certfile, verbose);
		if (request == NULL) {
			if (((dbdir != NULL) && (dbnickname != NULL)) ||
			    (certfile != NULL)) {
				printf(_("No request found that matched "
					 "arguments.\n"));
				return 1;
			}
		}
	}
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", verbose, globals.tctx);
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		continue;
	}
	printf(_("Number of certificates and requests being tracked: %d.\n"),
	       i);
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		/* Filter out based on the CA. */
		ca_name = NULL;
		rep = query_rep(bus, requests[i],
				CM_DBUS_REQUEST_INTERFACE, "get_ca", verbose);
		if (cm_tdbusm_get_p(rep, globals.tctx, &p) == 0) {
			ca_name = find_ca_name(globals.tctx, bus, p, verbose);
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
				"get_status", verbose);
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
		case CM_NEED_KEY_GEN_PIN:
		case CM_NEED_KEY_GEN_TOKEN:
		case CM_GENERATING_KEY_PAIR:
		case CM_HAVE_KEY_PAIR:
		case CM_NEED_KEYINFO:
		case CM_READING_KEYINFO:
		case CM_NEED_KEYINFO_READ_PIN:
		case CM_NEED_KEYINFO_READ_TOKEN:
		case CM_HAVE_KEYINFO:
		case CM_NEED_CSR:
		case CM_NEED_CSR_GEN_PIN:
		case CM_NEED_CSR_GEN_TOKEN:
		case CM_GENERATING_CSR:
		case CM_HAVE_CSR:
		case CM_NEED_TO_SUBMIT:
		case CM_SUBMITTING:
		case CM_NEED_TO_SAVE_CERT:
		case CM_PRE_SAVE_CERT:
		case CM_START_SAVING_CERT:
		case CM_SAVING_CERT:
		case CM_SAVED_CERT:
		case CM_POST_SAVED_CERT:
		case CM_NEED_TO_READ_CERT:
		case CM_READING_CERT:
		case CM_CA_WORKING:
		case CM_CA_REJECTED:
		case CM_CA_UNREACHABLE:
		case CM_CA_UNCONFIGURED:
		case CM_NEED_GUIDANCE:
		case CM_NEED_CA:
		case CM_NEWLY_ADDED:
		case CM_NEWLY_ADDED_START_READING_KEYINFO:
		case CM_NEWLY_ADDED_READING_KEYINFO:
		case CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN:
		case CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN:
		case CM_NEWLY_ADDED_START_READING_CERT:
		case CM_NEWLY_ADDED_READING_CERT:
		case CM_NEWLY_ADDED_DECIDING:
			if (tracking_only) {
				continue;
			}
			break;
		case CM_MONITORING:
		case CM_NEED_TO_NOTIFY_VALIDITY:
		case CM_NOTIFYING_VALIDITY:
		case CM_NEED_TO_NOTIFY_REJECTION:
		case CM_NOTIFYING_REJECTION:
		case CM_NEED_TO_NOTIFY_ISSUED_FAILED:
		case CM_NOTIFYING_ISSUED_FAILED:
		case CM_NEED_TO_NOTIFY_ISSUED_SAVED:
		case CM_NOTIFYING_ISSUED_SAVED:
			if (requests_only) {
				continue;
			}
			break;
		}
		/* Basic info. */
		nickname = find_request_name(globals.tctx, bus, requests[i],
					     verbose);
		if ((id != NULL) && (strcmp(nickname, id) != 0)) {
			continue;
		}
		if ((dbdir != NULL) || (dbnickname != NULL) ||
		    (certfile != NULL)) {
			rep = query_rep(bus, requests[i],
					CM_DBUS_REQUEST_INTERFACE,
					"get_cert_storage_info", verbose);
			if (cm_tdbusm_get_ssosos(rep, globals.tctx,
						 &s1, &s2, &s3, &s4) != 0) {
				printf(_("Error parsing server response.\n"));
				exit(1);
			}
			dbus_message_unref(rep);
			if ((dbdir != NULL) || (dbnickname != NULL)) {
				if ((strcmp(s1, "NSSDB") != 0) ||
				    ((dbdir != NULL) &&
				     (s2 != NULL) &&
				     (strcmp(dbdir, s2) != 0)) ||
				    ((dbnickname != NULL) &&
				     (s3 != NULL) &&
				     (strcmp(dbnickname, s3) != 0))) {
					continue;
				}
			}
			if (certfile != NULL) {
				if ((strcmp(s1, "FILE") != 0) ||
				    (strcmp(certfile, s2) != 0)) {
					continue;
				}
			}
		}
		printf(_("Request ID '%s':\n"), nickname);
		printf(_("\tstatus: %s\n"), s);
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_ca_error", verbose);
		if (cm_tdbusm_get_s(rep, globals.tctx, &s) == 0) {
			printf(_("\tca-error: %s\n"), s);
		}
		printf(_("\tstuck: %s\n"), b ? "yes" : "no");
		/* Get key/cert storage info. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_key_storage_info", verbose);
		if (cm_tdbusm_get_sososos(rep, globals.tctx,
				          &s1, &s2, &s3, &s4) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		s5 = query_rep_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				 "get_key_pin", verbose, globals.tctx);
		if ((s5 != NULL) && (strlen(s5) == 0)) {
			s5 = NULL;
		}
		s6 = query_rep_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				 "get_key_pin_file", verbose, globals.tctx);
		if ((s6 != NULL) && (strlen(s6) == 0)) {
			s6 = NULL;
		}
		printf(_("\tkey pair storage: type=%s"), s1 ? s1 : _("NONE"));
		if (s2 != NULL) {
			printf(_(",location='%s'"), s2);
		}
		if (s3 != NULL) {
			printf(_(",nickname='%s'"), s3);
		}
		if (s4 != NULL) {
			printf(_(",token='%s'"), s4);
		}
		if (s5 != NULL) {
			printf(_(",pin='%s'"), s5);
		}
		if (s6 != NULL) {
			printf(_(",pinfile='%s'"), s6);
		}
		printf("\n");
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_cert_storage_info", verbose);
		if (cm_tdbusm_get_ssosos(rep, globals.tctx,
				         &s1, &s2, &s3, &s4) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		printf(_("\tcertificate: type=%s,location='%s'"), s1, s2);
		if (s3 != NULL) {
			printf(_(",nickname='%s'"), s3);
		}
		if (s4 != NULL) {
			printf(_(",token='%s'"), s4);
		}
		printf("\n");
		/* Information from the certificate. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_cert_info", verbose);
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
		       n1 ?
		       cm_store_timestamp_from_time_for_display(n1, t) :
		       _("unknown"));
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
		printf(_("\tpre-save command: %s\n"),
		       query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				    CM_DBUS_PROP_CERT_PRESAVE_COMMAND, verbose, globals.tctx));
		printf(_("\tpost-save command: %s\n"),
		       query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				    CM_DBUS_PROP_CERT_POSTSAVE_COMMAND, verbose, globals.tctx));
		printf(_("\ttrack: %s\n"),
		       query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   "get_monitoring", verbose, globals.tctx) ?
		       "yes" : "no");
		printf(_("\tauto-renew: %s\n"),
		       query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   "get_autorenew", verbose, globals.tctx) ?
		       "yes" : "no");
	}
	return 0;
}

static int
list_cas(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char **cas, *s, *only_ca = DEFAULT_CA;
	char **as;
	int c, i, j, verbose = 0;

	opterr = 0;
	while ((c = getopt(argc, argv, ":sSv" GETOPT_CA)) != -1) {
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
		case 'v':
			verbose++;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					"list-cas", optopt);
			} else {
				fprintf(stderr, _("%s: invalid option -- '%c'\n"),
					"list-cas", optopt);
			}
			help(argv0, "list-cas");
			return 1;
		}
	}
	if (optind < argc) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "list-cas");
		return 1;
	}
	cas = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			   "get_known_cas", verbose, globals.tctx);
	for (i = 0; (cas != NULL) && (cas[i] != NULL); i++) {
		/* Filter out based on the CA. */
		s = find_ca_name(globals.tctx, bus, cas[i], verbose);
		if (s != NULL) {
			if ((only_ca != NULL) && (strcmp(s, only_ca) != 0)) {
				continue;
			}
		}
		printf(_("CA '%s':\n"), s);
		printf("\tis-default: %s\n",
		       query_rep_b(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   "get_is_default", verbose, globals.tctx) ?
		       "yes" : "no");
		s = query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
				"get_type", verbose, globals.tctx);
		printf(_("\tca-type: %s\n"), s);
		if (strcmp(s, "EXTERNAL") == 0) {
			printf(_("\thelper-location: %s\n"),
			       query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					   "get_location",
					   verbose, globals.tctx));
		} else {
			printf(_("\tnext-serial-number: %s\n"),
			       query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					   "get_serial",
					   verbose, globals.tctx));
		}
		as = query_rep_as(bus, cas[i],
				  CM_DBUS_CA_INTERFACE, "get_issuer_names",
				  verbose,
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
		N_("* If keys are to be encrypted:\n"),
		N_("  -p FILE	file which holds the encryption PIN\n"),
		N_("  -P PIN	PIN value\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME	nickname to assign to the request\n"),
		N_("  -g SIZE	size of key to be generated if one is not already in place\n"),
		N_("  -r		attempt to renew the certificate when expiration nears (default)\n"),
		N_("  -R		don't attempt to renew the certificate when expiration nears\n"),
#ifndef FORCE_CA
		N_("  -c CA		use the specified CA rather than the default\n"),
#endif
		N_("  -T PROFILE	ask the CA to process the request using the named profile or template\n"),
		N_("* Parameters for the signing request:\n"),
		N_("  -N NAME	set requested subject name (default: CN=<hostname>)\n"),
		N_("  -U EXTUSAGE	set requested extended key usage OID\n"),
		N_("  -K NAME	set requested principal name\n"),
		N_("  -D DNSNAME	set requested DNS name\n"),
		N_("  -E EMAIL	set requested email address\n"),
		N_("* Bus options:\n"),
		N_("  -S		connect to the certmonger service on the system bus\n"),
		N_("  -s		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -B	command to run before saving the certificate\n"),
		N_("  -C	command to run after saving the certificate\n"),
		N_("  -v	report all details of errors\n"),
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
		N_("* If keys are encrypted:\n"),
		N_("  -p FILE	file which holds the encryption PIN\n"),
		N_("  -P PIN	PIN value\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME	nickname to give to tracking request\n"),
		N_("  -r		attempt to renew the certificate when expiration nears (default)\n"),
		N_("  -R		don't attempt to renew the certificate when expiration nears\n"),
#ifndef FORCE_CA
		N_("  -c CA		use the specified CA rather than the default\n"),
#endif
		N_("  -T PROFILE	ask the CA to process the request using the named profile or template\n"),
		N_("* Parameters for the signing request at renewal time:\n"),
		N_("  -U EXTUSAGE	override requested extended key usage OID\n"),
		N_("  -K NAME	override requested principal name\n"),
		N_("  -D DNSNAME	override requested DNS name\n"),
		N_("  -E EMAIL	override requested email address\n"),
		N_("* Bus options:\n"),
		N_("  -S		connect to the certmonger service on the system bus\n"),
		N_("  -s		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -B	command to run before saving the certificate\n"),
		N_("  -C	command to run after saving the certificate\n"),
		N_("  -v	report all details of errors\n"),
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
		N_("* Other options:\n"),
		N_("  -v	report all details of errors\n"),
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
		N_("* If keys are encrypted:\n"),
		N_("  -p FILE	file which holds the encryption PIN\n"),
		N_("  -P PIN	PIN value\n"),
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
		N_("  -T PROFILE	ask the CA to process the request using the named profile or template\n"),
		N_("* Bus options:\n"),
		N_("  -S		connect to the certmonger service on the system bus\n"),
		N_("  -s		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -B	command to run before saving the certificate\n"),
		N_("  -C	command to run after saving the certificate\n"),
		N_("  -v	report all details of errors\n"),
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
		N_("* If selecting a specific request:\n"),
		N_("  -i NAME	nickname for tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR	only list requests and certs which use this NSS database\n"),
		N_("  -n NAME	only list requests and certs which use this nickname\n"),
		N_("* If using files for storage:\n"),
		N_("  -f FILE	only list requests and certs stored in this PEM file\n"),
		N_("* Bus options:\n"),
		N_("  -S	connect to the certmonger service on the system bus\n"),
		N_("  -s	connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v	report all details of errors\n"),
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
		N_("* Other options:\n"),
		N_("  -v	report all details of errors\n"),
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
#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif
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
