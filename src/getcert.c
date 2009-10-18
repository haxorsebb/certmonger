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

#include "cm.h"
#include "store.h"
#include "store-int.h"
#include "tdbus.h"
#include "tdbusm.h"

static void help(const char *cmd, const char *category);

static struct {
	DBusConnection *conn;
	void *tctx;
} globals = {
	.conn = NULL,
	.tctx = NULL
};

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
		printf("Error connecting to DBus.\n");
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
			printf("Error connecting to DBus.\n");
			exit(1);
		}
	}
	msg = dbus_message_new_method_call(CM_DBUS_NAME,
					   path, interface, method);
	if (msg == NULL) {
		printf("Error creating DBus request message.\n");
		exit(1);
	}
	return msg;
}

/* Send our request and ensure that we get a response. */
static DBusMessage *
send_req(DBusMessage *req)
{
	DBusMessage *rep;
	rep = dbus_connection_send_with_reply_and_block(globals.conn, req,
							30 * 1000, NULL);
	if (rep == NULL) {
		printf("No response received from local service.\n");
		exit(1);
	}
	dbus_message_unref(req);
	return rep;
}

/* Send the specified, argument-less method call to the named object. */
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
		printf("Error parsing server response.\n");
		exit(1);
	}
	dbus_message_unref(rep);
	return b;
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
		printf("Error parsing server response.\n");
		exit(1);
	}
	dbus_message_unref(rep);
}

static int
request(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char subject_default[LINE_MAX];
	char *dbdir = NULL, *token = NULL, *nickname = NULL;
	char *keyfile = NULL, *certfile = NULL;
	int keysize = 0, track_exp = 0, auto_renew = 0, c, i;
	char *ca = NULL, *subject = NULL, **eku = NULL;
	char **principal = NULL, **dns = NULL, **email = NULL;
	struct cm_tdbusm_dict param[32];
	const struct cm_tdbusm_dict *params[32];
	DBusMessage *req, *rep;
	dbus_bool_t b;
	char *p;

	memset(subject_default, '\0', sizeof(subject_default));
	strcpy(subject_default, "CN=");
	if (gethostname(subject_default + 3,
			sizeof(subject_default) - 4) != 0) {
		strcpy(subject_default, "CN=localhost");
	}
	subject = subject_default;

	while ((c = getopt(argc, argv, "d:n:t:k:f:g:erc:s:U:K:D:E:")) != -1) {
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
		case 'e':
			track_exp++;
			break;
		case 'r':
			auto_renew++;
			break;
		case 'c':
			ca = talloc_strdup(globals.tctx, optarg);
			break;
		case 's':
			subject = talloc_strdup(globals.tctx, optarg);
			break;
		case 'U':
			add_string(globals.tctx, &eku, optarg);
			break;
		case 'K':
			add_string(globals.tctx, &principal, optarg);
			break;
		case 'D':
			add_string(globals.tctx, &dns, optarg);
			break;
		case 'E':
			add_string(globals.tctx, &email, optarg);
			break;
		default:
			help(argv0, "request");
			return 1;
		}
	}
	if (((dbdir != NULL) && (nickname == NULL)) ||
	    ((dbdir == NULL) && (nickname != NULL))) {
		printf("Database location or nickname specified "
		       "without the other.\n");
		help(argv0, "request");
		return 1;
	}
	if ((dbdir != NULL) && (certfile != NULL)) {
		printf("Database directory and certificate file "
		       "both specified.\n");
		help(argv0, "request");
		return 1;
	}
	if ((dbdir == NULL) && (nickname == NULL) && (certfile == NULL)) {
		printf("None of database directory and nickname or certificate "
		       "file specified.\n");
		help(argv0, "request");
		return 1;
	}
	i = 0;
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
	param[i].value.b = track_exp > 0;
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
	if (ca != NULL) {
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = ca;
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
		printf("Error setting request arguments.\n");
		exit(1);
	}
	rep = send_req(req);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf("Error parsing server response.\n");
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		printf("Request \"%s\" added.\n", p);
	} else {
		printf("Request failed.\n");
		exit(1);
	}
	return 0;
}

static const char *
find_request_by_storage(void *parent, enum cm_tdbus_type bus,
			const char *dbdir, 
			const char *nickname, 
			const char *token,
			const char *certfile)
{
	DBusMessage *rep;
	char **requests;
	int i, which;
	char *cert_stype, *cert_sloc, *cert_nick, *cert_tok;
	rep = query_rep(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			"get_requests");
	if (cm_tdbusm_get_ap(rep, globals.tctx, &requests) != 0) {
		printf("Error parsing server response.\n");
		exit(1);
	}
	dbus_message_unref(rep);
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

static int
add_basic_request(enum cm_tdbus_type bus,
		  char *dbdir, char *nickname, char *token,
		  char *keyfile, char *certfile,
		  char *ca, dbus_bool_t track, dbus_bool_t auto_renew)
{
	DBusMessage *req, *rep;
	int i;
	struct cm_tdbusm_dict param[16];
	const struct cm_tdbusm_dict *params[16];
	dbus_bool_t b;
	char *p;
	i = 0;
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
	param[i].value.b = track;
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
		printf("Error setting request arguments.\n");
		exit(1);
	}
	rep = send_req(req);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf("Error parsing server response.\n");
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		printf("New request \"%s\" added.\n", p);
		return 0;
	} else {
		printf("New request could not be added.\n");
		return 1;
	}
}

static int
set_tracking(const char *argv0, int argc, char **argv, dbus_bool_t track)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	DBusMessage *req, *rep;
	const char *request;
	struct cm_tdbusm_dict param[3];
	const struct cm_tdbusm_dict *params[3];
	char *dbdir = NULL, *token = NULL, *nickname = NULL;
	char *keyfile = NULL, *certfile = NULL, *ca = NULL;
	dbus_bool_t b;
	int c, auto_renew = 0, i;
	while ((c = getopt(argc, argv, "d:n:t:k:f:g:rc:")) != -1) {
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
			auto_renew++;
			break;
		case 'c':
			ca = talloc_strdup(globals.tctx, optarg);
			break;
		}
	}
	request = find_request_by_storage(globals.tctx, bus,
					  dbdir, nickname, token,
					  certfile);
	if (request != NULL) {
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
		params[i] = NULL;
		req = prep_req(bus, request, CM_DBUS_REQUEST_INTERFACE,
			       "modify");
		if (cm_tdbusm_set_d(req, params) != 0) {
			printf("Error setting request arguments.\n");
			exit(1);
		}
		rep = send_req(req);
		if (cm_tdbusm_get_b(rep, globals.tctx, &b) != 0) {
			printf("Error parsing server response.\n");
			exit(1);
		}
		dbus_message_unref(rep);
		if (b) {
			printf("Request \"%s\" modified.\n", request);
			return 0;
		} else {
			printf("Request \"%s\" could not be modified.\n",
			       request);
			return 1;
		}
	} else {
		return add_basic_request(bus, dbdir, nickname, token,
					 keyfile, certfile,
					 ca, track, track && (auto_renew > 0));
	}
}

static int
start_tracking(const char *argv0, int argc, char **argv)
{
	return set_tracking(argv0, argc, argv, TRUE);
}

static int
stop_tracking(const char *argv0, int argc, char **argv)
{
	return set_tracking(argv0, argc, argv, FALSE);
}

static int
list(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	enum cm_state state;
	DBusMessage *rep;
	char **requests, *s, *p, *nickname, *only_ca = NULL, *ca_name;
	dbus_bool_t b;
	char *s1, *s2, *s3, *s4;
	long n1, n2;
	char **as1, **as2, **as3, **as4, t[15];
	int requests_only = 0, tracking_only = 0, c, i, j;
	while ((c = getopt(argc, argv, "rtc:")) != -1) {
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
		default:
			help(argv0, "list");
			return 1;
		}
	}
	rep = query_rep(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			"get_requests");
	if (cm_tdbusm_get_as(rep, globals.tctx, &requests) != 0) {
		printf("Error parsing server response.\n");
		exit(1);
	}
	dbus_message_unref(rep);
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		/* Filter out based on the CA. */
		ca_name = NULL;
		rep = query_rep(bus, requests[i],
				CM_DBUS_REQUEST_INTERFACE, "get_ca");
		if (cm_tdbusm_get_p(rep, globals.tctx, &p) == 0) {
			dbus_message_unref(rep);
			rep = query_rep(bus, p,
					CM_DBUS_CA_INTERFACE,
					"get_nickname");
			if (cm_tdbusm_get_s(rep, globals.tctx,
					    &ca_name) != 0) {
				ca_name = NULL;
			}
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
			printf("Error parsing server response.\n");
			exit(1);
		}
		dbus_message_unref(rep);
		/* Filter out based on the current state. */
		state = cm_store_state_from_string(s);
		switch (state) {
		case CM_INVALID:
			printf("'%s' is in an invalid state!\n", s);
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
		case CM_HAVE_SUBMITTED:
		case CM_NEED_CA_STATUS:
		case CM_POLLING_CA_STATUS:
		case CM_RETRIEVING_CERT:
		case CM_NEED_TO_SAVE_CERT:
		case CM_SAVING_CERT:
		case CM_SAVED_CERT:
		case CM_NEED_TO_READ_CERT:
		case CM_READING_CERT:
		case CM_NEED_GUIDANCE:
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
		case CM_NOTIFYING:
			if (requests_only) {
				continue;
			}
			break;
		}
		/* Basic info. */
		rep = query_rep(bus, requests[i],
				CM_DBUS_REQUEST_INTERFACE, "get_nickname");
		if (cm_tdbusm_get_s(rep, globals.tctx, &nickname) != 0) {
			nickname = requests[i];
		}
		dbus_message_unref(rep);
		printf("Request '%s':\n", nickname);
		printf("\tstatus: %s\n", s);
		printf("\tstuck: %s\n", b ? "yes" : "no");
		/* Get key/cert storage info. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_key_storage_info");
		if (cm_tdbusm_get_sososos(rep, globals.tctx,
				          &s1, &s2, &s3, &s4) != 0) {
			printf("Error parsing server response.\n");
			exit(1);
		}
		dbus_message_unref(rep);
		printf("\tkey pair storage: %s%s%s%s%s%s%s%s%s\n",
		       strcmp(s1, "NONE") ? "type=" : "", s1 ? s1 : "",
		       s2 ? ",location='" : "", s2 ? s2 : "", s2 ? "'" : "",
		       s3 ? ",nickname=" : "", s3 ? s3 : "",
		       s4 ? ",token=" : "", s4 ? s4 : "");
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_cert_storage_info");
		if (cm_tdbusm_get_ssosos(rep, globals.tctx,
				         &s1, &s2, &s3, &s4) != 0) {
			printf("Error parsing server response.\n");
			exit(1);
		}
		dbus_message_unref(rep);
		printf("\tcertificate: type=%s,location='%s'%s%s%s%s\n",
		       s1, s2,
		       s3 ? ",nickname=" : "", s3 ? s3 : "",
		       s4 ? ",token=" : "", s4 ? s4 : "");
		/* Information from the certificate. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_cert_info");
		if (cm_tdbusm_get_sssnasasasnas(rep, globals.tctx,
						&s1, &s2, &s3, &n1,
						&as1, &as2, &as3,
						&n2, &as4) != 0) {
			printf("Error parsing server response.\n");
			exit(1);
		}
		dbus_message_unref(rep);
		if (ca_name != NULL) {
			printf("\tCA: %s\n", ca_name);
		}
		printf("\tissuer: %s\n", s1);
		printf("\tsubject: %s\n", s3);
		printf("\texpires: %s\n",
		       n1 ? cm_store_timestamp_from_time(n1, t) : "unknown");
		for (j = 0; (as1 != NULL) && (as1[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? "\temail: " : ",",
			       as1[j],
			       as1[j + 1] ? "" : "\n");
		}
		for (j = 0; (as2 != NULL) && (as2[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? "\tdns: " : ",",
			       as2[j],
			       as2[j + 1] ? "" : "\n");
		}
		for (j = 0; (as3 != NULL) && (as3[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? "\tprincipal: " : ",",
			       as3[j],
			       as3[j + 1] ? "" : "\n");
		}
		for (j = 0; (as4 != NULL) && (as4[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? "\teku: " : ",",
			       as4[j],
			       as4[j + 1] ? "" : "\n");
		}
		printf("\ttrack: %s\n",
		       query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   "get_monitoring", globals.tctx) ?
		       "yes" : "no");
		printf("\tauto-renew: %s\n",
		       query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   "get_autorenew", globals.tctx) ?
		       "yes" : "no");
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
	{"list", list},
};

static void
help(const char *cmd, const char *category)
{
	unsigned int i;
	struct {
		const char *category;
		const char *msg;
	} msgs[] = {
	{NULL,
	"%s - client certificate enrollment tool\n"},
	{"request",
	"Usage: %s request [options]\n"
	"\n"
	"Required arguments:\n"
	"* If using an NSS database for storage:\n"
	"  -d DIR	NSS database for key and cert\n"
	"  -n NAME	nickname for NSS-based storage (only valid with -d)\n"
	"  -t NAME	optional token name for NSS-based storage (only valid with -d)\n"
	"* If using files for storage:\n"
	"  -k FILE	PEM file for private key\n"
	"  -f FILE	PEM file for certificate (only valid with -k)\n"
	"\n"
	"Optional arguments:\n"
	"* Certificate handling settings:\n"
	"  -g SIZE	size of key to be generated if one is not already in place\n"
	"  -e		track and warn of impending expiration of certificate\n"
	"  -r		attempt to renew the certificate when expiration nears\n"
	"  -c CA	use the specified CA rather than the default\n"
	"* Parameters for the signing request:\n"
	"  -s NAME	set requested subject name (default: CN=<hostname>)\n"
	"  -U EXTUSAGE	add requested extended key usage OID\n"
	"  -K NAME	add requested principal name\n"
	"  -D DNSNAME	add requested DNS name\n"
	"  -E EMAIL	add requested email address\n",},
	{"start-tracking",
	"Usage: %s start-tracking [options]\n"
	"\n"
	"Required arguments:\n"
	"* If using an NSS database for storage:\n"
	"  -d DIR	NSS database for key and cert\n"
	"  -n NAME	nickname for NSS-based storage (only valid with -d)\n"
	"  -t NAME	optional token name for NSS-based storage (only valid with -d)\n"
	"* If using files for storage:\n"
	"  -k FILE	PEM file for private key\n"
	"  -f FILE	PEM file for certificate (only valid with -k)\n"
	"\n"
	"Optional arguments:\n"
	"* Certificate handling settings:\n"
	"  -r		attempt to renew the certificate when expiration nears\n"
	"  -c CA	use the specified CA rather than the default\n",},
	{"stop-tracking",
	"Usage: %s stop-tracking [options]\n"
	"\n"
	"Required arguments:\n"
	"* If using an NSS database for storage:\n"
	"  -d DIR	NSS database for key and cert\n"
	"  -n NAME	nickname for NSS-based storage (only valid with -d)\n"
	"  -t NAME	optional token name for NSS-based storage (only valid with -d)\n"
	"* If using files for storage:\n"
	"  -k FILE	PEM file for private key\n"
	"  -f FILE	PEM file for certificate (only valid with -k)\n",},
	{"list",
	"Usage: %s list [options]\n"
	"* General options:\n"
	"  -c CA	list only requests and cert associated with this CA\n"
	"  -r		list only information about outstanding requests\n"
	"  -t		list only information about tracked certificates\n"}};
	for (i = 0; i < sizeof(msgs) / sizeof(msgs[0]); i++) {
		if ((category != NULL) && (msgs[i].category != NULL) &&
		    (strcmp(category, msgs[i].category) != 0)) {
			continue;
		}
		if (i > 0) {
			printf("\n");
		}
		printf(msgs[i].msg, cmd);
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
		fprintf(stderr, "%s: unrecognized command\n", verb);
		return 1;
	} else {
		help(p, NULL);
		return 1;
	}
}
