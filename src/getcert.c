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
	if (((keyfile != NULL) && (certfile == NULL)) ||
	    ((keyfile == NULL) && (certfile != NULL))) {
		printf("Filename for key or certificate specified "
		       "without the other.\n");
		help(argv0, "request");
		return 1;
	}
	if (((dbdir != NULL) && (nickname == NULL)) ||
	    ((dbdir == NULL) && (nickname != NULL))) {
		printf("Database location or nickname specified "
		       "without the other.\n");
		help(argv0, "request");
		return 1;
	}
	if ((dbdir != NULL) && ((certfile != NULL) || (keyfile != NULL))) {
		printf("Database directory and key or certificate file "
		       "all specified.\n");
		help(argv0, "request");
		return 1;
	}
	if ((dbdir == NULL) && (certfile == NULL) && (keyfile == NULL)) {
		printf("None of database directory or key or certificate file "
		       "specified.\n");
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
	if (b) {
		printf("Request \"%s\" added.\n", p);
	} else {
		printf("Request failed.\n");
		exit(1);
	}
	return 0;
}

static int
request_old(const char *argv0, int argc, char **argv)
{
	struct cm_store_entry *entry;
	char cn_template[LINE_MAX];
	const char *ca = NULL;
	const char *dbdir = NULL, *token = NULL, *nickname = NULL;
	const char *keyfile = NULL, *certfile = NULL;
	const char *subject = NULL, *service = NULL, *usage = NULL;
	int keygen = 0, keysize = 0, track_exp = 0, auto_renew = 0, c;
	while ((c = getopt(argc, argv, "c:gG:d:n:k:f:S:s:t:u:er")) != -1) {
		switch (c) {
		case 'c':
			ca = optarg;
			break;
		case 'g':
			keygen++;
			break;
		case 'G':
			keysize = atoi(optarg);
			break;
		case 'd':
			dbdir = optarg;
			break;
		case 'n':
			nickname = optarg;
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'f':
			certfile = optarg;
			break;
		case 'S':
			subject = optarg;
			break;
		case 's':
			service = optarg;
			break;
		case 't':
			token = optarg;
			break;
		case 'u':
			usage = optarg;
			break;
		case 'e':
			track_exp++;
			break;
		case 'r':
			auto_renew++;
			break;
		default:
			help(argv0, "request");
			return 1;
		}
	}
	entry = cm_store_entry_new(NULL);
	if (entry != NULL) {
		/* Sort out the key type we want. */
		entry->cm_key_type_default = 1;
		entry->cm_key_type.cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
		if (keysize != 0) {
			entry->cm_key_type_default = 0;
			entry->cm_key_type.cm_key_algorithm =
				CM_DEFAULT_PUBKEY_TYPE;
			entry->cm_key_type.cm_key_size = keysize;
		}
		/* Sort out the key storage location. */
		if (((keyfile != NULL) && (certfile == NULL)) ||
		    ((keyfile == NULL) && (certfile != NULL))) {
			printf("Filename for key or certificate specified "
			       "without the other.\n");
			return 1;
		}
		if (keyfile != NULL) {
			entry->cm_key_storage_default = 0;
			entry->cm_key_storage_type = cm_key_storage_file;
			entry->cm_key_storage_location = talloc_strdup(entry,
								       keyfile);
		} else
		if ((dbdir != NULL) && (nickname != NULL)) {
			entry->cm_key_storage_default = 0;
			entry->cm_key_storage_type = cm_key_storage_nssdb;
			entry->cm_key_storage_location = talloc_strdup(entry,
								       dbdir);
			if (token != NULL) {
				entry->cm_key_token = talloc_strdup(entry,
								    token);
			}
			entry->cm_key_nickname = talloc_strdup(entry, nickname);
		} else {
			entry->cm_key_storage_default = 0;
			entry->cm_key_storage_type = CM_DEFAULT_KEY_STORAGE_TYPE;
			entry->cm_key_storage_location = talloc_strdup(entry, CM_DEFAULT_KEY_STORAGE_LOCATION);
			if (CM_DEFAULT_KEY_TOKEN != NULL) {
				entry->cm_key_token = talloc_strdup(entry, CM_DEFAULT_KEY_TOKEN);
			}
			if (CM_DEFAULT_KEY_NICKNAME != NULL) {
				entry->cm_key_nickname = talloc_strdup(entry, CM_DEFAULT_KEY_NICKNAME);
			}
		}
		/* If we were asked to generate a key, then we need to do that.
		 * Otherwise, assume we need to generate a CSR. */
		entry->cm_state = keygen ? CM_NEED_KEY_PAIR : CM_NEED_CSR;
		/* Sort out the certificate storage location. */
		if (certfile != NULL) {
			entry->cm_cert_storage_default = 0;
			entry->cm_cert_storage_type = cm_cert_storage_file;
			entry->cm_cert_storage_location = talloc_strdup(entry,
									certfile);
		} else
		if ((dbdir != NULL) && (nickname != NULL)) {
			entry->cm_cert_storage_default = 0;
			entry->cm_cert_storage_type = cm_cert_storage_nssdb;
			entry->cm_cert_storage_location = talloc_strdup(entry, dbdir);
			if (token != NULL) {
				entry->cm_cert_token = talloc_strdup(entry,
								     token);
			}
			entry->cm_cert_nickname = talloc_strdup(entry, nickname);
		} else {
			entry->cm_cert_storage_default = 0;
			entry->cm_cert_storage_type = CM_DEFAULT_CERT_STORAGE_TYPE;
			entry->cm_cert_storage_location = talloc_strdup(entry, CM_DEFAULT_CERT_STORAGE_LOCATION);
			if (CM_DEFAULT_CERT_TOKEN != NULL) {
				entry->cm_cert_token = talloc_strdup(entry, CM_DEFAULT_CERT_TOKEN);
			}
			if (CM_DEFAULT_CERT_NICKNAME != NULL) {
				entry->cm_cert_nickname = talloc_strdup(entry, CM_DEFAULT_CERT_NICKNAME);
			}
			return 1;
		}
		/* For now, just use the default time-until-expiration
		 * threshold values for deciding when we need to warn the user.
		 */
		entry->cm_ttls_default = 1;
		/* For now, just use the defaults for notifications. */
		entry->cm_notification_default = 1;
		/* Figure out a subject name to use in the CSR. */
		if (subject != NULL) {
			/* Use the specified value. */
			entry->cm_template_subject = talloc_strdup(entry,
								   subject);
		} else {
			/* Try to read the local hostname. */
			memset(cn_template, '\0', sizeof(cn_template));
			strcpy(cn_template, "CN=");
			if (gethostname(cn_template + 3,
					sizeof(cn_template) - 3 - 1) != 0) {
				/* Failed to read the local hostname, default
				 * to "localhost". */
				strcpy(cn_template, "CN=localhost");
			}
			entry->cm_template_subject = talloc_strdup(entry,
								   cn_template);
		}
		/* If we weren't told which CA to use, for now, use the dummy.
		 */
		if (ca == NULL) {
			entry->cm_ca_type = cm_ca_dummy;
		}
		/* Sort out if we're tracking expiration. */
		if (track_exp) {
			entry->cm_monitor = 1;
			entry->cm_monitor_default = 0;
		} else {
			entry->cm_monitor_default = 1;
		}
		/* Sort out if we're trying to auto-renew certificates. */
		if (auto_renew) {
			entry->cm_autorenew = 1;
			entry->cm_autorenew_default = 0;
		} else {
			entry->cm_autorenew_default = 1;
		}
		/* Save this entry to our request store. */
		if (cm_store_entry_save(entry) == 0) {
			printf("Request added.\n");
			talloc_free(entry);
			return 0;
		} else {
			printf("Error adding request.\n");
			talloc_free(entry);
			return 1;
		}
	} else {
		printf("Error creating template request.\n");
		talloc_free(entry);
		return 1;
	}
}

static int
start_tracking(const char *argv0, int argc, char **argv)
{
	return 0;
}

static int
stop_tracking(const char *argv0, int argc, char **argv)
{
	return 0;
}

static int
list(const char *argv0, int argc, char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	enum cm_state state;
	DBusMessage *rep;
	char **requests, *s, **as;
	dbus_bool_t b;
	long n;
	int requests_only = 0, tracking_only = 0, c, i;
	while ((c = getopt(argc, argv, "rt")) != -1) {
		switch (c) {
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
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_status");
		if (cm_tdbusm_get_sb(rep, globals.tctx, &s, &b) != 0) {
			printf("Error parsing server response.\n");
			exit(1);
		}
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
		printf("Request '%s':\n", requests[i]);
		printf("\tstatus: %s\n", s);
		printf("\tblocked: %s\n", b ? "yes" : "no");
	}
	return 0;
}

static int
list_old(const char *argv0, int argc, char **argv)
{
	struct cm_store_entry **entries;
	const char *key_storage = NULL, *cert_storage = NULL;
	char token[LINE_MAX], nickname[LINE_MAX], ca[LINE_MAX], stamp[15];
	int requests_only = 0, tracking_only = 0, c, i;
	time_t tstamp;
	while ((c = getopt(argc, argv, "rt")) != -1) {
		switch (c) {
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
	entries = cm_store_get_all_entries(NULL);
	for (i = 0; (entries != NULL) && (entries[i] != NULL); i++) {
		switch (entries[i]->cm_state) {
		case CM_INVALID:
			printf("'%s' is in an invalid state!\n",
			       entries[i]->cm_id);
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
		switch (entries[i]->cm_key_storage_type) {
		case cm_key_storage_file:
			key_storage = "file";
			break;
		case cm_key_storage_nssdb:
			key_storage = "nssdb";
			break;
		}
		switch (entries[i]->cm_cert_storage_type) {
		case cm_cert_storage_file:
			cert_storage = "file";
			break;
		case cm_cert_storage_nssdb:
			cert_storage = "nssdb";
			break;
		}
		printf("Request '%s'\n", entries[i]->cm_id);
		strcpy(ca, "(unknown)");
		switch (entries[i]->cm_ca_type) {
		case cm_ca_dummy:
			strcpy(ca, "dummy(local)");
			break;
		}
		printf("           CA: %s\n", ca);
		printf("        state: %s\n",
		       cm_store_state_as_string(entries[i]->cm_state));
		if (entries[i]->cm_key_token != NULL) {
			sprintf(token, ",token='%s'",
				entries[i]->cm_key_token);
		} else {
			strcpy(token, "");
		}
		if (entries[i]->cm_key_nickname != NULL) {
			sprintf(nickname, ",nickname='%s'",
				entries[i]->cm_key_nickname);
		} else {
			strcpy(nickname, "");
		}
		printf("     key pair: type=%s,location='%s'%s%s\n",
		       key_storage, entries[i]->cm_key_storage_location,
		       token, nickname);
		if (entries[i]->cm_cert_token != NULL) {
			sprintf(token, ",token='%s'",
				entries[i]->cm_cert_token);
		} else {
			strcpy(token, "");
		}
		if (entries[i]->cm_cert_nickname != NULL) {
			sprintf(nickname, ",nickname='%s'",
				entries[i]->cm_cert_nickname);
		} else {
			strcpy(nickname, "");
		}
		printf("  certificate: type=%s,location='%s'%s%s\n",
		       cert_storage, entries[i]->cm_cert_storage_location,
		       token, nickname);
		tstamp = entries[i]->cm_cert_expiration;
		printf("      expires: %s\n",
		       (tstamp == 0) ?
		       "(unknown)" :
		       cm_store_timestamp_from_time(tstamp, stamp));
		printf("    key usage: %s\n",
		       entries[i]->cm_cert_ku ?: "(unspecified)");
		printf("      monitor: %s\n",
		       entries[i]->cm_monitor ? "yes" : "no");
		printf("   auto-renew: %s\n",
		       entries[i]->cm_autorenew ? "yes" : "no");
	}
	talloc_free(entries);
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
	"  -c LOCATION	use the specified CA rather than the default\n"
	"* Parameters for the signing request:\n"
	"  -s NAME	set requested subject name (default: CN=<hostname>)\n"
	"  -u USAGE	add requested key usage\n"
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
	"  -c LOCATION	use the specified CA rather than the default\n",},
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
