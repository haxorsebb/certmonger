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
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>

#include <dbus/dbus.h>

#include "log.h"
#include "cm.h"
#include "prefs.h"
#include "store.h"
#include "store-int.h"
#include "submit-int.h"
#include "tdbus.h"
#include "tdbush.h"
#include "tdbusm.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

/* Things we know about the calling client. */
struct cm_client_info {
	uid_t uid;
};

/* Convenience functions. */
static struct cm_store_entry *
get_entry_for_path(struct cm_context *ctx, const char *path)
{
	int initial;
	if (path != NULL) {
		initial = strlen(CM_DBUS_REQUEST_PATH);
		if (strncmp(path, CM_DBUS_REQUEST_PATH, initial) == 0) {
			if (path[initial] == '/') {
				return cm_get_entry_by_busname(ctx,
							       path +
							       initial +
							       1);
			}
		}
	}
	return NULL;
}
static struct cm_store_entry *
get_entry_for_request_message(DBusMessage *msg, struct cm_context *ctx)
{
	return msg ? get_entry_for_path(ctx, dbus_message_get_path(msg)) : NULL;
}
static struct cm_store_ca *
get_ca_for_path(struct cm_context *ctx, const char *path)
{
	int initial;
	if (path != NULL) {
		initial = strlen(CM_DBUS_CA_PATH);
		if (strncmp(path, CM_DBUS_CA_PATH, initial) == 0) {
			if (path[initial] == '/') {
				return cm_get_ca_by_busname(ctx,
							    path + initial + 1);
			}
		}
	}
	return NULL;
}
static struct cm_store_ca *
get_ca_for_request_message(DBusMessage *msg, struct cm_context *ctx)
{
	return msg ? get_ca_for_path(ctx, dbus_message_get_path(msg)) : NULL;
}

/* These used to be local functions, but we ended up using them elsewhere.
 * Should probably just be reworked where we use them. */
static char *
maybe_strdup(void *parent, const char *s)
{
	return cm_store_maybe_strdup(parent, s);
}
static char **
maybe_strdupv(void *parent, char **s)
{
	return cm_store_maybe_strdupv(parent, s);
}

/* Convenience functions for returning errors from the base object to callers. */
static DBusHandlerResult
send_internal_base_error(DBusConnection *conn, DBusMessage *req)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_BASE_INTERNAL,
				     _("An internal error has occurred."));
	if (msg != NULL) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
send_internal_base_missing_arg_error(DBusConnection *conn, DBusMessage *req,
				     const char *text, const char *arg)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_BASE_MISSING_ARG, text);
	if (msg != NULL) {
		cm_tdbusm_set_s(msg, arg);
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
send_internal_base_bad_arg_error(DBusConnection *conn, DBusMessage *req,
				 const char *text, const char *badval,
				 const char *arg)
{
	DBusMessage *msg;
	msg = dbus_message_new_error_printf(req, CM_DBUS_ERROR_BASE_BAD_ARG,
					    text, badval);
	if (msg != NULL) {
		cm_tdbusm_set_s(msg, arg);
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
send_internal_base_duplicate_error(DBusConnection *conn, DBusMessage *req,
				   const char *text, const char *dup,
				   const char *arg1, const char *arg2)
{
	DBusMessage *msg;
	const char *args[] = {arg1, arg2, NULL};
	msg = dbus_message_new_error_printf(req, CM_DBUS_ERROR_BASE_DUPLICATE,
					    text, dup);
	if (msg != NULL) {
		cm_tdbusm_set_as(msg, args);
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
send_internal_base_no_such_entry_error(DBusConnection *conn, DBusMessage *req)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_BASE_NO_SUCH_ENTRY,
				     _("No matching entry found.\n"));
	if (msg != NULL) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Some validity-testing we do for caller-supplied arguments. */
static int
check_arg_is_absolute_path(const char *path)
{
	return (path[0] == '/') ? 0 : -1;
}

static int
check_arg_is_absolute_nss_path(const char *path)
{
	if (strncmp(path, "sql:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "dbm:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "rdb:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "extern:", 7) == 0) {
		path += 7;
	}
	return (path[0] == '/') ? 0 : -1;
}

static int
check_arg_is_directory(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			return 0;
		}
	}
	return -1;
}

static int
check_arg_is_nss_directory(const char *path)
{
	struct stat st;
	if (strncmp(path, "sql:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "dbm:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "rdb:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "extern:", 7) == 0) {
		path += 7;
	}
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			return 0;
		}
	}
	return -1;
}

static int
check_arg_is_reg_or_missing(const char *path)
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
	return -1;
}

static int
check_arg_parent_is_directory(const char *path)
{
	char *tmp, *p;
	int ret;
	if (check_arg_is_absolute_path(path) != 0) {
		return -1;
	}
	tmp = strdup(path);
	if (tmp != NULL) {
		p = strrchr(tmp, '/');
		if (p != NULL) {
			if (p > tmp) {
				*p = '\0';
			} else {
				*(p + 1) = '\0';
			}
			ret = check_arg_is_directory(tmp);
			free(tmp);
			return ret;
		}
		free(tmp);
	}
	return -1;
}

/* org.fedorahosted.certmonger.add_known_ca */
static DBusHandlerResult
base_add_known_ca(DBusConnection *conn, DBusMessage *msg,
		  struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	void *parent;
	char *ca_name, *ca_command, **ca_issuer_names, *path;
	struct cm_store_ca *ca, *new_ca;
	int i, n_cas;

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_ssoas(msg, parent,
				&ca_name, &ca_command,
				&ca_issuer_names) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	n_cas = cm_get_n_cas(ctx);
	for (i = 0; i < n_cas; i++) {
		ca = cm_get_ca_by_index(ctx, i);
		if (strcasecmp(ca->cm_nickname, ca_name) == 0) {
			cm_log(1, "There is already a CA with "
			       "the nickname \"%s\": %s.\n", ca->cm_nickname,
			       ca->cm_busname);
			talloc_free(parent);
			return send_internal_base_duplicate_error(conn, msg,
								  _("There is already a CA with the nickname \"%s\"."),
								  ca->cm_nickname,
								  NULL,
								  NULL);
		}
	}
	/* Okay, we can go ahead and add the CA. */
	new_ca = talloc_ptrtype(parent, new_ca);
	if (new_ca == NULL) {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
	memset(new_ca, 0, sizeof(*new_ca));
	/* Populate it with all of the information we have. */
	new_ca->cm_busname = cm_store_ca_next_busname(new_ca);
	new_ca->cm_nickname = talloc_strdup(new_ca, ca_name);
	new_ca->cm_ca_known_issuer_names = maybe_strdupv(new_ca,
							 ca_issuer_names);
	new_ca->cm_ca_is_default = 0;
	new_ca->cm_ca_type = cm_ca_external;
	new_ca->cm_ca_external_helper = talloc_strdup(new_ca, ca_command);
	/* Hand it off to the main loop. */
	if (cm_add_ca(ctx, new_ca) != 0) {
		cm_log(1, "Error adding CA to main context.\n");
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			cm_tdbusm_set_b(rep, FALSE);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			path = talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_CA_PATH,
					       new_ca->cm_busname);
			cm_tdbusm_set_bp(rep, TRUE, path);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			talloc_free(parent);
			return send_internal_base_error(conn, msg);
		}
	}
}

/* org.fedorahosted.certmonger.add_request */
static DBusHandlerResult
base_add_request(DBusConnection *conn, DBusMessage *msg,
		 struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	DBusHandlerResult ret;
	void *parent;
	struct cm_tdbusm_dict **d;
	const struct cm_tdbusm_dict *param;
	struct cm_store_entry *e, *new_entry;
	struct cm_store_ca *ca;
	int i, n_entries;
	enum cm_key_storage_type key_storage;
	char *key_location, *key_nickname, *key_token, *key_pin, *key_pin_file;
	enum cm_cert_storage_type cert_storage;
	char *cert_location, *cert_nickname, *cert_token;
	char *path, *pre_command, *post_command;

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_d(msg, parent, &d) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Certificate storage. */
	param = cm_tdbusm_find_dict_entry(d, "CERT_STORAGE", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_CERT_LOCATION_TYPE,
						  cm_tdbusm_dict_s);
	}
	if (param == NULL) {
		/* This is a required parameter. */
		cm_log(1, "Cert storage type not specified.\n");
		talloc_free(parent);
		return send_internal_base_missing_arg_error(conn, msg,
							    _("Certificate storage type not specified."),
							    "CERT_STORAGE");
	} else {
		/* Check that it's a known/supported type. */
		if (strcasecmp(param->value.s, "FILE") == 0) {
			cert_storage = cm_cert_storage_file;
		} else
		if (strcasecmp(param->value.s, "NSSDB") == 0) {
			cert_storage = cm_cert_storage_nssdb;
		} else {
			cm_log(1, "Unknown cert storage type \"%s\".\n",
			       param->value.s);
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("Certificate storage type \"%s\" not supported."),
							       param->value.s,
							       "CERT_STORAGE");
			talloc_free(parent);
			return ret;
		}
	}
	/* Handle parameters for either a PIN or the location of a PIN. */
	param = cm_tdbusm_find_dict_entry(d, "KEY_PIN", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_PIN,
						  cm_tdbusm_dict_s);
	}
	if ((param == NULL) ||
	    (param->value.s == NULL) ||
	    (strlen(param->value.s) == 0)) {
		key_pin = NULL;
	} else {
		key_pin = param->value.s;
		key_pin_file = NULL;
	}
	param = cm_tdbusm_find_dict_entry(d, "KEY_PIN_FILE", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_PIN_FILE,
						  cm_tdbusm_dict_s);
	}
	if ((param == NULL) ||
	    (param->value.s == NULL) ||
	    (strlen(param->value.s) == 0)) {
		key_pin_file = NULL;
	} else {
		if (check_arg_is_absolute_path(param->value.s) != 0) {
			cm_log(1, "PIN storage location is not an absolute "
			       "path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.s,
							       "KEY_PIN_FILE");
			talloc_free(parent);
			return ret;
		}
		key_pin_file = param->value.s;
		key_pin = NULL;
	}
	/* Check that other required information about the
	 * certificate's location is provided. */
	cert_location = NULL;
	cert_nickname = NULL;
	cert_token = NULL;
	switch (cert_storage) {
	case cm_cert_storage_file:
		param = cm_tdbusm_find_dict_entry(d, "CERT_LOCATION",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CERT_LOCATION_FILE,
							  cm_tdbusm_dict_s);
		}
		if (param == NULL) {
			cm_log(1, "Cert storage location not specified.\n");
			talloc_free(parent);
			return send_internal_base_missing_arg_error(conn, msg,
								    _("Certificate storage location not specified."),
								    "CERT_LOCATION");
		}
		if (check_arg_is_absolute_path(param->value.s) != 0) {
			cm_log(1, "Cert storage location is not an absolute "
			       "path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.s,
							       "CERT_LOCATION");
			talloc_free(parent);
			return ret;
		}
		if (check_arg_parent_is_directory(param->value.s) != 0) {
			cm_log(1, "Cert storage location is not inside of "
			       "a directory.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The parent of location \"%s\" must be a valid directory."),
							       param->value.s,
							       "CERT_LOCATION");
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_reg_or_missing(param->value.s) != 0) {
			cm_log(1, "Cert storage location is "
			       "not a regular file.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be a file."),
							       param->value.s,
							       "CERT_LOCATION");
			talloc_free(parent);
			return ret;
		}
		cert_location = param->value.s;
		cert_nickname = NULL;
		cert_token = NULL;
		break;
	case cm_cert_storage_nssdb:
		param = cm_tdbusm_find_dict_entry(d, "CERT_LOCATION",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CERT_LOCATION_DATABASE,
							  cm_tdbusm_dict_s);
		}
		if (param == NULL) {
			cm_log(1, "Cert storage location not specified.\n");
			talloc_free(parent);
			return send_internal_base_missing_arg_error(conn, msg,
								    _("Certificate storage location not specified."),
								    "CERT_LOCATION");
		}
		if (check_arg_is_absolute_nss_path(param->value.s) != 0) {
			cm_log(1, "Cert storage location is not an absolute "
			       "path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.s,
							       "CERT_LOCATION");
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_nss_directory(param->value.s) != 0) {
			cm_log(1, "Cert storage location must be "
			       "a directory.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be a directory."),
							       param->value.s,
							       "CERT_LOCATION");
			talloc_free(parent);
			return ret;
		}
		cert_location = cm_store_canonicalize_directory(parent,
								param->value.s);
		param = cm_tdbusm_find_dict_entry(d, "CERT_NICKNAME",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CERT_LOCATION_NICKNAME,
							  cm_tdbusm_dict_s);
		}
		if (param == NULL) {
			cm_log(1, "Cert nickname not specified.\n");
			talloc_free(parent);
			return send_internal_base_missing_arg_error(conn, msg,
								    _("Certificate nickname not specified."),
								    "CERT_NICKNAME");
		}
		cert_nickname = param->value.s;
		param = cm_tdbusm_find_dict_entry(d, "CERT_TOKEN",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CERT_LOCATION_TOKEN,
							  cm_tdbusm_dict_s);
		}
		if (param == NULL) {
			cert_token = NULL;
		} else {
			cert_token = param->value.s;
		}
		break;
	}
	if (cert_location == NULL) {
		cm_log(1, "Cert storage location not specified.\n");
		talloc_free(parent);
		return send_internal_base_missing_arg_error(conn, msg,
							    _("Certificate storage location not specified."),
							    "CERT_LOCATION");
	}
	/* Check that the requested nickname will be unique. */
	param = cm_tdbusm_find_dict_entry(d, "NICKNAME", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_NICKNAME,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		n_entries = cm_get_n_entries(ctx);
		for (i = 0; i < n_entries; i++) {
			e = cm_get_entry_by_index(ctx, i);
			if (strcasecmp(e->cm_nickname, param->value.s) == 0) {
				cm_log(1, "There is already a request with "
				       "the nickname \"%s\": %s.\n",
				       e->cm_nickname, e->cm_busname);
				talloc_free(parent);
				return send_internal_base_duplicate_error(conn,
									  msg,
									  _("There is already a request with the nickname \"%s\"."),
									  e->cm_nickname,
									  "NICKNAME",
									  NULL);
			}
		}
	}
	/* Check for a duplicate of another entry's certificate storage
	 * information. */
	n_entries = cm_get_n_entries(ctx);
	for (i = 0; i < n_entries; i++) {
		e = cm_get_entry_by_index(ctx, i);
		if (cert_storage != e->cm_cert_storage_type) {
			continue;
		}
		if (strcmp(cert_location, e->cm_cert_storage_location) != 0) {
			continue;
		}
		switch (cert_storage) {
		case cm_cert_storage_file:
			break;
		case cm_cert_storage_nssdb:
			if (strcmp(cert_nickname, e->cm_cert_nickname) != 0) {
				continue;
			}
			break;
		}
		break;
	}
	if (i < n_entries) {
		/* We found a match, and that's bad. */
		cm_log(1, "Cert at same location is already being "
		       "used for request %s with nickname \"%s\".\n",
		       e->cm_busname, e->cm_nickname);
		talloc_free(parent);
		return send_internal_base_duplicate_error(conn, msg,
							  _("Certificate at same location is already used by request with nickname \"%s\"."),
							  e->cm_nickname,
							  "CERT_LOCATION",
							  cert_storage == cm_cert_storage_nssdb ?
							  "CERT_NICKNAME" : NULL);
	}
	/* Key storage.  We can afford to be a bit more lax about this because
	 * we don't require that we know anything about the key. */
	param = cm_tdbusm_find_dict_entry(d, "KEY_STORAGE", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_LOCATION_TYPE,
						  cm_tdbusm_dict_s);
	}
	if (param == NULL) {
		key_storage = cm_key_storage_none;
		key_location = NULL;
		key_token = NULL;
		key_nickname = NULL;
	} else {
		/* Check that it's a known/supported type. */
		if (strcasecmp(param->value.s, "FILE") == 0) {
			key_storage = cm_key_storage_file;
		} else
		if (strcasecmp(param->value.s, "NSSDB") == 0) {
			key_storage = cm_key_storage_nssdb;
		} else
		if (strcasecmp(param->value.s, "NONE") == 0) {
			key_storage = cm_key_storage_none;
		} else {
			cm_log(1, "Unknown key storage type \"%s\".\n",
			       param->value.s);
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("Key storage type \"%s\" not supported."),
							       param->value.s,
							       "KEY_STORAGE");
			talloc_free(parent);
			return ret;
		}
		/* Check that other required information about the key's
		 * location is provided. */
		switch (key_storage) {
		case cm_key_storage_none:
			key_location = NULL;
			key_nickname = NULL;
			key_token = NULL;
			break;
		case cm_key_storage_file:
			param = cm_tdbusm_find_dict_entry(d, "KEY_LOCATION",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				param = cm_tdbusm_find_dict_entry(d,
								  CM_DBUS_PROP_KEY_LOCATION_FILE,
								  cm_tdbusm_dict_s);
			}
			if (param == NULL) {
				cm_log(1,
				       "Key storage location not specified.\n");
				talloc_free(parent);
				return send_internal_base_missing_arg_error(conn, msg,
									    _("Key storage location not specified."),
									    "KEY_LOCATION");
			}
			if (check_arg_is_absolute_path(param->value.s) != 0) {
				cm_log(1, "Key storage location is not an "
				       "absolute path.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be an absolute path."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			if (check_arg_parent_is_directory(param->value.s) != 0) {
				cm_log(1, "Key storage location is not inside "
				       "of a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" must be a valid directory."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			if (check_arg_is_reg_or_missing(param->value.s) != 0) {
				cm_log(1, "Key storage location is "
				       "not a regular file.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be a file."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			key_location = param->value.s;
			key_nickname = NULL;
			key_token = NULL;
			break;
		case cm_key_storage_nssdb:
			param = cm_tdbusm_find_dict_entry(d, "KEY_LOCATION",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				param = cm_tdbusm_find_dict_entry(d,
								  CM_DBUS_PROP_KEY_LOCATION_DATABASE,
								  cm_tdbusm_dict_s);
			}
			if (param == NULL) {
				cm_log(1,
				       "Key storage location not specified.\n");
				talloc_free(parent);
				return send_internal_base_missing_arg_error(conn, msg,
									    _("Key storage location not specified."),
									    "KEY_LOCATION");
			}
			if (check_arg_is_absolute_nss_path(param->value.s) != 0) {
				cm_log(1, "Key storage location is not an "
				       "absolute path.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be an absolute path."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			if (check_arg_is_nss_directory(param->value.s) != 0) {
				cm_log(1, "Key storage location must be "
				       "a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be a directory."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			key_location = cm_store_canonicalize_directory(parent,
								       param->value.s);
			param = cm_tdbusm_find_dict_entry(d, "KEY_NICKNAME",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				param = cm_tdbusm_find_dict_entry(d,
								  CM_DBUS_PROP_KEY_LOCATION_NICKNAME,
								  cm_tdbusm_dict_s);
			}
			if (param == NULL) {
				cm_log(1, "Key nickname not specified.\n");
				talloc_free(parent);
				return send_internal_base_missing_arg_error(conn, msg,
									    _("Key nickname not specified."),
									    "KEY_NICKNAME");
			}
			key_nickname = param->value.s;
			param = cm_tdbusm_find_dict_entry(d, "KEY_TOKEN",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				param = cm_tdbusm_find_dict_entry(d,
								  CM_DBUS_PROP_KEY_LOCATION_TOKEN,
								  cm_tdbusm_dict_s);
			}
			if (param == NULL) {
				key_token = NULL;
			} else {
				key_token = param->value.s;
			}
			break;
		}
		/* Check for a duplicate of another entry's key storage
		 * information. */
		n_entries = cm_get_n_entries(ctx);
		for (i = 0; i < n_entries; i++) {
			e = cm_get_entry_by_index(ctx, i);
			if (key_storage != e->cm_key_storage_type) {
				continue;
			}
			switch (key_storage) {
			case cm_key_storage_none:
				continue;
				break;
			case cm_key_storage_file:
				if (strcmp(key_location,
					   e->cm_key_storage_location) != 0) {
					continue;
				}
				break;
			case cm_key_storage_nssdb:
				if (strcmp(key_location,
					   e->cm_key_storage_location) != 0) {
					continue;
				}
				if (strcmp(key_nickname,
					   e->cm_key_nickname) != 0) {
					continue;
				}
				break;
			}
			break;
		}
		if (i < n_entries) {
			/* We found a match, and that's bad. */
			cm_log(1, "Key at same location is already being "
			       "used for request %s with nickname \"%s\".\n",
			       e->cm_busname, e->cm_nickname);
			talloc_free(parent);
			return send_internal_base_duplicate_error(conn, msg,
								  _("Key at same location is already used by request with nickname \"%s\"."),
								  e->cm_nickname,
								  "KEY_LOCATION",
								  key_storage == cm_key_storage_nssdb ?
								  "KEY_NICKNAME" : NULL);
		}
	}
	/* What to run before we save the certificate. */
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_CERT_PRESAVE_COMMAND,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		pre_command = param->value.s;
	} else {
		pre_command = NULL;
	}
	/* What to run after we save the certificate. */
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_CERT_POSTSAVE_COMMAND,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		post_command = param->value.s;
	} else {
		post_command = NULL;
	}
	/* Okay, we can go ahead and add the entry. */
	new_entry = talloc_ptrtype(parent, new_entry);
	if (new_entry == NULL) {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
	memset(new_entry, 0, sizeof(*new_entry));
	/* Populate it with all of the information we have. */
	new_entry->cm_busname = cm_store_entry_next_busname(new_entry);
	param = cm_tdbusm_find_dict_entry(d, "NICKNAME", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_NICKNAME,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		new_entry->cm_nickname = talloc_strdup(new_entry,
						       param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d, "KEY_SIZE", cm_tdbusm_dict_n);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_SIZE,
						  cm_tdbusm_dict_n);
	}
	if (param != NULL) {
		new_entry->cm_key_type.cm_key_gen_algorithm = CM_DEFAULT_PUBKEY_TYPE;
		new_entry->cm_key_type.cm_key_gen_size = param->value.n;
	} else {
		new_entry->cm_key_type.cm_key_gen_algorithm = CM_DEFAULT_PUBKEY_TYPE;
		new_entry->cm_key_type.cm_key_gen_size = CM_DEFAULT_PUBKEY_SIZE;
	}
	if (new_entry->cm_key_type.cm_key_gen_size < CM_MINIMUM_PUBKEY_SIZE) {
		new_entry->cm_key_type.cm_key_gen_size = CM_MINIMUM_PUBKEY_SIZE;
	}
	/* Key and certificate storage. */
	new_entry->cm_key_storage_type = key_storage;
	new_entry->cm_key_storage_location = maybe_strdup(new_entry,
							  key_location);
	new_entry->cm_key_nickname = maybe_strdup(new_entry, key_nickname);
	new_entry->cm_key_token = maybe_strdup(new_entry, key_token);
	new_entry->cm_key_pin = maybe_strdup(new_entry, key_pin);
	new_entry->cm_key_pin_file = maybe_strdup(new_entry, key_pin_file);
	new_entry->cm_cert_storage_type = cert_storage;
	new_entry->cm_cert_storage_location = maybe_strdup(new_entry,
							   cert_location);
	new_entry->cm_cert_nickname = maybe_strdup(new_entry, cert_nickname);
	new_entry->cm_cert_token = maybe_strdup(new_entry, cert_token);
	/* Which CA to use. */
	param = cm_tdbusm_find_dict_entry(d, "CA", cm_tdbusm_dict_p);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_CA,
						  cm_tdbusm_dict_p);
	}
	if (param != NULL) {
		ca = get_ca_for_path(ctx, param->value.s);
		if (ca != NULL) {
			new_entry->cm_ca_nickname = talloc_strdup(new_entry,
								  ca->cm_nickname);
		} else {
			cm_log(1, "No CA with path \"%s\" known.\n",
			       param->value.s);
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("No such CA."),
							       param->value.s,
							       "CA");
			talloc_free(parent);
			return ret;
		}
	}
	/* What to tell the CA we want. */
	param = cm_tdbusm_find_dict_entry(d, CM_DBUS_PROP_CA_PROFILE, cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_ca_profile = maybe_strdup(new_entry,
							param->value.s);
	}
	/* Behavior settings. */
	param = cm_tdbusm_find_dict_entry(d, "TRACK", cm_tdbusm_dict_b);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_MONITORING,
						  cm_tdbusm_dict_b);
	}
	if (param != NULL) {
		new_entry->cm_monitor = param->value.b;
	} else {
		new_entry->cm_monitor = cm_prefs_monitor();
	}
	param = cm_tdbusm_find_dict_entry(d, "RENEW", cm_tdbusm_dict_b);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_AUTORENEW,
						  cm_tdbusm_dict_b);
	}
	if (param != NULL) {
		new_entry->cm_autorenew = param->value.b;
	} else {
		new_entry->cm_autorenew = cm_prefs_autorenew();
	}
	if (pre_command != NULL) {
		new_entry->cm_pre_certsave_uid = talloc_asprintf(new_entry,
								 "%lu",
								 (unsigned long) ci->uid);
		if (new_entry->cm_pre_certsave_uid != NULL) {
			new_entry->cm_pre_certsave_command = maybe_strdup(new_entry,
									  pre_command);
		}
	}
	if (post_command != NULL) {
		new_entry->cm_post_certsave_uid = talloc_asprintf(new_entry,
								  "%lu",
								  (unsigned long) ci->uid);
		if (new_entry->cm_post_certsave_uid != NULL) {
			new_entry->cm_post_certsave_command = maybe_strdup(new_entry,
									   post_command);
		}
	}
	/* Template information. */
	param = cm_tdbusm_find_dict_entry(d, "SUBJECT", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_SUBJECT,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		new_entry->cm_template_subject = maybe_strdup(new_entry,
							      param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d, "EKU", cm_tdbusm_dict_as);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_EKU,
						  cm_tdbusm_dict_as);
	}
	if (param != NULL) {
		new_entry->cm_template_eku = cm_submit_maybe_joinv(new_entry,
								   ",",
								   param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "PRINCIPAL", cm_tdbusm_dict_as);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_PRINCIPAL,
						  cm_tdbusm_dict_as);
	}
	if (param != NULL) {
		new_entry->cm_template_principal = maybe_strdupv(new_entry,
								 param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "DNS", cm_tdbusm_dict_as);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_HOSTNAME,
						  cm_tdbusm_dict_as);
	}
	if (param != NULL) {
		new_entry->cm_template_hostname = maybe_strdupv(new_entry,
								param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "EMAIL", cm_tdbusm_dict_as);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_EMAIL,
						  cm_tdbusm_dict_as);
	}
	if (param != NULL) {
		new_entry->cm_template_email = maybe_strdupv(new_entry,
							     param->value.as);
	}
	/* Hand it off to the main loop. */
	new_entry->cm_state = CM_NEWLY_ADDED;
	if (cm_add_entry(ctx, new_entry) != 0) {
		cm_log(1, "Error adding entry to main loop.\n");
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			cm_tdbusm_set_b(rep, FALSE);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			path = talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_REQUEST_PATH,
					       new_entry->cm_busname);
			cm_tdbusm_set_bp(rep, TRUE, path);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			talloc_free(parent);
			return send_internal_base_error(conn, msg);
		}
	}
}

/* org.fedorahosted.certmonger.find_request_by_nickname */
static DBusHandlerResult
base_find_request_by_nickname(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	struct cm_store_entry *entry;
	DBusMessage *rep;
	void *parent;
	char *arg, *path;
	int i, n_entries;

	parent = talloc_new(NULL);
	path = NULL;
	if (cm_tdbusm_get_s(msg, parent, &arg) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else {
		n_entries = cm_get_n_entries(ctx);
		for (i = 0; i < n_entries; i++) {
			entry = cm_get_entry_by_index(ctx, i);
			if (strcmp(arg, entry->cm_nickname) == 0) {
				path = talloc_asprintf(ctx, "%s/%s",
						       CM_DBUS_REQUEST_PATH,
						       entry->cm_busname);
				break;
			}
		}
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (path != NULL) {
			cm_tdbusm_set_p(rep, path);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.find_ca_by_nickname */
static DBusHandlerResult
base_find_ca_by_nickname(DBusConnection *conn, DBusMessage *msg,
			 struct cm_client_info *ci, struct cm_context *ctx)
{
	struct cm_store_ca *ca;
	DBusMessage *rep;
	void *parent;
	char *arg, *path;
	int i, n_cas;

	parent = talloc_new(NULL);
	path = NULL;
	if (cm_tdbusm_get_s(msg, parent, &arg) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else {
		n_cas = cm_get_n_cas(ctx);
		for (i = 0; i < n_cas; i++) {
			ca = cm_get_ca_by_index(ctx, i);
			if (strcmp(arg, ca->cm_nickname) == 0) {
				path = talloc_asprintf(ctx, "%s/%s",
						       CM_DBUS_CA_PATH,
						       ca->cm_busname);
				break;
			}
		}
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (path != NULL) {
			cm_tdbusm_set_p(rep, path);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.get_known_cas */
static DBusHandlerResult
base_get_known_cas(DBusConnection *conn, DBusMessage *msg,
		   struct cm_client_info *ci, struct cm_context *ctx)
{
	int i, n_cas;
	struct cm_store_ca *ca;
	char **ret;
	DBusMessage *rep;
	n_cas = cm_get_n_cas(ctx);
	ret = talloc_array(ctx, char *, n_cas + 1);
	if (ret != NULL) {
		for (i = 0; i < n_cas; i++) {
			ca = cm_get_ca_by_index(ctx, i);
			if (ca == NULL) {
				break;
			}
			ret[i] = talloc_asprintf(ret, "%s/%s",
						 CM_DBUS_CA_PATH,
						 ca->cm_busname);
		}
		ret[i] = NULL;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_ap(rep, (const char **) ret);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(ret);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		talloc_free(ret);
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.get_requests */
static DBusHandlerResult
base_get_requests(DBusConnection *conn, DBusMessage *msg,
		  struct cm_client_info *ci, struct cm_context *ctx)
{
	int i, n_entries;
	struct cm_store_entry *entry;
	char **ret;
	DBusMessage *rep;
	n_entries = cm_get_n_entries(ctx);
	ret = talloc_array(ctx, char *, n_entries + 1);
	if (ret != NULL) {
		for (i = 0; i < n_entries; i++) {
			entry = cm_get_entry_by_index(ctx, i);
			if (entry == NULL) {
				break;
			}
			ret[i] = talloc_asprintf(ret, "%s/%s",
						 CM_DBUS_REQUEST_PATH,
						 entry->cm_busname);
		}
		ret[i] = NULL;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_ap(rep, (const char **) ret);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(ret);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		talloc_free(ret);
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.get_supported_key_types */
static DBusHandlerResult
base_get_supported_key_types(DBusConnection *conn, DBusMessage *msg,
			     struct cm_client_info *ci, struct cm_context *ctx)
{
	const char *key_types[] = {"RSA", NULL};
	DBusMessage *rep;
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_as(rep, key_types);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_base_error(conn, msg);
	}
}

static DBusHandlerResult
base_get_supported_key_and_cert_storage(DBusConnection *conn, DBusMessage *msg,
					struct cm_client_info *ci, struct cm_context *ctx)
{
#ifdef HAVE_OPENSSL
	const char *maybe_file = "FILE";
#else
	const char *maybe_file = NULL;
#endif
	const char *storage_types[] = {"NSSDB", maybe_file, NULL};
	DBusMessage *rep;
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_as(rep, storage_types);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.get_supported_key_storage */
static DBusHandlerResult
base_get_supported_key_storage(DBusConnection *conn, DBusMessage *msg,
			       struct cm_client_info *ci, struct cm_context *ctx)
{
	return base_get_supported_key_and_cert_storage(conn, msg, ci, ctx);
}

/* org.fedorahosted.certmonger.get_supported_cert_storage */
static DBusHandlerResult
base_get_supported_cert_storage(DBusConnection *conn, DBusMessage *msg,
				struct cm_client_info *ci, struct cm_context *ctx)
{
	return base_get_supported_key_and_cert_storage(conn, msg, ci, ctx);
}

/* org.fedorahosted.certmonger.remove_known_ca */
static DBusHandlerResult
base_remove_known_ca(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	int ret;
	void *parent;
	char *path;

	rep = dbus_message_new_method_return(msg);
	if (rep == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_p(msg, parent, &path) == 0) {
		ca = get_ca_for_path(ctx, path);
		talloc_free(parent);
		if (ca != NULL) {
			ret = cm_remove_ca(ctx, ca->cm_nickname);
			cm_tdbusm_set_b(rep, (ret == 0));
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			dbus_message_unref(rep);
			return send_internal_base_no_such_entry_error(conn,
								      msg);
		}
	} else {
		talloc_free(parent);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
}

/* org.fedorahosted.certmonger.remove_request */
static DBusHandlerResult
base_remove_request(DBusConnection *conn, DBusMessage *msg,
		    struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	int ret;
	void *parent;
	char *path;

	rep = dbus_message_new_method_return(msg);
	if (rep == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_p(msg, parent, &path) == 0) {
		entry = get_entry_for_path(ctx, path);
		talloc_free(parent);
		if (entry != NULL) {
			ret = cm_remove_entry(ctx, entry->cm_nickname);
			cm_tdbusm_set_b(rep, (ret == 0));
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			dbus_message_unref(rep);
			return send_internal_base_no_such_entry_error(conn,
								      msg);
		}
	} else {
		talloc_free(parent);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
}

/* Convenience functions for returning errors from a CA object to callers. */
static DBusHandlerResult
send_internal_ca_error(DBusConnection *conn, DBusMessage *req)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_CA_INTERNAL,
				     _("An internal error has occurred."));
	if (msg != NULL) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Functions implemented for CA objects.  Most of the "get_XXX" functions
 * predate the properties interface being added, so they're redundant now. */

/* org.fedorahosted.certonger.ca.get_nickname */
static DBusHandlerResult
ca_get_nickname(DBusConnection *conn, DBusMessage *msg,
		struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;

	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (ca->cm_nickname != NULL) {
			cm_tdbusm_set_s(rep, ca->cm_nickname);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_is_default */
static DBusHandlerResult
ca_get_is_default(DBusConnection *conn, DBusMessage *msg,
		  struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_b(rep, ca->cm_ca_is_default);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_issuer_names */
static DBusHandlerResult
ca_get_issuer_names(DBusConnection *conn, DBusMessage *msg,
		    struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char **names;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		names = (const char **) ca->cm_ca_known_issuer_names;
		cm_tdbusm_set_as(rep, names);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_location */
static DBusHandlerResult
ca_get_location(DBusConnection *conn, DBusMessage *msg,
		struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, ca->cm_ca_external_helper);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_type */
static DBusHandlerResult
ca_get_type(DBusConnection *conn, DBusMessage *msg,
	    struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char *ca_type;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		ca_type = NULL;
		switch (ca->cm_ca_type) {
		case cm_ca_internal_self:
			ca_type = "INTERNAL:SELF";
			break;
		case cm_ca_external:
			ca_type = "EXTERNAL";
			break;
		}
		cm_tdbusm_set_s(rep, ca_type);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_serial */
static DBusHandlerResult
ca_get_serial(DBusConnection *conn, DBusMessage *msg,
	      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char *serial;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		switch (ca->cm_ca_type) {
		case cm_ca_internal_self:
			serial = ca->cm_ca_internal_serial;
			cm_tdbusm_set_s(rep, serial);
			break;
		case cm_ca_external:
			break;
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* Custom property get/set logic for CA structures. */
static dbus_bool_t
ca_prop_get_is_default(struct cm_context *ctx, void *parent,
		       void *record, const char *name)
{
	struct cm_store_ca *ca = record;
	if (strcmp(name, CM_DBUS_PROP_IS_DEFAULT) == 0) {
		return ca->cm_ca_is_default ? TRUE : FALSE;
	}
	return FALSE;
}

static void
ca_prop_set_is_default(struct cm_context *ctx, void *parent,
		       void *record, const char *name,
		       dbus_bool_t new_value)
{
	const char *propname[2], *path;
	struct cm_store_ca *ca = record, *other;
	int i;

	if (strcmp(name, CM_DBUS_PROP_IS_DEFAULT) == 0) {
		propname[0] = CM_DBUS_PROP_IS_DEFAULT;
		propname[1] = NULL;
		if (new_value) {
			i = 0;
			while ((other = cm_get_ca_by_index(ctx, i++)) != NULL) {
				if ((other != ca) &&
				    (other->cm_ca_is_default)) {
					other->cm_ca_is_default = FALSE;
					path = talloc_asprintf(parent, "%s/%s",
							       CM_DBUS_CA_PATH,
							       other->cm_busname);
					cm_tdbush_property_emit_changed(ctx, path,
									CM_DBUS_CA_INTERFACE,
									propname);
				}
			}
		}
		if ((!ca->cm_ca_is_default && new_value) ||
		    (ca->cm_ca_is_default && !new_value)) {
			ca->cm_ca_is_default = new_value;
			path = talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_CA_PATH,
					       ca->cm_busname);
			cm_tdbush_property_emit_changed(ctx, path,
							CM_DBUS_CA_INTERFACE,
							propname);
		}
	}
}

/* Convenience functions for returning errors from a request object to callers. */
static DBusHandlerResult
send_internal_request_error(DBusConnection *conn, DBusMessage *req)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_REQUEST_INTERNAL,
				     _("An internal error has occurred."));
	if (msg != NULL) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Functions implemented for request objects.  Most of the "get_XXX" functions
 * predate the properties interface being added, so they're redundant now. */

/* org.fedorahosted.certmonger.request.get_nickname */
static DBusHandlerResult
request_get_nickname(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_nickname != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_nickname);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_key_pin */
static DBusHandlerResult
request_get_key_pin(DBusConnection *conn, DBusMessage *msg,
		    struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, entry->cm_key_pin);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_key_pin_file */
static DBusHandlerResult
request_get_key_pin_file(DBusConnection *conn, DBusMessage *msg,
			 struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, entry->cm_key_pin_file);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_autorenew */
static DBusHandlerResult
request_get_autorenew(DBusConnection *conn, DBusMessage *msg,
		      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_b(rep, entry->cm_autorenew);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_cert_data */
static DBusHandlerResult
request_get_cert_data(DBusConnection *conn, DBusMessage *msg,
		      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_cert != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_cert);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* convert our text bit string into a number */
static long
ku_from_string(const char *ku)
{
	long i = 0;
	while ((ku != NULL) && (*ku++ != '\0')) {
		i <<= 1;
		i |= 1;
	}
	return i;
}

/* split the comma-separated list into an array */
static char **
eku_splitv(void *parent, const char *eku)
{
	char **ret = NULL;
	const char *p, *q;
	int i;
	if ((eku != NULL) && (strlen(eku) > 0)) {
		ret = talloc_array_ptrtype(parent, ret, strlen(eku) + 1);
		p = eku;
		i = 0;
		while (*p != '\0') {
			q = p + strcspn(p, ",");
			if (p != q) {
				ret[i++] = talloc_strndup(ret, p, q - p);
			}
			p = q + strspn(q, ",");
		}
		ret[i] = NULL;
		if (i == 0) {
			talloc_free(ret);
			ret = NULL;
		}
	}
	return ret;
}

/* org.fedorahosted.certmonger.request.get_cert_info */
static DBusHandlerResult
request_get_cert_info(DBusConnection *conn, DBusMessage *msg,
		      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	char **eku;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		eku = eku_splitv(entry, entry->cm_cert_eku);
		cm_tdbusm_set_sssnasasasnas(rep,
					    entry->cm_cert_issuer,
					    entry->cm_cert_serial,
					    entry->cm_cert_subject,
					    entry->cm_cert_not_after,
					    (const char **) entry->cm_cert_email,
					    (const char **) entry->cm_cert_hostname,
					    (const char **) entry->cm_cert_principal,
					    ku_from_string(entry->cm_cert_ku),
					    (const char **) eku);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(eku);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_cert_last_checked */
static DBusHandlerResult
request_get_cert_last_checked(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_submitted != 0) {
			cm_tdbusm_set_n(rep, entry->cm_submitted);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_cert_storage_info */
static DBusHandlerResult
request_get_cert_storage_info(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *type, *location, *nick, *token;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		location = entry->cm_cert_storage_location;
		switch (entry->cm_cert_storage_type) {
		case cm_cert_storage_file:
			type = "FILE";
			cm_tdbusm_set_ss(rep, type, location);
			dbus_connection_send(conn, rep, NULL);
			break;
		case cm_cert_storage_nssdb:
			type = "NSSDB";
			token = entry->cm_cert_token;
			nick = entry->cm_cert_nickname;
			if (token != NULL) {
				cm_tdbusm_set_ssss(rep, type,
						   location, nick, token);
				dbus_connection_send(conn, rep, NULL);
			} else
			if (nick != NULL) {
				cm_tdbusm_set_sss(rep, type, location, nick);
				dbus_connection_send(conn, rep, NULL);
			} else {
				cm_tdbusm_set_ss(rep, type, location);
				dbus_connection_send(conn, rep, NULL);
			}
			break;
		}
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_csr_data */
static DBusHandlerResult
request_get_csr_data(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_csr != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_csr);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_csr_info */
static DBusHandlerResult
request_get_csr_info(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	char **eku;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_csr != NULL) {
			eku = eku_splitv(entry, entry->cm_template_eku);
			cm_tdbusm_set_sasasasnas(rep,
						 entry->cm_template_subject,
						 (const char **) entry->cm_template_email,
						 (const char **) entry->cm_template_hostname,
						 (const char **) entry->cm_template_principal,
						 ku_from_string(entry->cm_template_ku),
						 (const char **) eku);
			talloc_free(eku);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_key_storage_info */
static DBusHandlerResult
request_get_key_storage_info(DBusConnection *conn, DBusMessage *msg,
			     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *type, *location, *nick, *token;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		location = entry->cm_key_storage_location;
		switch (entry->cm_key_storage_type) {
		case cm_key_storage_none:
			type = "NONE";
			cm_tdbusm_set_s(rep, type);
			dbus_connection_send(conn, rep, NULL);
			break;
		case cm_key_storage_file:
			type = "FILE";
			cm_tdbusm_set_ss(rep, type, location);
			dbus_connection_send(conn, rep, NULL);
			break;
		case cm_key_storage_nssdb:
			type = "NSSDB";
			token = entry->cm_key_token;
			nick = entry->cm_key_nickname;
			if (token != NULL) {
				cm_tdbusm_set_ssss(rep, type,
						   location, nick, token);
				dbus_connection_send(conn, rep, NULL);
			} else
			if (nick != NULL) {
				cm_tdbusm_set_sss(rep, type, location, nick);
				dbus_connection_send(conn, rep, NULL);
			} else {
				cm_tdbusm_set_ss(rep, type, location);
				dbus_connection_send(conn, rep, NULL);
			}
			break;
		}
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_key_type_and_size */
static DBusHandlerResult
request_get_key_type_and_size(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *type;
	int size;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	type = "UNKNOWN";
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_unspecified:
		type = "UNKNOWN";
		break;
	case cm_key_rsa:
		type = "RSA";
		break;
	}
	if (rep != NULL) {
		size = entry->cm_key_type.cm_key_size;
		cm_tdbusm_set_sn(rep, type, size);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_monitoring */
static DBusHandlerResult
request_get_monitoring(DBusConnection *conn, DBusMessage *msg,
		       struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_b(rep, entry->cm_monitor);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_notification_info */
static DBusHandlerResult
request_get_notification_info(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	enum cm_notification_method m;
	const char *method, *d;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	m = cm_prefs_notification_method();
	d = cm_prefs_notification_destination();
	method = NULL;
	switch (m) {
	case cm_notification_unspecified:
		abort();
		break;
	case cm_notification_none:
		method = "none";
		break;
	case cm_notification_stdout:
		method = "stdout";
		break;
	case cm_notification_syslog:
		method = "syslog";
		break;
	case cm_notification_email:
		method = "email";
		break;
	case cm_notification_command:
		method = "command";
		break;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_ss(rep, method, d);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

static dbus_bool_t request_prop_get_stuck(struct cm_context *ctx, void *parent,
					  void *record, const char *name);

/* org.fedorahosted.certmonger.request.get_status */
static DBusHandlerResult
request_get_status(DBusConnection *conn, DBusMessage *msg,
		   struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *state;
	dbus_bool_t stuck;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		state = cm_store_state_as_string(entry->cm_state);
		stuck = request_prop_get_stuck(ctx, NULL, entry, CM_DBUS_PROP_STUCK);
		cm_tdbusm_set_sb(rep, state, stuck);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_ca */
static DBusHandlerResult
request_get_ca(DBusConnection *conn, DBusMessage *msg,
	       struct cm_client_info *ci, struct cm_context *ctx)
{
	void *parent;
	DBusMessage *rep;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *path;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		parent = talloc_new(NULL);
		if ((entry->cm_ca_nickname != NULL) &&
		    (strlen(entry->cm_ca_nickname) > 0)) {
			ca = cm_get_ca_by_nickname(ctx, entry->cm_ca_nickname);
			if ((ca != NULL) &&
			    (ca->cm_busname != NULL) &&
			    (strlen(ca->cm_busname) > 0)) {
				path = talloc_asprintf(parent, "%s/%s",
						       CM_DBUS_CA_PATH,
						       ca->cm_busname);
				cm_tdbusm_set_p(rep, path);
			}
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_ca_error */
static DBusHandlerResult
request_get_ca_error(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	void *parent;
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		parent = talloc_new(NULL);
		if ((entry->cm_ca_error != NULL) &&
		    (strlen(entry->cm_ca_error) > 0)) {
			cm_tdbusm_set_s(rep, entry->cm_ca_error);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_submitted_cookie */
static DBusHandlerResult
request_get_submitted_cookie(DBusConnection *conn, DBusMessage *msg,
			     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_ca_cookie != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_ca_cookie);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_submitted_date */
static DBusHandlerResult
request_get_submitted_date(DBusConnection *conn, DBusMessage *msg,
			   struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_submitted != 0) {
			cm_tdbusm_set_n(rep, entry->cm_submitted);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.modify */
static DBusHandlerResult
request_modify(DBusConnection *conn, DBusMessage *msg,
	       struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	struct cm_tdbusm_dict **d;
	const struct cm_tdbusm_dict *param;
	char *new_request_path;
	void *parent;
	const char *propname[sizeof(*entry)];
	int i;
	size_t n_propname = 0;

	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	parent = talloc_new(NULL);
	if (cm_tdbusm_get_d(msg, parent, &d) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		/* Check any new nickname values, because we need to reject
		 * those outright if the new value's already being used. */
		param = cm_tdbusm_find_dict_entry(d, "NICKNAME",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_NICKNAME,
							  cm_tdbusm_dict_s);
		}
		if (param != NULL) {
			if (cm_get_entry_by_nickname(ctx, param->value.s) != NULL) {
				return send_internal_base_duplicate_error(conn, msg,
									  _("There is already a request with the nickname \"%s\"."),
									  param->value.s,
									  "NICKNAME",
									  NULL);
			}
		}
		/* If we're being asked to change the CA, check that the new CA
		 * exists. */
		param = cm_tdbusm_find_dict_entry(d, "CA", cm_tdbusm_dict_p);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CA,
							  cm_tdbusm_dict_p);
		}
		if (param != NULL) {
			ca = get_ca_for_path(ctx, param->value.s);
			if (ca == NULL) {
				return send_internal_base_bad_arg_error(conn, msg,
									_("Certificate authority \"%s\" not known."),
									param->value.s,
									"CA");
			}
		}
		/* Now walk the list of other things the client asked us to
		 * change. */
		for (i = 0; (d != NULL) && (d[i] != NULL); i++) {
			param = d[i];
			if ((param->value_type == cm_tdbusm_dict_b) &&
			    ((strcasecmp(param->key, "RENEW") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_AUTORENEW) == 0))) {
				entry->cm_autorenew = param->value.b;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_AUTORENEW;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_b) &&
			    ((strcasecmp(param->key, "TRACK") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_MONITORING) == 0))) {
				entry->cm_monitor = param->value.b;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_MONITORING;
				}
			} else
			if (((param->value_type == cm_tdbusm_dict_s) ||
			     (param->value_type == cm_tdbusm_dict_p)) &&
			    ((strcasecmp(param->key, "CA") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_CA) == 0))) {
				ca = get_ca_for_path(ctx, param->value.s);
				talloc_free(entry->cm_ca_nickname);
				entry->cm_ca_nickname = talloc_strdup(entry,
								      ca->cm_nickname);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CA;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_CA_PROFILE) == 0)) {
				talloc_free(entry->cm_ca_profile);
				entry->cm_ca_profile = talloc_strdup(entry,
								     param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CA_PROFILE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "NICKNAME") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_NICKNAME) == 0))) {
				talloc_free(entry->cm_nickname);
				entry->cm_nickname = talloc_strdup(entry,
								   param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_NICKNAME;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "SUBJECT") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_SUBJECT) == 0))) {
				talloc_free(entry->cm_template_subject);
				entry->cm_template_subject = maybe_strdup(entry,
									  param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_SUBJECT;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "KEY_PIN") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_KEY_PIN) == 0))) {
				talloc_free(entry->cm_key_pin);
				entry->cm_key_pin = maybe_strdup(entry,
								 param->value.s);
				if (entry->cm_key_pin != NULL) {
					entry->cm_key_pin_file = NULL;
				}
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_KEY_PIN;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "KEY_PIN_FILE") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_KEY_PIN_FILE) == 0))) {
				if ((param->value.s != NULL) &&
				    (strlen(param->value.s) != 0) &&
				    (check_arg_is_absolute_path(param->value.s) != 0)) {
					cm_log(1, "PIN storage location is not "
					       "an absolute path.\n");
					return send_internal_base_bad_arg_error(conn, msg,
										_("The location \"%s\" must be an absolute path."),
										param->value.s,
										"KEY_PIN_FILE");
				}
				talloc_free(entry->cm_key_pin_file);
				entry->cm_key_pin_file = maybe_strdup(entry,
								      param->value.s);
				if (entry->cm_key_pin_file != NULL) {
					entry->cm_key_pin = NULL;
				}
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_KEY_PIN_FILE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    ((strcasecmp(param->key, "EKU") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_EKU) == 0))) {
				talloc_free(entry->cm_template_eku);
				entry->cm_template_eku = cm_submit_maybe_joinv(entry,
									       ",",
									       param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_EKU;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    ((strcasecmp(param->key, "PRINCIPAL") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_PRINCIPAL) == 0))) {
				talloc_free(entry->cm_template_principal);
				entry->cm_template_principal = maybe_strdupv(entry,
									     param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_PRINCIPAL;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    ((strcasecmp(param->key, "DNS") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_HOSTNAME) == 0))) {
				talloc_free(entry->cm_template_hostname);
				entry->cm_template_hostname = maybe_strdupv(entry,
									    param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_HOSTNAME;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    ((strcasecmp(param->key, "EMAIL") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_EMAIL) == 0))) {
				talloc_free(entry->cm_template_email);
				entry->cm_template_email = maybe_strdupv(entry,
									 param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_EMAIL;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_CERT_PRESAVE_COMMAND) == 0)) {
				talloc_free(entry->cm_pre_certsave_command);
				entry->cm_pre_certsave_command = maybe_strdup(entry,
									      param->value.s);
				talloc_free(entry->cm_pre_certsave_uid);
				if (entry->cm_pre_certsave_command != NULL) {
					entry->cm_pre_certsave_uid = talloc_asprintf(entry, "%lu",
										     (unsigned long) ci->uid);
					if (entry->cm_pre_certsave_uid == NULL) {
						talloc_free(entry->cm_pre_certsave_command);
						entry->cm_pre_certsave_command = NULL;
					}
				} else {
					entry->cm_pre_certsave_uid = NULL;
				}
				if (n_propname + 3 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
					propname[n_propname++] = CM_DBUS_PROP_CERT_PRESAVE_UID;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_CERT_POSTSAVE_COMMAND) == 0)) {
				talloc_free(entry->cm_post_certsave_command);
				entry->cm_post_certsave_command = maybe_strdup(entry,
									       param->value.s);
				talloc_free(entry->cm_post_certsave_uid);
				if (entry->cm_post_certsave_command != NULL) {
					entry->cm_post_certsave_uid = talloc_asprintf(entry, "%lu",
										      (unsigned long) ci->uid);
					if (entry->cm_post_certsave_uid == NULL) {
						talloc_free(entry->cm_post_certsave_command);
						entry->cm_post_certsave_command = NULL;
					}
				} else {
					entry->cm_post_certsave_uid = NULL;
				}
				if (n_propname + 3 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
					propname[n_propname++] = CM_DBUS_PROP_CERT_POSTSAVE_UID;
				}
			} else {
				break;
			}
		}
		if (d[i] == NULL) {
			new_request_path = talloc_asprintf(parent, "%s/%s",
							   CM_DBUS_REQUEST_PATH,
							   entry->cm_busname);
			if ((n_propname > 0) &&
			    (n_propname + 1 < sizeof(propname) / sizeof(propname[0]))) {
				propname[n_propname] = NULL;
				cm_tdbush_property_emit_changed(ctx, new_request_path,
								CM_DBUS_REQUEST_INTERFACE,
								propname);
			}
			cm_tdbusm_set_bp(rep,
					 cm_restart_one(ctx,
							entry->cm_nickname),
					 new_request_path);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			talloc_free(new_request_path);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			dbus_message_unref(rep);
			rep = dbus_message_new_error(msg,
						     CM_DBUS_ERROR_REQUEST_BAD_ARG,
						     _("Unrecognized parameter or wrong value type."));
			if (rep != NULL) {
				cm_tdbusm_set_s(rep, d[i]->key);
				dbus_connection_send(conn, rep, NULL);
				dbus_message_unref(rep);
				return DBUS_HANDLER_RESULT_HANDLED;
			}
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
	} else {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
}

/* org.fedorahosted.certmonger.request.resubmit */
static DBusHandlerResult
request_resubmit(DBusConnection *conn, DBusMessage *msg,
		 struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *propname[2];
	char *path;

	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (cm_stop_one(ctx, entry->cm_nickname)) {
			/* if we have a key, the thing to do now is to generate
			 * a new CSR, otherwise we have to generate a key first
			 * */
			if (entry->cm_key_type.cm_key_size == 0) {
				entry->cm_state = CM_NEED_KEY_PAIR;
			} else {
				entry->cm_state = CM_NEED_CSR;
			}
			/* emit a properties-changed signal for the state */
			propname[0] = CM_DBUS_PROP_STATUS;
			propname[1] = NULL;
			path = talloc_asprintf(entry, "%s/%s",
					       CM_DBUS_REQUEST_PATH,
					       entry->cm_busname);
			cm_tdbush_property_emit_changed(ctx, path,
							CM_DBUS_REQUEST_INTERFACE,
							propname);
			talloc_free(path);
			if (cm_start_one(ctx, entry->cm_nickname)) {
				cm_tdbusm_set_b(rep, TRUE);
			} else {
				cm_tdbusm_set_b(rep, FALSE);
			}
		} else {
			cm_tdbusm_set_b(rep, FALSE);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* Custom property get/set logic for request structures. */
static dbus_bool_t
request_prop_get_autorenew(struct cm_context *ctx, void *parent,
			   void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_autorenew ? TRUE : FALSE;
}

static dbus_bool_t
request_prop_get_monitoring(struct cm_context *ctx, void *parent,
			    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_monitor ? TRUE : FALSE;
}

static const char *
request_prop_get_cert_location_type(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		return "FILE";
		break;
	case cm_cert_storage_nssdb:
		return "NSSDB";
		break;
	}
	return "";
}

static const char *
request_prop_get_cert_location_file(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_nssdb:
		break;
	case cm_cert_storage_file:
		return entry->cm_cert_storage_location;
		break;
	}
	return "";
}

static const char *
request_prop_get_cert_location_database(struct cm_context *ctx, void *parent,
					void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		break;
	case cm_cert_storage_nssdb:
		return entry->cm_cert_storage_location;
		break;
	}
	return "";
}

static const char *
request_prop_get_cert_location_nickname(struct cm_context *ctx, void *parent,
					void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		break;
	case cm_cert_storage_nssdb:
		return entry->cm_cert_nickname;
		break;
	}
	return "";
}

static const char *
request_prop_get_cert_location_token(struct cm_context *ctx, void *parent,
				     void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		break;
	case cm_cert_storage_nssdb:
		return entry->cm_cert_token;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_type(struct cm_context *ctx, void *parent,
				   void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		return "NONE";
		break;
	case cm_key_storage_file:
		return "FILE";
		break;
	case cm_key_storage_nssdb:
		return "NSSDB";
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_file(struct cm_context *ctx, void *parent,
				   void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
	case cm_key_storage_nssdb:
		break;
	case cm_key_storage_file:
		return entry->cm_key_storage_location;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_database(struct cm_context *ctx, void *parent,
				       void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
	case cm_key_storage_file:
		break;
	case cm_key_storage_nssdb:
		return entry->cm_key_storage_location;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_nickname(struct cm_context *ctx, void *parent,
				       void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
	case cm_key_storage_file:
		break;
	case cm_key_storage_nssdb:
		return entry->cm_key_nickname;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_token(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
	case cm_key_storage_file:
		break;
	case cm_key_storage_nssdb:
		return entry->cm_key_token;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_type(struct cm_context *ctx, void *parent,
			  void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_unspecified:
		return "";
		break;
	case cm_key_rsa:
		return "RSA";
		break;
	}
	return "";
}

static long
request_prop_get_key_size(struct cm_context *ctx, void *parent,
			  void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_unspecified:
		return 0;
		break;
	case cm_key_rsa:
		return entry->cm_key_type.cm_key_size;
		break;
	}
	return 0;
}

static const char *
request_prop_get_notification_type(struct cm_context *ctx, void *parent,
				   void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_notification_method) {
	case cm_notification_unspecified:
	case cm_notification_none:
		return "";
		break;
	case cm_notification_syslog:
		return "SYSLOG";
		break;
	case cm_notification_email:
		return "EMAIL";
		break;
	case cm_notification_stdout:
		return "STDOUT";
		break;
	case cm_notification_command:
		return "COMMAND";
		break;
	}
	return "";
}

static const char *
request_prop_get_notification_syslog(struct cm_context *ctx, void *parent,
				     void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_notification_method) {
	case cm_notification_unspecified:
	case cm_notification_none:
	case cm_notification_email:
	case cm_notification_stdout:
	case cm_notification_command:
		return "";
		break;
	case cm_notification_syslog:
		return entry->cm_notification_destination;
		break;
	}
	return "";
}

static const char *
request_prop_get_notification_email(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_notification_method) {
	case cm_notification_unspecified:
	case cm_notification_none:
	case cm_notification_syslog:
	case cm_notification_stdout:
	case cm_notification_command:
		return "";
		break;
	case cm_notification_email:
		return entry->cm_notification_destination;
		break;
	}
	return "";
}

static const char *
request_prop_get_notification_command(struct cm_context *ctx, void *parent,
				      void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_notification_method) {
	case cm_notification_unspecified:
	case cm_notification_none:
	case cm_notification_email:
	case cm_notification_stdout:
	case cm_notification_syslog:
		return "";
		break;
	case cm_notification_command:
		return entry->cm_notification_destination;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_pin(struct cm_context *ctx, void *parent,
			 void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_key_pin ? entry->cm_key_pin : "";
}

static void
request_prop_set_key_pin(struct cm_context *ctx, void *parent,
			 void *record, const char *name, const char *value)
{
	struct cm_store_entry *entry = record;
	const char *properties[2];
	char *path;

	entry->cm_key_pin = maybe_strdup(entry, value);
	if (entry->cm_key_pin != NULL) {
		entry->cm_key_pin_file = NULL;
		properties[0] = CM_DBUS_PROP_KEY_PIN_FILE;
		properties[1] = NULL;
		path = talloc_asprintf(parent, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       entry->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_REQUEST_INTERFACE,
						properties);
	}
}

static const char *
request_prop_get_key_pin_file(struct cm_context *ctx, void *parent,
			      void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_key_pin_file ? entry->cm_key_pin_file : "";
}

static void
request_prop_set_key_pin_file(struct cm_context *ctx, void *parent,
			      void *record, const char *name, const char *value)
{
	struct cm_store_entry *entry = record;
	const char *properties[2];
	char *path;

	entry->cm_key_pin_file = maybe_strdup(entry, value);
	if (entry->cm_key_pin_file != NULL) {
		entry->cm_key_pin = NULL;
		properties[0] = CM_DBUS_PROP_KEY_PIN;
		properties[1] = NULL;
		path = talloc_asprintf(parent, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       entry->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_REQUEST_INTERFACE,
						properties);
	}
}

static const char *
request_prop_get_status(struct cm_context *ctx, void *parent,
			void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return cm_store_state_as_string(entry->cm_state);
}

static dbus_bool_t
request_prop_get_stuck(struct cm_context *ctx, void *parent,
		       void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	dbus_bool_t stuck = FALSE;
	switch (entry->cm_state) {
	case CM_INVALID:
	case CM_NEED_KEY_PAIR:
	case CM_GENERATING_KEY_PAIR:
	case CM_HAVE_KEY_PAIR:
	case CM_NEED_KEYINFO:
	case CM_READING_KEYINFO:
	case CM_HAVE_KEYINFO:
	case CM_NEED_CSR:
	case CM_GENERATING_CSR:
	case CM_HAVE_CSR:
	case CM_NEED_TO_SUBMIT:
	case CM_SUBMITTING:
	case CM_CA_WORKING:
	case CM_NEED_TO_SAVE_CERT:
	case CM_PRE_SAVE_CERT:
	case CM_START_SAVING_CERT:
	case CM_SAVING_CERT:
	case CM_NEED_TO_READ_CERT:
	case CM_READING_CERT:
	case CM_SAVED_CERT:
	case CM_POST_SAVED_CERT:
	case CM_MONITORING:
	case CM_NEED_TO_NOTIFY_VALIDITY:
	case CM_NOTIFYING_VALIDITY:
	case CM_NEED_TO_NOTIFY_REJECTION:
	case CM_NOTIFYING_REJECTION:
	case CM_NEED_TO_NOTIFY_ISSUED_FAILED:
	case CM_NOTIFYING_ISSUED_FAILED:
	case CM_NEED_TO_NOTIFY_ISSUED_SAVED:
	case CM_NOTIFYING_ISSUED_SAVED:
	case CM_NEWLY_ADDED:
	case CM_NEWLY_ADDED_START_READING_KEYINFO:
	case CM_NEWLY_ADDED_READING_KEYINFO:
	case CM_NEWLY_ADDED_START_READING_CERT:
	case CM_NEWLY_ADDED_READING_CERT:
	case CM_NEWLY_ADDED_DECIDING:
		stuck = FALSE;
		break;
	case CM_NEED_KEYINFO_READ_TOKEN:
	case CM_NEED_KEYINFO_READ_PIN:
	case CM_NEED_KEY_GEN_TOKEN:
	case CM_NEED_KEY_GEN_PIN:
	case CM_NEED_CSR_GEN_TOKEN:
	case CM_NEED_CSR_GEN_PIN:
	case CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN:
	case CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN:
	case CM_NEED_GUIDANCE:
	case CM_NEED_CA:
	case CM_CA_REJECTED:
	case CM_CA_UNREACHABLE:
	case CM_CA_UNCONFIGURED:
		stuck = TRUE;
		break;
	}
	return stuck;
}

static const char *
request_prop_get_ca(struct cm_context *ctx, void *parent,
		    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	struct cm_store_ca *ca;
	if (entry->cm_ca_nickname != NULL) {
		ca = cm_get_ca_by_nickname(ctx, entry->cm_ca_nickname);
		if (ca != NULL) {
			return talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_REQUEST_PATH,
					       ca->cm_busname);
		}
	}
	return "";
}

/* the types of objects we have in our D-Bus object tree */
enum cm_tdbush_object_type {
	cm_tdbush_object_type_none,
	cm_tdbush_object_type_parent_of_base,
	cm_tdbush_object_type_base,
	cm_tdbush_object_type_parent_of_cas,
	cm_tdbush_object_type_group_of_cas,
	cm_tdbush_object_type_ca,
	cm_tdbush_object_type_parent_of_requests,
	cm_tdbush_object_type_group_of_requests,
	cm_tdbush_object_type_request
};

/* an annotation attached to a method or data field */
struct cm_tdbush_member_annotation {
	const char *cm_name;
	const char *cm_value;
	struct cm_tdbush_member_annotation *cm_next;
};

/* a callable method on an object */
struct cm_tdbush_method {
	const char *cm_name;
	struct cm_tdbush_method_arg {
		const char *cm_name;
		const char *cm_bus_type;
		enum cm_tdbush_method_arg_direction {
			cm_tdbush_method_arg_in,
			cm_tdbush_method_arg_out,
		} cm_direction;
		struct cm_tdbush_method_arg *cm_next;
	} *cm_args;
	struct cm_tdbush_member_annotation *cm_annotations;
	DBusHandlerResult (*cm_fn)(DBusConnection *conn,
				   DBusMessage *msg,
				   struct cm_client_info *ci,
				   struct cm_context *ctx);
};

/* a signal emitted by an object */
struct cm_tdbush_signal {
	const char *cm_name;
	struct cm_tdbush_signal_arg {
		const char *cm_name;
		const char *cm_bus_type;
		struct cm_tdbush_signal_arg *cm_next;
	} *cm_args;
};

/* a data property of an object */
struct cm_tdbush_property {
	const char *cm_name;
	/* what it looks like on the bus */
	enum cm_tdbush_property_bus_type {
		cm_tdbush_property_path,
		cm_tdbush_property_string,
		cm_tdbush_property_strings,
		cm_tdbush_property_boolean,
		cm_tdbush_property_number
	} cm_bus_type;
	enum cm_tdbush_property_access {
		cm_tdbush_property_read,
		cm_tdbush_property_write,
		cm_tdbush_property_readwrite
	} cm_access;
	/* how we represent it internally */
	enum cm_tdbush_property_local_type {
		cm_tdbush_property_special,
		cm_tdbush_property_char_p,
		cm_tdbush_property_char_pp,
		cm_tdbush_property_time_t,
		cm_tdbush_property_comma_list,
	} cm_local_type;
	/* for char_p, char_pp, time_t, comma_list members */
	ptrdiff_t cm_offset;
	/* for "special" members */
	const char * (*cm_read_string)(struct cm_context *ctx, void *parent,
				       void *structure, const char *name);
	const char ** (*cm_read_strings)(struct cm_context *ctx, void *parent,
					 void *structure, const char *name);
	dbus_bool_t (*cm_read_boolean)(struct cm_context *ctx, void *parent,
				       void *structure, const char *name);
	long (*cm_read_number)(struct cm_context *ctx, void *parent,
			       void *structure, const char *name);
	void (*cm_write_string)(struct cm_context *ctx, void *parent,
				void *structure, const char *name,
				const char *new_value);
	void (*cm_write_strings)(struct cm_context *ctx, void *parent,
				 void *structure, const char *name,
				 const char **new_value);
	void (*cm_write_boolean)(struct cm_context *ctx, void *parent,
				 void *structure, const char *name,
				 dbus_bool_t new_value);
	void (*cm_write_number)(struct cm_context *ctx, void *parent,
				void *structure, const char *name,
				long new_value);
	struct cm_tdbush_member_annotation *cm_annotations;
};

/* methods, signals, and members are grouped by interface name */
struct cm_tdbush_interface {
	const char *cm_name;
	struct cm_tdbush_interface_item {
		enum cm_tdbush_interface_member_type {
			cm_tdbush_interface_method,
			cm_tdbush_interface_signal,
			cm_tdbush_interface_property,
		} cm_member_type;
		struct cm_tdbush_method *cm_method;
		struct cm_tdbush_signal *cm_signal;
		struct cm_tdbush_property *cm_property;
		struct cm_tdbush_interface_item *cm_next;
	} *cm_items;
};

/* a mapping from an object type to an interface that applies to it */
struct cm_tdbush_interface_map {
	enum cm_tdbush_object_type cm_type;
	struct cm_tdbush_interface * (*cm_interface)(void);
};
static enum cm_tdbush_object_type cm_tdbush_classify_path(struct cm_context *ctx,
							  const char *path);
static struct cm_tdbush_interface_map *cm_tdbush_object_type_map_get_n(unsigned int i);

static struct cm_tdbush_method_arg *
make_method_arg(const char *name,
		const char *bus_type,
		enum cm_tdbush_method_arg_direction direction,
		struct cm_tdbush_method_arg *next)
{
	struct cm_tdbush_method_arg *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_bus_type = bus_type;
	ret->cm_direction = direction;
	ret->cm_next = next;
	return ret;
}

static struct cm_tdbush_member_annotation *
make_member_annotation(const char *name,
		       const char *value,
		       struct cm_tdbush_member_annotation *next)
{
	struct cm_tdbush_member_annotation *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_value = value;
	ret->cm_next = next;
	return ret;
}

static struct cm_tdbush_method *
make_method(const char *name,
	    DBusHandlerResult (*fn)(DBusConnection *conn,
				    DBusMessage *msg,
				    struct cm_client_info *ci,
				    struct cm_context *ctx),
	    struct cm_tdbush_method_arg *args,
	    struct cm_tdbush_member_annotation *annotations)
{
	struct cm_tdbush_method *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_fn = fn;
	ret->cm_args = args;
	ret->cm_annotations = annotations;
	return ret;
}

static struct cm_tdbush_signal_arg *
make_signal_arg(const char *name,
		const char *bus_type,
		struct cm_tdbush_signal_arg *next)
{
	struct cm_tdbush_signal_arg *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_bus_type = bus_type;
	ret->cm_next = next;
	return ret;
}

static struct cm_tdbush_signal *
make_signal(const char *name, struct cm_tdbush_signal_arg *args)
{
	struct cm_tdbush_signal *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_args = args;
	return ret;
}

static struct cm_tdbush_property *
make_property(const char *name,
	      enum cm_tdbush_property_bus_type bus_type,
	      enum cm_tdbush_property_access acces,
	      enum cm_tdbush_property_local_type local_type,
	      ptrdiff_t offset,
	      const char * (*read_string)(struct cm_context *ctx, void *parent,
					  void *structure, const char *name),
	      const char ** (*read_strings)(struct cm_context *ctx,
					    void *parent,
					    void *structure,
					    const char *name),
	      dbus_bool_t (*read_boolean)(struct cm_context *ctx, void *parent,
					  void *structure, const char *name),
	      long (*read_number)(struct cm_context *ctx, void *parent,
				  void *structure, const char *name),
	      void (*write_string)(struct cm_context *ctx, void *parent,
				   void *structure, const char *name,
				   const char *new_value),
	      void (*write_strings)(struct cm_context *ctx, void *parent,
				    void *structure, const char *name,
				    const char **new_values),
	      void (*write_boolean)(struct cm_context *ctx, void *parent,
				    void *structure, const char *name,
				    dbus_bool_t),
	      void (*write_number)(struct cm_context *ctx, void *parent,
				   void *structure, const char *name,
				   long new_value),
	      struct cm_tdbush_member_annotation *annotations)
{
	struct cm_tdbush_property *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_bus_type = bus_type;
	ret->cm_access = acces;
	ret->cm_local_type = local_type;
	ret->cm_offset = offset;
	ret->cm_read_string = read_string;
	ret->cm_read_strings = read_strings;
	ret->cm_read_number = read_number;
	ret->cm_read_boolean = read_boolean;
	ret->cm_write_string = write_string;
	ret->cm_write_strings = write_strings;
	ret->cm_write_number = write_number;
	ret->cm_write_boolean = write_boolean;
	ret->cm_annotations = annotations;
	switch (ret->cm_local_type) {
	case cm_tdbush_property_char_p:
	case cm_tdbush_property_char_pp:
	case cm_tdbush_property_time_t:
	case cm_tdbush_property_comma_list:
		assert(ret->cm_offset != 0);
		break;
	case cm_tdbush_property_special:
		assert(ret->cm_offset == 0);
		if ((ret->cm_access == cm_tdbush_property_read) ||
		    (ret->cm_access == cm_tdbush_property_readwrite)) {
			switch (ret->cm_bus_type) {
			case cm_tdbush_property_path:
			case cm_tdbush_property_string:
				assert(ret->cm_read_string != NULL);
				break;
			case cm_tdbush_property_strings:
				assert(ret->cm_read_strings != NULL);
				break;
			case cm_tdbush_property_boolean:
				assert(ret->cm_read_boolean != NULL);
				break;
			case cm_tdbush_property_number:
				assert(ret->cm_read_number != NULL);
				break;
			}
		}
		if ((ret->cm_access == cm_tdbush_property_readwrite) ||
		    (ret->cm_access == cm_tdbush_property_write)) {
			switch (ret->cm_bus_type) {
			case cm_tdbush_property_path:
			case cm_tdbush_property_string:
				assert(ret->cm_write_string != NULL);
				break;
			case cm_tdbush_property_strings:
				assert(ret->cm_write_strings != NULL);
				break;
			case cm_tdbush_property_boolean:
				assert(ret->cm_write_boolean != NULL);
				break;
			case cm_tdbush_property_number:
				assert(ret->cm_write_number != NULL);
				break;
			}
		}
		break;
	}
	return ret;
}

static struct cm_tdbush_interface_item *
make_interface_item(enum cm_tdbush_interface_member_type member_type,
		    void *ptr,
		    struct cm_tdbush_interface_item *next)
{
	struct cm_tdbush_interface_item *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_member_type = member_type;
	switch (ret->cm_member_type) {
	case cm_tdbush_interface_method:
		ret->cm_method = ptr;
		break;
	case cm_tdbush_interface_signal:
		ret->cm_signal = ptr;
		break;
	case cm_tdbush_interface_property:
		ret->cm_property = ptr;
		break;
	}
	ret->cm_next = next;
	return ret;
}

static struct cm_tdbush_interface *
make_interface(const char *name,
	       struct cm_tdbush_interface_item *items)
{
	struct cm_tdbush_interface *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_items = items;
	return ret;
}

/* introspection callbacks for specific parts of an interface */
static char *
cm_tdbush_introspect_method(void *parent,
			    struct cm_tdbush_method *method)
{
	char *ret = NULL;
	const char *direction;
	struct cm_tdbush_method_arg *arg;
	struct cm_tdbush_member_annotation *annotation;

	ret = talloc_asprintf(parent, "  <method name=\"%s\">",
			      method->cm_name);
	arg = method->cm_args;
	while (arg != NULL) {
		direction = "unknown";
		switch (arg->cm_direction) {
		case cm_tdbush_method_arg_in:
			direction = "in";
			break;
		case cm_tdbush_method_arg_out:
			direction = "out";
			break;
		}
		ret = talloc_asprintf(parent,
				      "%s\n   <arg name=\"%s\" type=\"%s\" "
				      "direction=\"%s\"/>",
				      ret,
				      arg->cm_name, arg->cm_bus_type,
				      direction);
		arg = arg->cm_next;
	}
	annotation = method->cm_annotations;
	while (annotation != NULL) {
		ret = talloc_asprintf(parent,
				      "%s\n   <annotation name=\"%s\" "
				      "value=\"%s\"/>",
				      ret,
				      annotation->cm_name,
				      annotation->cm_value);
		annotation = annotation->cm_next;
	}
	ret = talloc_asprintf(parent, "%s\n  </method>", ret);
	return ret;
}

static char *
cm_tdbush_introspect_signal(void *parent,
			    struct cm_tdbush_signal *sig)
{
	char *ret = NULL;
	struct cm_tdbush_signal_arg *arg;

	ret = talloc_asprintf(parent, "  <signal name=\"%s\">",
			      sig->cm_name);
	arg = sig->cm_args;
	while (arg != NULL) {
		ret = talloc_asprintf(parent,
				      "%s\n   <arg name=\"%s\" type=\"%s\"/>",
				      ret, arg->cm_name, arg->cm_bus_type);
		arg = arg->cm_next;
	}
	ret = talloc_asprintf(parent, "%s\n  </signal>", ret);
	return ret;
}

static char *
cm_tdbush_introspect_property(void *parent,
			      struct cm_tdbush_property *prop)
{
	char *ret = NULL;
	const char *bus_type = "unknown", *access_type = "unknown";
	struct cm_tdbush_member_annotation *annotation;

	switch (prop->cm_bus_type) {
	case cm_tdbush_property_path:
		bus_type = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	case cm_tdbush_property_string:
		bus_type = DBUS_TYPE_STRING_AS_STRING;
		break;
	case cm_tdbush_property_strings:
		bus_type = DBUS_TYPE_ARRAY_AS_STRING
			   DBUS_TYPE_STRING_AS_STRING;
		break;
	case cm_tdbush_property_boolean:
		bus_type = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case cm_tdbush_property_number:
		bus_type = DBUS_TYPE_INT64_AS_STRING;
		break;
	}
	switch (prop->cm_access) {
	case cm_tdbush_property_read:
		access_type = "read";
		break;
	case cm_tdbush_property_write:
		access_type = "write";
		break;
	case cm_tdbush_property_readwrite:
		access_type = "readwrite";
		break;
	}
	annotation = prop->cm_annotations;
	if (annotation == NULL) {
		ret = talloc_asprintf(parent,
				      "  <property name=\"%s\" "
				      "type=\"%s\" access=\"%s\"/>",
				      prop->cm_name, bus_type, access_type);
	} else {
		ret = talloc_asprintf(parent,
				      "  <property name=\"%s\" "
				      "type=\"%s\" access=\"%s\">",
				      prop->cm_name, bus_type, access_type);
		while (annotation != NULL) {
			ret = talloc_asprintf(parent,
					      "%s\n   <annotation name=\"%s\" "
					      "value=\"%s\"/>",
					      ret,
					      annotation->cm_name,
					      annotation->cm_value);
			annotation = annotation->cm_next;
		}
		ret = talloc_asprintf(parent, "%s\n  </property>", ret);
	}
	return ret;
}

/* when we're introspecting a node, we need to return a list of its direct
 * children as part of that node's data */
static char *
cm_tdbush_introspect_childlist(struct cm_context *ctx, void *parent,
			       const char *path,
			       enum cm_tdbush_object_type type)
{
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *ret = NULL;
	const char *p;
	int i;

	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_request:
	case cm_tdbush_object_type_ca:
		/* these have no child nodes */
		break;
	case cm_tdbush_object_type_parent_of_base:
		/* the next intermediate node in the base object's path */
		p = CM_DBUS_BASE_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "\n <node name=\"%.*s\"/>", i, p);
		break;
	case cm_tdbush_object_type_base:
		/* the base itself is a parent of the groups of other objects,
		 * so include the next nodes in those paths */
		p = CM_DBUS_REQUEST_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "\n <node name=\"%.*s\"/>", i, p);
		p = CM_DBUS_CA_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "%s\n <node name=\"%.*s\"/>",
				      ret, i, p);
		break;
	case cm_tdbush_object_type_parent_of_cas:
		/* a child of the base node that is not the immediate parent of
		 * the CAs */
		p = CM_DBUS_CA_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "\n <node name=\"%.*s\"/>", i, p);
		break;
	case cm_tdbush_object_type_group_of_cas:
		/* a child of the base node that is the immediate parent of the
		 * CAs */
		i = cm_get_n_cas(ctx) - 1;
		while (i >= 0) {
			ca = cm_get_ca_by_index(ctx, i);
			if (ca != NULL) {
				ret = talloc_asprintf(parent,
						      "\n <node name=\"%s\"/>%s",
						      ca->cm_busname,
						      ret ? ret : "");
			}
			i--;
		}
		break;
	case cm_tdbush_object_type_parent_of_requests:
		/* a child of the base node that is not the immediate parent of
		 * the requests */
		p = CM_DBUS_REQUEST_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "\n <node name=\"%.*s\"/>", i, p);
		break;
	case cm_tdbush_object_type_group_of_requests:
		/* a child of the base node that is the immediate parent of the
		 * requests */
		i = cm_get_n_entries(ctx) - 1;
		while (i >= 0) {
			entry = cm_get_entry_by_index(ctx, i);
			if (entry != NULL) {
				ret = talloc_asprintf(parent,
						      "\n <node name=\"%s\"/>%s",
						      entry->cm_busname,
						      ret ? ret : "");
			}
			i--;
		}
		break;
	}
	return ret;
}

/* org.freedesktop.DBus.Introspectable.Introspect */
static DBusHandlerResult
cm_tdbush_introspect(DBusConnection *conn,
		     DBusMessage *msg,
		     struct cm_client_info *ci,
		     struct cm_context *ctx)
{
	const char *path;
	void *parent;
	char *xml, *member;
	static struct cm_tdbush_interface_map *map;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	enum cm_tdbush_object_type type;
	unsigned int i;
	DBusMessage *rep;

	path = dbus_message_get_path(msg);
	type = cm_tdbush_classify_path(ctx, path);
	parent = talloc_new(NULL);
	xml = talloc_asprintf(parent, "%s\n<node name=\"%s\">",
			      DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE,
			      path);
	for (i = 0; (map = cm_tdbush_object_type_map_get_n(i)) != NULL; i++) {
		if (map->cm_type != type) {
			continue;
		}
		iface = (*(map->cm_interface))();
		xml = talloc_asprintf(parent, "%s\n <interface name=\"%s\">",
				      xml, iface->cm_name);
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			member = NULL;
			switch (item->cm_member_type) {
			case cm_tdbush_interface_method:
				member = cm_tdbush_introspect_method(parent,
								     item->cm_method);
				if (member != NULL) {
					xml = talloc_asprintf(parent, "%s\n%s",
							      xml, member);
				}
				break;
			case cm_tdbush_interface_signal:
				member = cm_tdbush_introspect_signal(parent,
								     item->cm_signal);
				if (member != NULL) {
					xml = talloc_asprintf(parent, "%s\n%s",
							      xml, member);
				}
				break;
			case cm_tdbush_interface_property:
				member = cm_tdbush_introspect_property(parent,
								       item->cm_property);
				if (member != NULL) {
					xml = talloc_asprintf(parent, "%s\n%s",
							      xml, member);
				}
				break;
			}
		}
		xml = talloc_asprintf(parent, "%s\n </interface>", xml);
	}
	member = cm_tdbush_introspect_childlist(ctx, parent, path, type);
	if (member != NULL) {
		xml = talloc_asprintf(parent, "%s%s", xml, member);
	}
	xml = talloc_asprintf(parent, "%s\n</node>", xml);
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, xml);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	talloc_free(parent);
	return DBUS_HANDLER_RESULT_HANDLED;

}

/* org.freedesktop.DBus.Properties.Get */
static DBusHandlerResult
cm_tdbush_property_get(DBusConnection *conn,
		       DBusMessage *msg,
		       struct cm_client_info *ci,
		       struct cm_context *ctx)
{
	const char *path;
	char *interface, *property;
	void *parent;
	static struct cm_tdbush_interface_map *map;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	struct cm_tdbush_property *prop;
	enum cm_tdbush_object_type type;
	unsigned int i;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *record, **wpp;
	const char *p, **pp, ***ppp;
	time_t *tp;
	dbus_bool_t b;
	long l;
	DBusMessage *rep;

	path = dbus_message_get_path(msg);
	type = cm_tdbush_classify_path(ctx, path);

	/* Get a pointer to the record. */
	record = NULL;
	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_parent_of_base:
	case cm_tdbush_object_type_parent_of_requests:
	case cm_tdbush_object_type_parent_of_cas:
	case cm_tdbush_object_type_group_of_requests:
	case cm_tdbush_object_type_group_of_cas:
		cm_log(1, "No properties on (%s).\n", path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		break;
	case cm_tdbush_object_type_base:
		/* no object */
		record = NULL;
		break;
	case cm_tdbush_object_type_ca:
		ca = get_ca_for_path(ctx, path);
		if (ca == NULL) {
			cm_log(1, "No such CA (%s).\n", path);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) ca;
		break;
	case cm_tdbush_object_type_request:
		entry = get_entry_for_path(ctx, path);
		if (entry == NULL) {
			cm_log(1, "No such request (%s).\n", path);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) entry;
		break;
	}
	if ((record == NULL) && (type != cm_tdbush_object_type_base)) {
		cm_log(1, "No properties on (%s).\n", path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_ss(msg, parent, &interface, &property) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Locate the property. */
	item = NULL;
	for (i = 0; (map = cm_tdbush_object_type_map_get_n(i)) != NULL; i++) {
		if (map->cm_type != type) {
			continue;
		}
		iface = (*(map->cm_interface))();
		if ((interface != NULL) &&
		    (strlen(interface) > 0) &&
		    (strcmp(interface, iface->cm_name) != 0)) {
			continue;
		}
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			if (item->cm_member_type !=
			    cm_tdbush_interface_property) {
				continue;
			}
			prop = item->cm_property;
			if ((property != NULL) &&
			    (strcmp(property, prop->cm_name) != 0)) {
				continue;
			}
			switch (prop->cm_access) {
			case cm_tdbush_property_read:
			case cm_tdbush_property_readwrite:
				break;
			case cm_tdbush_property_write:
				/* not allowed! should we return an error? */
				continue;
				break;
			}
			break;
		}
		if (item != NULL) {
			break;
		}
	}
	if (item == NULL) {
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	prop = item->cm_property;

	rep = dbus_message_new_method_return(msg);
	if (rep == NULL) {
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Read the property data and set it as an argument. */
	switch (prop->cm_local_type) {
	case cm_tdbush_property_char_p:
		record += prop->cm_offset;
		pp = (const char **) record;
		if (*pp != NULL) {
			p = *pp;
			if ((p == NULL) || (strlen(p) == 0)) {
				if (prop->cm_bus_type == cm_tdbush_property_path) {
					p = NULL;
				}
				if (prop->cm_bus_type == cm_tdbush_property_string) {
					p = "";
				}
			}
			if (p != NULL) {
				if (prop->cm_bus_type == cm_tdbush_property_path) {
					cm_tdbusm_set_p(rep, p);
				}
				if (prop->cm_bus_type == cm_tdbush_property_string) {
					cm_tdbusm_set_s(rep, p);
				}
			}
		}
		break;
	case cm_tdbush_property_char_pp:
		record += prop->cm_offset;
		ppp = (const char ***) record;
		cm_tdbusm_set_as(rep, *ppp);
		break;
	case cm_tdbush_property_time_t:
		record += prop->cm_offset;
		tp = (time_t *) record;
		cm_tdbusm_set_n(rep, (long) *tp);
		break;
	case cm_tdbush_property_comma_list:
		record += prop->cm_offset;
		pp = (const char **) record;
		wpp = eku_splitv(record - prop->cm_offset, *pp);
		pp = (const char **) wpp;
		if (wpp != NULL) {
			cm_tdbusm_set_as(rep, pp);
		}
		break;
	case cm_tdbush_property_special:
		switch (prop->cm_bus_type) {
		case cm_tdbush_property_path:
			p = (*(prop->cm_read_string))(ctx, parent,
						      record, property);
			/* libdbus won't allow us to set NULL or empty paths */
			if ((p != NULL) && (strlen(p) > 0)) {
				cm_tdbusm_set_p(rep, p);
			}
			break;
		case cm_tdbush_property_string:
			p = (*(prop->cm_read_string))(ctx, parent,
						      record, property);
			/* libdbus won't allow us to set NULL strings */
			if (p == NULL) {
				p = "";
			}
			cm_tdbusm_set_s(rep, p);
			break;
		case cm_tdbush_property_strings:
			pp = (*(prop->cm_read_strings))(ctx, parent,
							record, property);
			cm_tdbusm_set_as(rep, pp);
			break;
		case cm_tdbush_property_boolean:
			b = (*(prop->cm_read_boolean))(ctx, parent,
						       record, property);
			cm_tdbusm_set_b(rep, b);
			break;
		case cm_tdbush_property_number:
			l = (*(prop->cm_read_number))(ctx, parent,
						      record, property);
			cm_tdbusm_set_n(rep, l);
			break;
		}
		break;
	}
	if (rep != NULL) {
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	talloc_free(parent);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/* org.freedesktop.DBus.Properties.Set */
static DBusHandlerResult
cm_tdbush_property_set(DBusConnection *conn,
		       DBusMessage *msg,
		       struct cm_client_info *ci,
		       struct cm_context *ctx)
{
	const char *path;
	char *interface, *property;
	void *parent;
	static struct cm_tdbush_interface_map *map;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	struct cm_tdbush_property *prop;
	enum cm_tdbush_object_type type;
	unsigned int i;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *record, *wp, **wpp, ***wppp;
	time_t *tp;
	dbus_bool_t b;
	long l;
	DBusMessage *rep;
	const char *properties[2];

	path = dbus_message_get_path(msg);
	type = cm_tdbush_classify_path(ctx, path);

	/* Get a pointer to the record. */
	record = NULL;
	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_parent_of_base:
	case cm_tdbush_object_type_parent_of_requests:
	case cm_tdbush_object_type_parent_of_cas:
	case cm_tdbush_object_type_group_of_requests:
	case cm_tdbush_object_type_group_of_cas:
		cm_log(1, "No properties on (%s).\n", path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		break;
	case cm_tdbush_object_type_base:
		/* no object */
		record = NULL;
		break;
	case cm_tdbush_object_type_ca:
		ca = get_ca_for_path(ctx, path);
		if (ca == NULL) {
			cm_log(1, "No such CA (%s).\n", path);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) ca;
		break;
	case cm_tdbush_object_type_request:
		entry = get_entry_for_path(ctx, path);
		if (entry == NULL) {
			cm_log(1, "No such request (%s).\n", path);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) entry;
		break;
	}
	if ((record == NULL) && (type != cm_tdbush_object_type_base)) {
		cm_log(1, "No properties on (%s).\n", path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_ss(msg, parent, &interface, &property) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Locate the property. */
	item = NULL;
	for (i = 0; (map = cm_tdbush_object_type_map_get_n(i)) != NULL; i++) {
		if (map->cm_type != type) {
			continue;
		}
		iface = (*(map->cm_interface))();
		if ((interface != NULL) &&
		    (strlen(interface) > 0) &&
		    (strcmp(interface, iface->cm_name) != 0)) {
			continue;
		}
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			if (item->cm_member_type !=
			    cm_tdbush_interface_property) {
				continue;
			}
			prop = item->cm_property;
			if ((property != NULL) &&
			    (strcmp(property, prop->cm_name) != 0)) {
				continue;
			}
			switch (prop->cm_access) {
			case cm_tdbush_property_read:
				/* not allowed! should we return an error? */
				continue;
				break;
			case cm_tdbush_property_readwrite:
			case cm_tdbush_property_write:
				break;
			}
			break;
		}
		if (item != NULL) {
			break;
		}
	}
	if (item == NULL) {
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	prop = item->cm_property;

	rep = dbus_message_new_method_return(msg);
	if (rep == NULL) {
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Read the argument and set the data. */
	switch (prop->cm_local_type) {
	case cm_tdbush_property_char_p:
		if (cm_tdbusm_get_sss(msg, parent, &interface, &property,
				      &wp) != 0) {
			cm_log(1, "Error parsing arguments.\n");
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record += prop->cm_offset;
		wpp = (char **) record;
		*wpp = maybe_strdup(record, wp);
		break;
	case cm_tdbush_property_char_pp:
		if (cm_tdbusm_get_ssas(msg, parent, &interface, &property,
				       &wpp) != 0) {
			cm_log(1, "Error parsing arguments.\n");
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record += prop->cm_offset;
		wppp = (char ***) record;
		*wppp = maybe_strdupv(record, wpp);
		break;
	case cm_tdbush_property_time_t:
		if (cm_tdbusm_get_ssn(msg, parent, &interface, &property,
				      &l) != 0) {
			cm_log(1, "Error parsing arguments.\n");
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record += prop->cm_offset;
		tp = (time_t *) record;
		*tp = l;
		break;
	case cm_tdbush_property_comma_list:
		if (cm_tdbusm_get_ssas(msg, parent, &interface, &property,
				       &wpp) != 0) {
			cm_log(1, "Error parsing arguments.\n");
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		wp = cm_submit_maybe_joinv(record, ",", wpp);
		record += prop->cm_offset;
		wpp = (char **) record;
		*wpp = maybe_strdup(record - prop->cm_offset, wp);
		break;
	case cm_tdbush_property_special:
		switch (prop->cm_bus_type) {
		case cm_tdbush_property_path:
		case cm_tdbush_property_string:
			if (cm_tdbusm_get_sss(msg, parent, &interface,
					      &property, &wp) != 0) {
				cm_log(1, "Error parsing arguments.\n");
				dbus_message_unref(rep);
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_string))(ctx, parent,
						   record, property, wp);
			break;
		case cm_tdbush_property_strings:
			if (cm_tdbusm_get_ssas(msg, parent, &interface,
					       &property, &wpp) != 0) {
				cm_log(1, "Error parsing arguments.\n");
				dbus_message_unref(rep);
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_strings))(ctx, parent,
						    record, property,
						    (const char **) wpp);
			break;
		case cm_tdbush_property_boolean:
			if (cm_tdbusm_get_ssb(msg, parent, &interface,
					      &property, &b) != 0) {
				cm_log(1, "Error parsing arguments.\n");
				dbus_message_unref(rep);
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_boolean))(ctx, parent,
						    record, property, b);
			break;
		case cm_tdbush_property_number:
			if (cm_tdbusm_get_ssn(msg, parent, &interface,
					      &property, &l) != 0) {
				cm_log(1, "Error parsing arguments.\n");
				dbus_message_unref(rep);
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_number))(ctx, parent,
						   record, property, l);
			break;
		}
		break;
	}
	if (rep != NULL) {
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	talloc_free(parent);

	properties[0] = prop->cm_name;
	properties[1] = NULL;
	cm_tdbush_property_emit_changed(ctx, path, interface, properties);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/* compare arrays of strings for having the same set of unique members */
static int
compare_strv(const char **a, const char **b)
{
	int m, n, i, j;
	if ((a == NULL) && (b == NULL)) {
		return 0;
	}
	for (m = 0; (a != NULL) && (a[m] != NULL); m++) {
		continue;
	}
	for (n = 0; (b != NULL) && (b[n] != NULL); n++) {
		continue;
	}
	if (m != n) {
		return -1;
	}
	for (i = 0; i < m; i++) {
		for (j = 0; j < n; j++) {
			if (strcmp(a[i], b[j]) == 0) {
				break;
			}
		}
		if (b[j] == NULL) {
			return -1;
		}
	}
	return 0;
}

/* do the heavy lifting for two cases:
 * org.freedesktop.DBus.Properties.GetAll method (old_record is NULL)
 * org.freedesktop.DBus.Properties.PropertiesChanged signal (old_record is not NULL) */
static DBusHandlerResult
cm_tdbush_property_get_all_or_changed(struct cm_context *ctx,
				      DBusConnection *conn,
				      DBusMessage *req,
				      const char *path,
				      const char *interface,
				      char *old_record,
				      const char **properties)
{
	void *parent;
	static struct cm_tdbush_interface_map *map;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	struct cm_tdbush_property *prop;
	enum cm_tdbush_object_type type;
	unsigned int i, j;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *record, *rec, *old_rec, **wpp, *ifacetmp;
	const char *p, **pp, ***ppp, **old_pp, *old_p, ***old_ppp;
	time_t *tp, *old_tp;
	dbus_bool_t b, old_b;
	long l, old_l;
	DBusMessage *rep;
	const struct cm_tdbusm_dict **d;
	struct cm_tdbusm_dict *dict, **dtmp;
	int n, m, n_dictvals = 0;

	/* If this is the method call, pull the path and interface from it.
	 * Either way, we need to be sure we have them. */
	parent = talloc_new(NULL);
	if (req != NULL) {
		path = dbus_message_get_path(req);
		if (cm_tdbusm_get_s(req, parent, &ifacetmp) != 0) {
			cm_log(1, "Error parsing arguments.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		interface = ifacetmp;
	}
	if (path == NULL) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	if (interface == NULL) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	type = cm_tdbush_classify_path(ctx, path);

	/* Get a pointer to the record. */
	record = NULL;
	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_parent_of_base:
	case cm_tdbush_object_type_parent_of_requests:
	case cm_tdbush_object_type_parent_of_cas:
	case cm_tdbush_object_type_group_of_requests:
	case cm_tdbush_object_type_group_of_cas:
		cm_log(1, "No properties on (%s).\n", path);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		break;
	case cm_tdbush_object_type_base:
		/* no object */
		record = NULL;
		break;
	case cm_tdbush_object_type_ca:
		ca = get_ca_for_path(ctx, path);
		if (ca == NULL) {
			cm_log(1, "No such CA (%s).\n", path);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) ca;
		break;
	case cm_tdbush_object_type_request:
		entry = get_entry_for_path(ctx, path);
		if (entry == NULL) {
			cm_log(1, "No such request (%s).\n", path);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) entry;
		break;
	}
	if ((record == NULL) && (type != cm_tdbush_object_type_base)) {
		cm_log(1, "No properties on (%s).\n", path);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Create the message we're sending. */
	if (req != NULL) {
		/* GetAll method reply. */
		rep = dbus_message_new_method_return(req);
		if (rep == NULL) {
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
	} else {
		/* PropertiesChanged signal. */
		rep = dbus_message_new_signal(path,
					      DBUS_INTERFACE_PROPERTIES,
					      "PropertiesChanged");
		if (rep == NULL) {
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
	}

	/* Examine all properties. */
	item = NULL;
	n_dictvals = 0;
	dict = NULL;
	d = NULL;
	for (i = 0, n = 0;
	     (map = cm_tdbush_object_type_map_get_n(i)) != NULL;
	     i++) {
		if (map->cm_type != type) {
			continue;
		}
		iface = (*(map->cm_interface))();
		if ((interface != NULL) &&
		    (strlen(interface) > 0) &&
		    (strcmp(interface, iface->cm_name) != 0)) {
			continue;
		}
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			if (item->cm_member_type !=
			    cm_tdbush_interface_property) {
				continue;
			}
			prop = item->cm_property;
			switch (prop->cm_access) {
			case cm_tdbush_property_read:
			case cm_tdbush_property_readwrite:
				break;
			case cm_tdbush_property_write:
				/* nope! */
				continue;
				break;
			}
			if (properties != NULL) {
				/* skip this property if we have a list of
				 * properties to list and this one's not
				 * included */
				for (j = 0; properties[j] != NULL; j++) {
					if (strcmp(properties[j],
						   prop->cm_name) == 0) {
						break;
					}
				}
				if (properties[j] == NULL) {
					continue;
				}
			}
			/* Resize the result dictionary if we need to. */
			if (n + 1 >= n_dictvals) {
				dict = talloc_realloc(parent, dict, struct cm_tdbusm_dict, n_dictvals + 32);
				if (dict == NULL) {
					cm_log(1, "Out of memory.\n");
					talloc_free(parent);
					return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
				}
				dtmp = talloc_realloc(parent, d, struct cm_tdbusm_dict *, n_dictvals + 33);
				d = (const struct cm_tdbusm_dict **) dtmp;
				if (d == NULL) {
					cm_log(1, "Out of memory.\n");
					talloc_free(parent);
					return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
				}
				for (m = 0; m < n; m++) {
					d[m] = &dict[m];
				}
				d[n] = NULL;
				n_dictvals += 32;
			}
			/* Read the property data and add it to the dict. */
			dict[n].key = talloc_strdup(parent, prop->cm_name);
			switch (prop->cm_bus_type) {
			case cm_tdbush_property_path:
				dict[n].value_type = cm_tdbusm_dict_p;
				break;
			case cm_tdbush_property_string:
				dict[n].value_type = cm_tdbusm_dict_s;
				break;
			case cm_tdbush_property_strings:
				dict[n].value_type = cm_tdbusm_dict_as;
				break;
			case cm_tdbush_property_boolean:
				dict[n].value_type = cm_tdbusm_dict_b;
				break;
			case cm_tdbush_property_number:
				dict[n].value_type = cm_tdbusm_dict_n;
				break;
			}
			switch (prop->cm_local_type) {
			case cm_tdbush_property_char_p:
				rec = record + prop->cm_offset;
				pp = (const char **) rec;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_pp = (const char **) old_rec;
					if ((*pp == NULL) &&
					    (*old_pp == NULL)) {
						continue;
					}
					if ((*pp != NULL) &&
					    (*old_pp != NULL) &&
					    (strcmp(*pp, *old_pp) == 0)) {
						continue;
					}
				}
				if ((pp != NULL) && (*pp != NULL)) {
					dict[n].value.s = (char *) *pp;
					if ((dict[n].value.s == NULL) ||
					    (strlen(dict[n].value.s) == 0)) {
						if (prop->cm_bus_type == cm_tdbush_property_path) {
							continue;
						}
						if (prop->cm_bus_type == cm_tdbush_property_string) {
							dict[n].value.s = "";
						}
					}
					d[n] = &dict[n];
					n++;
				}
				break;
			case cm_tdbush_property_char_pp:
				rec = record + prop->cm_offset;
				ppp = (const char ***) rec;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_ppp = (const char ***) old_rec;
					if (compare_strv(*old_ppp, *ppp) == 0) {
						continue;
					}
				}
				if ((ppp != NULL) && (*ppp != NULL)) {
					dict[n].value.as = (char **) *ppp;
					d[n] = &dict[n];
					n++;
				}
				break;
			case cm_tdbush_property_comma_list:
				rec = record + prop->cm_offset;
				wpp = (char **) rec;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_pp = (const char **) old_rec;
					if ((*wpp == NULL) &&
					    (*old_pp == NULL)) {
						continue;
					}
					if ((*wpp != NULL) &&
					    (*old_pp != NULL) &&
					    (strcmp(*wpp, *old_pp) == 0)) {
						continue;
					}
				}
				wpp = eku_splitv(record, *wpp);
				if (wpp != NULL) {
					dict[n].value.as = wpp;
					d[n] = &dict[n];
					n++;
				}
				break;
			case cm_tdbush_property_time_t:
				rec = record + prop->cm_offset;
				tp = (time_t *) rec;
				dict[n].value.n = *tp;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_tp = (time_t *) old_rec;
					if (*tp == *old_tp) {
						continue;
					}
				}
				d[n] = &dict[n];
				n++;
				break;
			case cm_tdbush_property_special:
				switch (prop->cm_bus_type) {
				case cm_tdbush_property_path:
				case cm_tdbush_property_string:
					p = (*(prop->cm_read_string))(ctx, parent,
								      record,
								      prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_p = (*(prop->cm_read_string))(ctx, parent,
										  old_record,
										  prop->cm_name);
						if ((p == NULL) &&
						    (old_p == NULL)) {
							continue;
						}
						if ((p != NULL) &&
						    (old_p != NULL) &&
						    (strcmp(p, old_p) == 0)) {
							continue;
						}
					}
					if ((p == NULL) || (strlen(p) == 0)) {
						if (prop->cm_bus_type == cm_tdbush_property_path) {
							continue;
						}
						if (prop->cm_bus_type == cm_tdbush_property_string) {
							p = "";
						}
					}
					dict[n].value.s = (char *) p;
					d[n] = &dict[n];
					n++;
					break;
				case cm_tdbush_property_strings:
					pp = (*(prop->cm_read_strings))(ctx, parent,
									record,
									prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_pp = (*(prop->cm_read_strings))(ctx, parent,
										    old_record,
										    prop->cm_name);
						if (compare_strv(old_pp, pp) == 0) {
							continue;
						}
					}
					if ((pp != NULL) && (*pp != NULL)) {
						dict[n].value.as = (char **) pp;
						d[n] = &dict[n];
						n++;
					}
					break;
				case cm_tdbush_property_boolean:
					b = (*(prop->cm_read_boolean))(ctx, parent,
								       record,
								       prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_b = (*(prop->cm_read_boolean))(ctx, parent,
										   old_record,
										   prop->cm_name);
						if (b == old_b) {
							continue;
						}
					}
					dict[n].value.b = b;
					d[n] = &dict[n];
					n++;
					break;
				case cm_tdbush_property_number:
					l = (*(prop->cm_read_number))(ctx, parent,
								      record,
								      prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_l = (*(prop->cm_read_number))(ctx, parent,
										  old_record,
										  prop->cm_name);
						if (l == old_l) {
							continue;
						}
					}
					dict[n].value.n = l;
					d[n] = &dict[n];
					n++;
					break;
				}
				break;
			}
		}
	}
	if (d != NULL) {
		d[n] = NULL;
	}

	if (req != NULL) {
		cm_tdbusm_set_d(rep, d);
	} else {
		cm_tdbusm_set_sd(rep, interface, d);
	}

	if (rep != NULL) {
		if ((old_record == NULL) || ((d != NULL) && (d[0] != NULL))) {
			dbus_connection_send(conn, rep, NULL);
		}
		dbus_message_unref(rep);
	}
	talloc_free(parent);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/* org.freedesktop.DBus.Properties.GetAll */
static DBusHandlerResult
cm_tdbush_property_get_all(DBusConnection *conn,
			   DBusMessage *msg,
			   struct cm_client_info *ci,
			   struct cm_context *ctx)
{
	return cm_tdbush_property_get_all_or_changed(ctx, conn, msg,
						     NULL, NULL, NULL, NULL);
}

/* emit org.freedesktop.DBus.Properties.PropertiesChanged for a specific set of
 * properties */
DBusHandlerResult
cm_tdbush_property_emit_changed(struct cm_context *ctx,
				const char *path,
				const char *interface,
				const char **properties)
{
	if (cm_get_conn_ptr(ctx) == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else {
		return cm_tdbush_property_get_all_or_changed(ctx,
							     cm_get_conn_ptr(ctx),
							     NULL,
							     path,
							     interface,
							     NULL,
							     properties);
	}
}

/* emit org.freedesktop.DBus.Properties.PropertiesChanged for the properties
 * which differ between the old and new entries */
void
cm_tdbush_property_emit_entry_changes(struct cm_context *ctx,
				      struct cm_store_entry *old_entry,
				      struct cm_store_entry *new_entry)
{
	char *path;
	if (cm_get_conn_ptr(ctx) != NULL) {
		path = talloc_asprintf(old_entry, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       old_entry->cm_busname);
		if (path != NULL) {
			cm_tdbush_property_get_all_or_changed(ctx,
							      cm_get_conn_ptr(ctx),
							      NULL,
							      path,
							      CM_DBUS_REQUEST_INTERFACE,
							      (char *) old_entry,
							      NULL);
			talloc_free(path);
		}
	}
}

/* emit org.fedorahosted.certmonger.request.SavedCertificate, for clients whom
 * filtering on PropertiesChanged isn't enough */
void
cm_tdbush_property_emit_entry_saved_cert(struct cm_context *ctx,
					 struct cm_store_entry *entry)
{
	DBusMessage *msg;
	char *path;

	if (cm_get_conn_ptr(ctx) != NULL) {
		path = talloc_asprintf(entry, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       entry->cm_busname);
		if (path != NULL) {
			msg = dbus_message_new_signal(path,
						      CM_DBUS_REQUEST_INTERFACE,
						      CM_DBUS_SIGNAL_REQUEST_CERT_SAVED);
			if (msg != NULL) {
				dbus_connection_send(cm_get_conn_ptr(ctx),
						     msg, NULL);
				dbus_message_unref(msg);
			}
			talloc_free(path);
		}
	}
}

/* emit org.freedesktop.DBus.Properties.PropertiesChanged for the properties
 * which differ between the old and new CAs */
void
cm_tdbush_property_emit_ca_changes(struct cm_context *ctx,
				   struct cm_store_ca *old_ca,
				   struct cm_store_ca *new_ca)
{
	char *path;
	if (cm_get_conn_ptr(ctx) != NULL) {
		path = talloc_asprintf(old_ca, "%s/%s",
				       CM_DBUS_CA_PATH,
				       old_ca->cm_busname);
		if (path != NULL) {
			cm_tdbush_property_get_all_or_changed(ctx,
							      cm_get_conn_ptr(ctx),
							      NULL,
							      path,
							      CM_DBUS_CA_INTERFACE,
							      (char *) old_ca,
							      NULL);
			talloc_free(path);
		}
	}
}

/* interface for org.freedesktop.DBus.Introspectable */
static struct cm_tdbush_interface *
cm_tdbush_iface_introspection(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(DBUS_INTERFACE_INTROSPECTABLE,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("Introspect",
								     cm_tdbush_introspect,
								     make_method_arg("xml_data",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
							 NULL));
	}
	return ret;
}

/* interface for org.freedesktop.DBus.Properties */
static struct cm_tdbush_interface *
cm_tdbush_iface_properties(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(DBUS_INTERFACE_PROPERTIES,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("Get",
								     cm_tdbush_property_get,
								     make_method_arg("interface_name",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("property_name",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("value",
										     "v",
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("Set",
								     cm_tdbush_property_set,
								     make_method_arg("interface_name",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("property_name",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("value",
										     "v",
										     cm_tdbush_method_arg_in,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("GetAll",
								     cm_tdbush_property_get_all,
								     make_method_arg("interface_name",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("props",
										     "a{sv}",
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_signal,
							 make_signal("PropertiesChanged",
								     make_signal_arg("interface_name",
										     "s",
								     make_signal_arg("changed_properties",
										     "a{sv}",
								     make_signal_arg("invalidated_properties",
										     "as",
										     NULL)))),
							 NULL)))));
	}
	return ret;
}


/* interface for org.freedesktop.certmonger.request */
static struct cm_tdbush_interface *
cm_tdbush_iface_request(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(CM_DBUS_REQUEST_INTERFACE,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_nickname",
								     request_get_nickname,
								     make_method_arg("nickname",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NICKNAME,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_nickname),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_autorenew",
								     request_get_autorenew,
								     make_method_arg("enabled",
										     "b",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_AUTORENEW,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, request_prop_get_autorenew, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_cert_data",
								     request_get_cert_data,
								     make_method_arg("pem",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       make_member_annotation("org.freedesktop.DBus.Property.EmitsChangedSignal",
											      "true",
											      NULL)),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_cert_info",
								     request_get_cert_info,
								     make_method_arg("issuer",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("serial_hex",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("subject",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("not_after",
										     "x",
										     cm_tdbush_method_arg_out,
								     make_method_arg("email",
										     "as",
										     cm_tdbush_method_arg_out,
								     make_method_arg("dns",
										     "as",
										     cm_tdbush_method_arg_out,
								     make_method_arg("principal_names",
										     "as",
										     cm_tdbush_method_arg_out,
								     make_method_arg("key_usage",
										     "x",
										     cm_tdbush_method_arg_out,
								     make_method_arg("extended_key_usage",
										     "as",
										     cm_tdbush_method_arg_out,
										     NULL))))))))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_ISSUER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_issuer),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_SERIAL,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_serial),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_SUBJECT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_subject),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_EMAIL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_cert_email),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_EKU,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_comma_list,
								       offsetof(struct cm_store_entry, cm_cert_eku),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_HOSTNAME,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_cert_hostname),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_PRINCIPAL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_cert_principal),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_cert_last_checked",
								     request_get_cert_last_checked,
								     make_method_arg("date",
										     "x",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LAST_CHECKED,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_time_t,
								       offsetof(struct cm_store_entry, cm_last_need_notify_check),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_cert_storage_info",
								     request_get_cert_storage_info,
								     make_method_arg("type",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("location_or_nickname",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("nss_token",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_TYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_type, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_FILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_file, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_DATABASE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_database, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_NICKNAME,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_nickname, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_TOKEN,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_token, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_csr_data",
								     request_get_csr_data,
								     make_method_arg("pem",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CSR,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_csr),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_csr_info",
								     request_get_csr_info,
								     make_method_arg("subject",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("email",
										     "as",
										     cm_tdbush_method_arg_out,
								     make_method_arg("dns",
										     "as",
										     cm_tdbush_method_arg_out,
								     make_method_arg("principal_names",
										     "as",
										     cm_tdbush_method_arg_out,
								     make_method_arg("key_usage",
										     "x",
										     cm_tdbush_method_arg_out,
								     make_method_arg("extended_key_usage",
										     "as",
										     cm_tdbush_method_arg_out,
										     NULL)))))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_PIN,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_pin, NULL, NULL, NULL,
								       request_prop_set_key_pin, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_PIN_FILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_pin_file, NULL, NULL, NULL,
								       request_prop_set_key_pin_file, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_SUBJECT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_template_subject),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_EMAIL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_email),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_EKU,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_comma_list,
								       offsetof(struct cm_store_entry, cm_template_eku),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_HOSTNAME,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_hostname),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_PRINCIPAL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_principal),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_key_pin",
								     request_get_key_pin,
								     make_method_arg("pin",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_key_pin_file",
								     request_get_key_pin_file,
								     make_method_arg("pin_file",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_key_storage_info",
								     request_get_key_storage_info,
								     make_method_arg("type",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("location_or_nickname",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("nss_token",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_TYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_type, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_FILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_file, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_DATABASE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_database, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_NICKNAME,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_nickname, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_TOKEN,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_token, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_key_type_and_size",
								     request_get_key_type_and_size,
								     make_method_arg("type",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("size",
										     "x",
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_TYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_type, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_SIZE,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, request_prop_get_key_size,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_monitoring",
								     request_get_monitoring,
								     make_method_arg("enabled",
										     "b",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_MONITORING,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, request_prop_get_monitoring, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_notification_info",
								     request_get_notification_info,
								     make_method_arg("method",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("destination",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NOTIFICATION_TYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_notification_type, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NOTIFICATION_SYSLOG_PRIORITY,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_notification_syslog, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NOTIFICATION_EMAIL,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_notification_email, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NOTIFICATION_COMMAND,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_notification_command, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_status",
								     request_get_status,
								     make_method_arg("state",
										     "s",
										     cm_tdbush_method_arg_out,
								     make_method_arg("blocked",
										     "b",
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_STATUS,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_status, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_STUCK,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, request_prop_get_stuck, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_ca",
								     request_get_ca,
								     make_method_arg("name",
										     "o",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA,
								       cm_tdbush_property_path,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_ca, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_PROFILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_ca_profile),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_submitted_cookie",
								     request_get_submitted_cookie,
								     make_method_arg("cookie",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_COOKIE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_ca_cookie),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_ca_error",
								     request_get_ca_error,
								     make_method_arg("text",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_ERROR,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_ca_error),
								       NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_submitted_date",
								     request_get_submitted_date,
								     make_method_arg("date",
										     "x",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SUBMITTED_DATE,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_time_t,
								       offsetof(struct cm_store_entry, cm_submitted),
								       NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("modify",
								     request_modify,
								     make_method_arg("updates",
										     "a{sv}",
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     "b",
										     cm_tdbush_method_arg_out,
								     make_method_arg("path",
										     "o",
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("resubmit",
								     request_resubmit,
								     make_method_arg("working",
										     "b",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_PRESAVE_COMMAND,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_pre_certsave_command),
								       NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_PRESAVE_UID,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_pre_certsave_uid),
								       NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_POSTSAVE_COMMAND,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_post_certsave_command),
								       NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_POSTSAVE_UID,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_post_certsave_uid),
								       NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_signal,
							 make_signal(CM_DBUS_SIGNAL_REQUEST_CERT_SAVED,
								     NULL),
							 NULL))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))));
	}
	return ret;
}

/* interface for org.freedesktop.certmonger.ca */
static struct cm_tdbush_interface *
cm_tdbush_iface_ca(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(CM_DBUS_CA_INTERFACE,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_nickname",
								     ca_get_nickname,
								     make_method_arg("nickname",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NICKNAME,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_nickname),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_is_default",
								     ca_get_is_default,
								     make_method_arg("default",
										     "b",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_IS_DEFAULT,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, ca_prop_get_is_default, NULL,
								       NULL, NULL, ca_prop_set_is_default, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_type",
								     ca_get_type,
								     make_method_arg("type",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_serial",
								     ca_get_serial,
								     make_method_arg("serial_hex",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_location",
								     ca_get_location,
								     make_method_arg("path",
										     "s",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_issuer_names",
								     ca_get_issuer_names,
								     make_method_arg("names",
										     "as",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_ISSUER_NAMES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_known_issuer_names),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     NULL))))))))));
	}
	return ret;
}

/* interface for org.freedesktop.certmonger */
static struct cm_tdbush_interface *
cm_tdbush_iface_base(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(CM_DBUS_BASE_INTERFACE,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("add_known_ca",
								     base_add_known_ca,
								     make_method_arg("nickname",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("command",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("known_names",
										     "as",
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     "b",
										     cm_tdbush_method_arg_out,
								     make_method_arg("name",
										     "o",
										     cm_tdbush_method_arg_out,
										     NULL))))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("add_request",
								     base_add_request,
								     make_method_arg("template",
										     "a{sv}",
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     "b",
										     cm_tdbush_method_arg_out,
								     make_method_arg("name",
										     "o",
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("find_ca_by_nickname",
								     base_find_ca_by_nickname,
								     make_method_arg("nickname",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("ca",
										     "o",
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("find_request_by_nickname",
								     base_find_request_by_nickname,
								     make_method_arg("nickname",
										     "s",
										     cm_tdbush_method_arg_in,
								     make_method_arg("request",
										     "o",
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_known_cas",
								     base_get_known_cas,
								     make_method_arg("ca_list",
										     "ao",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_requests",
								     base_get_requests,
								     make_method_arg("requests",
										     "ao",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_supported_key_types",
								     base_get_supported_key_types,
								     make_method_arg("key_type_list",
										     "as",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_supported_key_storage",
								     base_get_supported_key_storage,
								     make_method_arg("key_storage_type_list",
										     "as",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_supported_cert_storage",
								     base_get_supported_cert_storage,
								     make_method_arg("cert_storage_type_list",
										     "as",
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("remove_known_ca",
								     base_remove_known_ca,
								     make_method_arg("ca",
										     "o",
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     "b",
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("remove_request",
								     base_remove_request,
								     make_method_arg("request",
										     "o",
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     "b",
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     NULL))))))))))));
	}
	return ret;
}

/* map object types to an get-interface functions */
struct cm_tdbush_interface_map
cm_tdbush_object_type_map[] = {
	{cm_tdbush_object_type_parent_of_base, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_base, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_base, &cm_tdbush_iface_properties},
	{cm_tdbush_object_type_base, &cm_tdbush_iface_base},
	{cm_tdbush_object_type_parent_of_cas, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_group_of_cas, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_ca, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_ca, &cm_tdbush_iface_properties},
	{cm_tdbush_object_type_ca, &cm_tdbush_iface_ca},
	{cm_tdbush_object_type_parent_of_requests, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_group_of_requests, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_request, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_request, &cm_tdbush_iface_properties},
	{cm_tdbush_object_type_request, &cm_tdbush_iface_request},
};

static struct cm_tdbush_interface_map *
cm_tdbush_object_type_map_get_n(unsigned int i)
{
	if (i < (sizeof(cm_tdbush_object_type_map) /
		 sizeof(cm_tdbush_object_type_map[0]))) {
		return cm_tdbush_object_type_map + i;
	} else {
		return NULL;
	}
}

static enum cm_tdbush_object_type
cm_tdbush_classify_path(struct cm_context *ctx, const char *path)
{
	int basepathlen = strlen(CM_DBUS_BASE_PATH);
	int capathlen = strlen(CM_DBUS_CA_PATH);
	int reqpathlen = strlen(CM_DBUS_REQUEST_PATH);
	int pathlen = strlen(path);

	/* Base is just a name, so check for it first. */
	if (strcmp(path, CM_DBUS_BASE_PATH) == 0) {
		return cm_tdbush_object_type_base;
	}
	/* The group of requests is just a name, so check for it. */
	if (strcmp(path, CM_DBUS_REQUEST_PATH) == 0) {
		return cm_tdbush_object_type_group_of_requests;
	}
	/* The group of CAs is just a name, so check for it. */
	if (strcmp(path, CM_DBUS_CA_PATH) == 0) {
		return cm_tdbush_object_type_group_of_cas;
	}
	/* Check for things above the base node. */
	if ((strcmp(path, "/") == 0) ||
	    ((pathlen < basepathlen) &&
	     (strncmp(path, CM_DBUS_BASE_PATH, pathlen) == 0) &&
	     (CM_DBUS_BASE_PATH[pathlen] == '/'))) {
		return cm_tdbush_object_type_parent_of_base;
	}
	/* Check for things above the request group node. */
	if (((pathlen < reqpathlen) &&
	     (strncmp(path, CM_DBUS_REQUEST_PATH, pathlen) == 0) &&
	     (CM_DBUS_REQUEST_PATH[pathlen] == '/'))) {
		return cm_tdbush_object_type_parent_of_requests;
	}
	/* Check for things above the CA group node. */
	if (((pathlen < capathlen) &&
	     (strncmp(path, CM_DBUS_CA_PATH, pathlen) == 0) &&
	     (CM_DBUS_CA_PATH[pathlen] == '/'))) {
		return cm_tdbush_object_type_parent_of_cas;
	}
	/* Check if it names a request. */
	if ((pathlen > reqpathlen) &&
	    (strncmp(path, CM_DBUS_REQUEST_PATH, reqpathlen) == 0) &&
	    (path[reqpathlen] == '/') &&
	    (cm_get_entry_by_busname(ctx, path + reqpathlen + 1) != NULL)) {
		return cm_tdbush_object_type_request;
	}
	/* Check if it names a CA. */
	if ((pathlen > capathlen) &&
	    (strncmp(path, CM_DBUS_CA_PATH, capathlen) == 0) &&
	    (path[capathlen] == '/') &&
	    (cm_get_ca_by_busname(ctx, path + capathlen + 1) != NULL)) {
		return cm_tdbush_object_type_ca;
	}
	/* It's not classifiable. */
	return cm_tdbush_object_type_none;
}

/* the list of method calls that we've made that we haven't yet received
 * responses for, and the methods to invoke once we've gotten responses for our
 * outstanding requests  */
struct cm_tdbush_pending_call {
	DBusMessage *cm_msg;
	const char *cm_path, *cm_interface, *cm_method;
	enum cm_tdbush_object_type cm_type;
	DBusHandlerResult (*cm_fn)(DBusConnection *conn,
				   DBusMessage *msg,
				   struct cm_client_info *ci,
				   struct cm_context *ctx);
	dbus_bool_t cm_know_uid; /* GetConnectionUnixUser replied? */
	dbus_uint32_t cm_pending_uid; /* pending GetConnectionUnixUser call */
	uid_t cm_uid;
	struct cm_tdbush_pending_call *cm_next;
} *cm_pending_calls;

/* handle a method call by either asserting that we don't support a method, or
 * by asking for information about the caller */
DBusHandlerResult
cm_tdbush_handle_method_call(DBusConnection *conn, DBusMessage *msg,
			     struct cm_context *ctx)
{
	struct cm_tdbush_pending_call pending, *tmp;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	struct cm_tdbush_method *meth;
	unsigned int i;

	memset(&pending, 0, sizeof(pending));
	pending.cm_msg = dbus_message_ref(msg);
	pending.cm_path = dbus_message_get_path(pending.cm_msg);
	pending.cm_interface = dbus_message_get_interface(pending.cm_msg);
	pending.cm_method = dbus_message_get_member(pending.cm_msg);
	pending.cm_type = cm_tdbush_classify_path(ctx, pending.cm_path);
	pending.cm_know_uid = FALSE;
	for (i = 0;
	     i < sizeof(cm_tdbush_object_type_map) / sizeof(cm_tdbush_object_type_map[i]);
	     i++) {
		if (cm_tdbush_object_type_map[i].cm_type != pending.cm_type) {
			continue;
		}
		iface = (*((cm_tdbush_object_type_map[i]).cm_interface))();
		if ((pending.cm_interface != NULL) &&
		    (strcmp(iface->cm_name, pending.cm_interface) != 0)) {
			continue;
		}
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			if (item->cm_member_type != cm_tdbush_interface_method) {
				continue;
			}
			meth = item->cm_method;
			if (strcmp(meth->cm_name, pending.cm_method) != 0) {
				continue;
			}
			/* found it */
			pending.cm_fn = meth->cm_fn;
			tmp = talloc_ptrtype(NULL, tmp);
			if (tmp != NULL) {
				/* we need to know who this is */
				msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
								   DBUS_PATH_DBUS,
								   DBUS_INTERFACE_DBUS,
								   "GetConnectionUnixUser");
				if (msg != NULL) {
					cm_tdbusm_set_s(msg, dbus_message_get_sender(pending.cm_msg));
					if (dbus_connection_send(conn, msg,
								 &pending.cm_pending_uid)) {
						*tmp = pending;
						tmp->cm_next = cm_pending_calls;
						cm_pending_calls = tmp;
						cm_reset_timeout(ctx);
						cm_log(4, "Pending GetConnectionUnixUser serial %lu\n",
						       (unsigned long) pending.cm_pending_uid);
						dbus_message_unref(msg);
						cm_reset_timeout(ctx);
						return DBUS_HANDLER_RESULT_HANDLED;
					}
					dbus_message_unref(msg);
				}
				talloc_free(tmp);
			}
			dbus_message_unref(pending.cm_msg);
			cm_reset_timeout(ctx);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		if (item == NULL) {
			continue;
		}
	}
	dbus_message_unref(pending.cm_msg);
	cm_reset_timeout(ctx);
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult
cm_tdbush_handle_method_return(DBusConnection *conn, DBusMessage *msg,
			       struct cm_context *ctx)
{
	struct cm_tdbush_pending_call **p, *call, *next;
	dbus_uint32_t serial;
	struct cm_client_info client_info;
	long uid;

	serial = dbus_message_get_reply_serial(msg);
	/* figure out which of our pending calls this goes with */
	for (p = &cm_pending_calls;
	     (p != NULL) && (*p != NULL);
	     p = &((*p)->cm_next)) {
		call = *p;
		next = call->cm_next;
		if (call->cm_pending_uid == serial) {
			if (cm_tdbusm_get_n(msg, call, &uid) != 0) {
				cm_log(1, "Result error from GetConnectionUnixUser().\n");
				dbus_message_unref(call->cm_msg);
				talloc_free(call);
				*p = next;
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			call->cm_uid = uid;
			call->cm_know_uid = TRUE;
			break;
		}
	}
	if ((p == NULL) || (*p == NULL)) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	/* do we know enough now? if not, we're done here */
	if (!call->cm_know_uid) {
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* actually run the method */
	cm_log(4, "User ID %lu called %s:%s.%s.\n",
	       uid, call->cm_path, call->cm_interface, call->cm_method);

	client_info.uid = call->cm_uid;
	(*call->cm_fn)(conn, call->cm_msg, &client_info, ctx);

	/* remove the pending call record */
	dbus_message_unref(call->cm_msg);
	talloc_free(call);
	*p = next;
	cm_reset_timeout(ctx);

	return DBUS_HANDLER_RESULT_HANDLED;
}
