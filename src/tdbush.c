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
#include <sys/stat.h>
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
#include "tdbusm.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

/* Functions which tell us if, based on the path alone, there's an object of
 * the specified type with that path. */
static dbus_bool_t
is_ancestor_of_base(struct cm_context *ctx, const char *path,
		    const char *interface, const char *member)
{
	int basepathlen = strlen(CM_DBUS_BASE_PATH);
	int pathlen = strlen(path);
	return (strcmp(path, "/") == 0) ||
	       ((pathlen < basepathlen) &&
		(strncmp(path, CM_DBUS_BASE_PATH, pathlen) == 0) &&
		(CM_DBUS_BASE_PATH[pathlen] == '/'));
}
static dbus_bool_t
is_ancestor_of_cas(struct cm_context *ctx, const char *path,
		   const char *interface, const char *member)
{
	int capathlen = strlen(CM_DBUS_CA_PATH);
	int pathlen = strlen(path);
	return (strcmp(path, "/") == 0) ||
	       ((pathlen < capathlen) &&
		(strncmp(path, CM_DBUS_CA_PATH, pathlen) == 0) &&
		(CM_DBUS_CA_PATH[pathlen] == '/'));
}
static dbus_bool_t
is_ancestor_of_requests(struct cm_context *ctx, const char *path,
		        const char *interface, const char *member)
{
	int reqpathlen = strlen(CM_DBUS_REQUEST_PATH);
	int pathlen = strlen(path);
	return (strcmp(path, "/") == 0) ||
	       ((pathlen < reqpathlen) &&
		(strncmp(path, CM_DBUS_REQUEST_PATH, pathlen) == 0) &&
		(CM_DBUS_REQUEST_PATH[pathlen] == '/'));
}
static dbus_bool_t
is_base(struct cm_context *ctx, const char *path,
	const char *interface, const char *member)
{
	return (strcmp(path, CM_DBUS_BASE_PATH) == 0);
}
static dbus_bool_t
is_ca_group(struct cm_context *ctx, const char *path,
	    const char *interface, const char *member)
{
	return (strcmp(path, CM_DBUS_CA_PATH) == 0);
}
static dbus_bool_t
is_request_group(struct cm_context *ctx, const char *path,
		 const char *interface, const char *member)
{
	return (strcmp(path, CM_DBUS_REQUEST_PATH) == 0);
}
static struct cm_store_entry *
get_entry_for_path(struct cm_context *ctx, const char *path)
{
	int initial;
	if (path != NULL) {
		initial = strlen(CM_DBUS_REQUEST_PATH);
		if (strncmp(path, CM_DBUS_REQUEST_PATH, initial) == 0) {
			if (path[initial] == '/') {
				return cm_get_entry_by_id(ctx,
							  path + initial + 1);
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
				return cm_get_ca_by_id(ctx, path + initial + 1);
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
static dbus_bool_t
is_ca(struct cm_context *ctx, const char *path,
      const char *interface, const char *member)
{
	return get_ca_for_path(ctx, path) != NULL;
}
static dbus_bool_t
is_request(struct cm_context *ctx, const char *path,
	   const char *interface, const char *member)
{
	return get_entry_for_path(ctx, path) != NULL;
}

/* Functions implemented for the base object. */
static char *
maybe_strdup(void *parent, const char *s)
{
	if (s != NULL) {
		return talloc_strdup(parent, s);
	}
	return NULL;
}

static char **
maybe_strdupv(void *parent, char **s)
{
	int i;
	char **ret = NULL;
	for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
		continue;
	}
	if (i > 0) {
		ret = talloc_array_ptrtype(parent, ret, i + 1);
		if (ret != NULL) {
			for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
				ret[i] = talloc_strdup(ret, s[i]);
			}
			ret[i] = NULL;
		}
	}
	return ret;
}

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

static int
cm_tdbush_check_object_path_component(struct cm_context *ctx, const char *name)
{
	if (strlen(name) == 0) {
		return -1;
	}
	if (strspn(name,
		   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		   "abcdefghijklmnopqrstuvwxyz"
		   "0123456789_") != strlen(name)) {
		return -1;
	}
	return 0;
}

static int
cm_tdbush_check_arg_is_absolute_path(const char *path)
{
	return (path[0] == '/') ? 0 : -1;
}

static int
cm_tdbush_check_arg_is_absolute_nss_path(const char *path)
{
	if (strncmp(path, "sql:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "dbm:", 4) == 0) {
		path += 4;
	}
	return (path[0] == '/') ? 0 : -1;
}

static int
cm_tdbush_check_arg_is_directory(const char *path)
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
cm_tdbush_check_arg_is_nss_directory(const char *path)
{
	struct stat st;
	if (strncmp(path, "sql:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "dbm:", 4) == 0) {
		path += 4;
	}
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			return 0;
		}
	}
	return -1;
}

static int
cm_tdbush_check_arg_is_reg_or_missing(const char *path)
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
cm_tdbush_check_arg_parent_is_directory(const char *path)
{
	char *tmp, *p;
	int ret;
	if (cm_tdbush_check_arg_is_absolute_path(path) != 0) {
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
			ret = cm_tdbush_check_arg_is_directory(tmp);
			free(tmp);
			return ret;
		}
		free(tmp);
	}
	return -1;
}

static DBusHandlerResult
base_add_known_ca(DBusConnection *conn, DBusMessage *msg,
		  struct cm_context *ctx)
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
		if (strcasecmp(ca->cm_id, ca_name) == 0) {
			cm_log(1, "There is already a CA with "
			       "the nickname \"%s\".\n", ca->cm_id);
			talloc_free(parent);
			return send_internal_base_duplicate_error(conn, msg,
								  _("There is already a CA with the nickname \"%s\"."),
								  ca->cm_id,
								  NULL,
								  NULL);
		}
	}
	if (cm_tdbush_check_object_path_component(ctx, ca_name) != 0) {
		return send_internal_base_bad_arg_error(conn, msg,
							_("The nickname \"%s\" is not allowed."),
							ca_name, NULL);
	}
	/* Okay, we can go ahead and add the CA. */
	new_ca = talloc_ptrtype(parent, new_ca);
	if (new_ca == NULL) {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
	memset(new_ca, 0, sizeof(*new_ca));
	/* Populate it with all of the information we have. */
	new_ca->cm_id = talloc_strdup(new_ca, ca_name);
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
					       new_ca->cm_id);
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

static DBusHandlerResult
base_add_request(DBusConnection *conn, DBusMessage *msg,
		 struct cm_context *ctx)
{
	DBusMessage *rep;
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
	char *path;

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_d(msg, parent, &d) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Certificate storage. */
	param = cm_tdbusm_find_dict_entry(d, "CERT_STORAGE", cm_tdbusm_dict_s);
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
			DBusHandlerResult ret;
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
		key_pin = NULL;
	} else {
		key_pin = param->value.s;
	}
	param = cm_tdbusm_find_dict_entry(d, "KEY_PIN_FILE", cm_tdbusm_dict_s);
	if (param == NULL) {
		key_pin_file = NULL;
	} else {
		if (cm_tdbush_check_arg_is_absolute_path(param->value.s) != 0) {
			cm_log(1, "PIN storage location is not an absolute "
			       "path.\n");
			talloc_free(parent);
			return send_internal_base_bad_arg_error(conn, msg,
								_("The location \"%s\" must be an absolute path."),
								param->value.s,
								"KEY_PIN_FILE");
		}
		key_pin_file = param->value.s;
	}
	/* Check that other required information about the
	 * certificate's location is provided. */
	switch (cert_storage) {
	case cm_cert_storage_file:
		param = cm_tdbusm_find_dict_entry(d, "CERT_LOCATION",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			cm_log(1, "Cert storage location not specified.\n");
			talloc_free(parent);
			return send_internal_base_missing_arg_error(conn, msg,
								    _("Certificate storage location not specified."),
								    "CERT_LOCATION");
		}
		if (cm_tdbush_check_arg_is_absolute_path(param->value.s) != 0) {
			cm_log(1, "Cert storage location is not an absolute "
			       "path.\n");
			talloc_free(parent);
			return send_internal_base_bad_arg_error(conn, msg,
								_("The location \"%s\" must be an absolute path."),
								param->value.s,
								"CERT_LOCATION");
		}
		if (cm_tdbush_check_arg_parent_is_directory(param->value.s) != 0) {
			cm_log(1, "Cert storage location is not inside of "
			       "a directory.\n");
			talloc_free(parent);
			return send_internal_base_bad_arg_error(conn, msg,
								_("The parent of location \"%s\" must be a valid directory."),
								param->value.s,
								"CERT_LOCATION");
		}
		if (cm_tdbush_check_arg_is_reg_or_missing(param->value.s) != 0) {
			cm_log(1, "Cert storage location is "
			       "not a regular file.\n");
			talloc_free(parent);
			return send_internal_base_bad_arg_error(conn, msg,
								_("The location \"%s\" must be a file."),
								param->value.s,
								"CERT_LOCATION");
		}
		cert_location = param->value.s;
		cert_nickname = NULL;
		cert_token = NULL;
		break;
	case cm_cert_storage_nssdb:
		param = cm_tdbusm_find_dict_entry(d, "CERT_LOCATION",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			cm_log(1, "Cert storage location not specified.\n");
			talloc_free(parent);
			return send_internal_base_missing_arg_error(conn, msg,
								    _("Certificate storage location not specified."),
								    "CERT_LOCATION");
		}
		if (cm_tdbush_check_arg_is_absolute_nss_path(param->value.s) != 0) {
			cm_log(1, "Cert storage location is not an absolute "
			       "path.\n");
			talloc_free(parent);
			return send_internal_base_bad_arg_error(conn, msg,
								_("The location \"%s\" must be an absolute path."),
								param->value.s,
								"CERT_LOCATION");
		}
		if (cm_tdbush_check_arg_is_nss_directory(param->value.s) != 0) {
			cm_log(1, "Cert storage location must be "
			       "a directory.\n");
			talloc_free(parent);
			return send_internal_base_bad_arg_error(conn, msg,
								_("The location \"%s\" must be a directory."),
								param->value.s,
								"CERT_LOCATION");
		}
		cert_location = cm_store_canonicalize_directory(parent,
								param->value.s);
		param = cm_tdbusm_find_dict_entry(d, "CERT_NICKNAME",
						  cm_tdbusm_dict_s);
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
			cert_token = NULL;
		} else {
			cert_token = param->value.s;
		}
		break;
	}
	/* Check that the requested nickname will be unique. */
	param = cm_tdbusm_find_dict_entry(d, "NICKNAME", cm_tdbusm_dict_s);
	if (param != NULL) {
		n_entries = cm_get_n_entries(ctx);
		for (i = 0; i < n_entries; i++) {
			e = cm_get_entry_by_index(ctx, i);
			if (strcasecmp(e->cm_id, param->value.s) == 0) {
				cm_log(1, "There is already a request with "
				       "the nickname \"%s\".\n", e->cm_id);
				talloc_free(parent);
				return send_internal_base_duplicate_error(conn, msg,
									  _("There is already a request with the nickname \"%s\"."),
									  e->cm_id,
									  "NICKNAME",
									  NULL);
			}
		}
		if (cm_tdbush_check_object_path_component(ctx,
							  param->value.s) != 0) {
			return send_internal_base_bad_arg_error(conn, msg,
								_("The nickname \"%s\" is not allowed."),
								param->value.s,
								"NICKNAME");
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
		       "used for request \"%s\".\n", e->cm_id);
		talloc_free(parent);
		return send_internal_base_duplicate_error(conn, msg,
							  _("Certificate at same location is already used by request \"%s\"."),
							  e->cm_id,
							  "CERT_LOCATION",
							  cert_storage == cm_cert_storage_nssdb ?
							  "CERT_NICKNAME" : NULL);
	}
	/* Key storage.  We can afford to be a bit more lax about this because
	 * we don't require that we know anything about the key. */
	param = cm_tdbusm_find_dict_entry(d, "KEY_STORAGE", cm_tdbusm_dict_s);
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
			DBusHandlerResult ret;
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
				cm_log(1,
				       "Key storage location not specified.\n");
				talloc_free(parent);
				return send_internal_base_missing_arg_error(conn, msg,
									    _("Key storage location not specified."),
									    "KEY_LOCATION");
			}
			if (cm_tdbush_check_arg_is_absolute_path(param->value.s) != 0) {
				cm_log(1, "Key storage location is not an "
				       "absolute path.\n");
				talloc_free(parent);
				return send_internal_base_bad_arg_error(conn, msg,
									_("The location \"%s\" must be an absolute path."),
									param->value.s,
									"KEY_LOCATION");
			}
			if (cm_tdbush_check_arg_parent_is_directory(param->value.s) != 0) {
				cm_log(1, "Key storage location is not inside "
				       "of a directory.\n");
				talloc_free(parent);
				return send_internal_base_bad_arg_error(conn, msg,
									_("The parent of location \"%s\" must be a valid directory."),
									param->value.s,
									"KEY_LOCATION");
			}
			if (cm_tdbush_check_arg_is_reg_or_missing(param->value.s) != 0) {
				cm_log(1, "Key storage location is "
				       "not a regular file.\n");
				talloc_free(parent);
				return send_internal_base_bad_arg_error(conn, msg,
									_("The location \"%s\" must be a file."),
									param->value.s,
									"KEY_LOCATION");
			}
			key_location = param->value.s;
			key_nickname = NULL;
			key_token = NULL;
			break;
		case cm_key_storage_nssdb:
			param = cm_tdbusm_find_dict_entry(d, "KEY_LOCATION",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				cm_log(1,
				       "Key storage location not specified.\n");
				talloc_free(parent);
				return send_internal_base_missing_arg_error(conn, msg,
									    _("Key storage location not specified."),
									    "KEY_LOCATION");
			}
			if (cm_tdbush_check_arg_is_absolute_nss_path(param->value.s) != 0) {
				cm_log(1, "Key storage location is not an "
				       "absolute path.\n");
				talloc_free(parent);
				return send_internal_base_bad_arg_error(conn, msg,
									_("The location \"%s\" must be an absolute path."),
									param->value.s,
									"KEY_LOCATION");
			}
			if (cm_tdbush_check_arg_is_nss_directory(param->value.s) != 0) {
				cm_log(1, "Key storage location must be "
				       "a directory.\n");
				talloc_free(parent);
				return send_internal_base_bad_arg_error(conn, msg,
									_("The location \"%s\" must be a directory."),
									param->value.s,
									"KEY_LOCATION");
			}
			key_location = cm_store_canonicalize_directory(parent,
								       param->value.s);
			param = cm_tdbusm_find_dict_entry(d, "KEY_NICKNAME",
							  cm_tdbusm_dict_s);
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
			       "used for request \"%s\".\n", e->cm_id);
			talloc_free(parent);
			return send_internal_base_duplicate_error(conn, msg,
								  _("Key at same location is already used by request \"%s\"."),
								  e->cm_id,
								  "KEY_LOCATION",
								  key_storage == cm_key_storage_nssdb ?
								  "KEY_NICKNAME" : NULL);
		}
	}
	/* Okay, we can go ahead and add the entry. */
	new_entry = talloc_ptrtype(parent, new_entry);
	if (new_entry == NULL) {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
	memset(new_entry, 0, sizeof(*new_entry));
	/* Populate it with all of the information we have. */
	param = cm_tdbusm_find_dict_entry(d, "NICKNAME", cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_id = talloc_strdup(new_entry, param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d, "KEY_SIZE", cm_tdbusm_dict_n);
	if (param != NULL) {
		new_entry->cm_key_type.cm_key_gen_algorithm = CM_DEFAULT_PUBKEY_TYPE;
		new_entry->cm_key_type.cm_key_gen_size = param->value.n;
	} else {
		new_entry->cm_key_type.cm_key_gen_algorithm = CM_DEFAULT_PUBKEY_TYPE;
		new_entry->cm_key_type.cm_key_gen_size = CM_DEFAULT_PUBKEY_SIZE;
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
	param = cm_tdbusm_find_dict_entry(d, "CA", cm_tdbusm_dict_s);
	if (param != NULL) {
		ca = get_ca_for_path(ctx, param->value.s);
		if (ca != NULL) {
			new_entry->cm_ca_name = talloc_strdup(new_entry,
							      ca->cm_id);
		} else {
			cm_log(1, "No CA with path \"%s\" known.\n",
			       param->value.s);
			talloc_free(parent);
			return send_internal_base_bad_arg_error(conn, msg,
								_("No such CA."),
								param->value.s,
								"CA");
		}
	}
	/* Behavior settings. */
	param = cm_tdbusm_find_dict_entry(d, "TRACK", cm_tdbusm_dict_b);
	if (param != NULL) {
		new_entry->cm_monitor = param->value.b;
	} else {
		new_entry->cm_monitor = cm_prefs_monitor();
	}
	param = cm_tdbusm_find_dict_entry(d, "RENEW", cm_tdbusm_dict_b);
	if (param != NULL) {
		new_entry->cm_autorenew = param->value.b;
	} else {
		new_entry->cm_autorenew = cm_prefs_autorenew();
	}
	/* Template information. */
	param = cm_tdbusm_find_dict_entry(d, "SUBJECT", cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_template_subject = maybe_strdup(new_entry,
							      param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d, "EKU", cm_tdbusm_dict_as);
	if (param != NULL) {
		new_entry->cm_template_eku = cm_submit_maybe_joinv(new_entry,
								   ",",
								   param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "PRINCIPAL", cm_tdbusm_dict_as);
	if (param != NULL) {
		new_entry->cm_template_principal = maybe_strdupv(new_entry,
								 param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "DNS", cm_tdbusm_dict_as);
	if (param != NULL) {
		new_entry->cm_template_hostname = maybe_strdupv(new_entry,
								param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "EMAIL", cm_tdbusm_dict_as);
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
					       new_entry->cm_id);
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

static DBusHandlerResult
base_get_defaults(DBusConnection *conn, DBusMessage *msg,
		  struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
base_get_known_cas(DBusConnection *conn, DBusMessage *msg,
		   struct cm_context *ctx)
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
						 CM_DBUS_CA_PATH, ca->cm_id);
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

static DBusHandlerResult
base_get_requests(DBusConnection *conn, DBusMessage *msg,
		  struct cm_context *ctx)
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
						 entry->cm_id);
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

static DBusHandlerResult
base_get_supported_key_types(DBusConnection *conn, DBusMessage *msg,
			     struct cm_context *ctx)
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
					struct cm_context *ctx)
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

static DBusHandlerResult
base_remove_known_ca(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
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
			ret = cm_remove_ca(ctx, ca->cm_id);
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

static DBusHandlerResult
base_remove_request(DBusConnection *conn, DBusMessage *msg,
		    struct cm_context *ctx)
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
			ret = cm_remove_entry(ctx, entry->cm_id);
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

/* Functions implemented for known CAs. */
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
static DBusHandlerResult
ca_get_nickname(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (ca->cm_id != NULL) {
			cm_tdbusm_set_s(rep, ca->cm_id);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

static DBusHandlerResult
ca_get_is_default(DBusConnection *conn, DBusMessage *msg,
		  struct cm_context *ctx)
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

static DBusHandlerResult
ca_get_issuer_names(DBusConnection *conn, DBusMessage *msg,
		    struct cm_context *ctx)
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

static DBusHandlerResult
ca_get_location(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
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

static DBusHandlerResult
ca_get_type(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
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

static DBusHandlerResult
ca_get_serial(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
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

static DBusHandlerResult
ca_modify(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Functions implemented for request objects. */
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

static DBusHandlerResult
request_get_nickname(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_id != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_id);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

static DBusHandlerResult
request_get_key_pin(DBusConnection *conn, DBusMessage *msg,
		    struct cm_context *ctx)
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

static DBusHandlerResult
request_get_key_pin_file(DBusConnection *conn, DBusMessage *msg,
			 struct cm_context *ctx)
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

static DBusHandlerResult
request_get_autorenew(DBusConnection *conn, DBusMessage *msg,
		      struct cm_context *ctx)
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

static DBusHandlerResult
request_get_cert_data(DBusConnection *conn, DBusMessage *msg,
		      struct cm_context *ctx)
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

static char **
eku_splitv(const char *eku)
{
	char **ret = NULL;
	const char *p, *q;
	int i;
	if ((eku != NULL) && (strlen(eku) > 0)) {
		ret = talloc_array_ptrtype(NULL, ret, strlen(eku) + 1);
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

static DBusHandlerResult
request_get_cert_info(DBusConnection *conn, DBusMessage *msg,
		      struct cm_context *ctx)
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
		eku = eku_splitv(entry->cm_cert_eku);
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

static DBusHandlerResult
request_get_cert_last_checked(DBusConnection *conn, DBusMessage *msg,
			      struct cm_context *ctx)
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

static DBusHandlerResult
request_get_cert_storage_info(DBusConnection *conn, DBusMessage *msg,
			      struct cm_context *ctx)
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

static DBusHandlerResult
request_get_csr_data(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
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

static DBusHandlerResult
request_get_csr_info(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
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
			eku = eku_splitv(entry->cm_template_eku);
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

static DBusHandlerResult
request_get_key_storage_info(DBusConnection *conn, DBusMessage *msg,
			     struct cm_context *ctx)
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

static DBusHandlerResult
request_get_key_type_and_size(DBusConnection *conn, DBusMessage *msg,
			      struct cm_context *ctx)
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

static DBusHandlerResult
request_get_monitoring(DBusConnection *conn, DBusMessage *msg,
		       struct cm_context *ctx)
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

static DBusHandlerResult
request_get_notification_info(DBusConnection *conn, DBusMessage *msg,
			      struct cm_context *ctx)
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
	case cm_notification_stdout:
		method = "stdout";
		break;
	case cm_notification_syslog:
		method = "syslog";
		break;
	case cm_notification_email:
		method = "email";
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

static DBusHandlerResult
request_get_status(DBusConnection *conn, DBusMessage *msg,
		   struct cm_context *ctx)
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
		stuck = FALSE;
		switch (entry->cm_state) {
		case CM_INVALID:
		case CM_NEED_KEY_PAIR:
		case CM_GENERATING_KEY_PAIR:
		case CM_HAVE_KEY_PAIR:
		case CM_NEED_CSR:
		case CM_GENERATING_CSR:
		case CM_HAVE_CSR:
		case CM_NEED_TO_SUBMIT:
		case CM_SUBMITTING:
		case CM_CA_WORKING:
		case CM_NEED_TO_SAVE_CERT:
		case CM_SAVING_CERT:
		case CM_NEED_TO_READ_CERT:
		case CM_READING_CERT:
		case CM_SAVED_CERT:
		case CM_MONITORING:
		case CM_NEED_TO_NOTIFY:
		case CM_NOTIFYING:
		case CM_NEWLY_ADDED:
		case CM_NEWLY_ADDED_START_READING_KEYI:
		case CM_NEWLY_ADDED_READING_KEYI:
		case CM_NEWLY_ADDED_START_READING_CERT:
		case CM_NEWLY_ADDED_READING_CERT:
		case CM_NEWLY_ADDED_DECIDING:
			stuck = FALSE;
			break;
		case CM_NEED_KEY_GEN_PIN:
		case CM_NEED_CSR_GEN_PIN:
		case CM_NEWLY_ADDED_NEED_KEYI_READ_PIN:
		case CM_NEED_GUIDANCE:
		case CM_NEED_CA:
		case CM_CA_REJECTED:
		case CM_CA_UNREACHABLE:
		case CM_CA_UNCONFIGURED:
			stuck = TRUE;
			break;
		}
		cm_tdbusm_set_sb(rep, state, stuck);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

static DBusHandlerResult
request_get_ca(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	void *parent;
	DBusMessage *rep;
	struct cm_store_entry *entry;
	char *path;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		parent = talloc_new(NULL);
		if ((entry->cm_ca_name != NULL) &&
		    (strlen(entry->cm_ca_name) > 0)) {
			path = talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_CA_PATH,
					       entry->cm_ca_name);
			cm_tdbusm_set_p(rep, path);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

static DBusHandlerResult
request_get_ca_error(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
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

static DBusHandlerResult
request_get_submitted_cookie(DBusConnection *conn, DBusMessage *msg,
			     struct cm_context *ctx)
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

static DBusHandlerResult
request_get_submitted_date(DBusConnection *conn, DBusMessage *msg,
			   struct cm_context *ctx)
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

static DBusHandlerResult
request_modify(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	struct cm_tdbusm_dict **d;
	const struct cm_tdbusm_dict *param;
	char *new_request_path;
	void *parent;
	int i;

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
		if (param != NULL) {
			if (cm_get_entry_by_id(ctx, param->value.s) != NULL) {
				return send_internal_base_duplicate_error(conn, msg,
									  _("There is already a request with the nickname \"%s\"."),
									  param->value.s,
									  "NICKNAME",
									  NULL);
			}
			if (cm_tdbush_check_object_path_component(ctx, param->value.s) != 0) {
				return send_internal_base_bad_arg_error(conn, msg,
									_("The nickname \"%s\" is not allowed."),
									param->value.s,
									"NICKNAME");
			}
		}
		/* If we're being asked to change the CA, check that the new CA
		 * exists. */
		param = cm_tdbusm_find_dict_entry(d, "CA", cm_tdbusm_dict_s);
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
			    (strcasecmp(param->key, "RENEW") == 0)) {
				entry->cm_autorenew = param->value.b;
			} else
			if ((param->value_type == cm_tdbusm_dict_b) &&
			    (strcasecmp(param->key, "TRACK") == 0)) {
				entry->cm_monitor = param->value.b;
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, "CA") == 0)) {
				ca = get_ca_for_path(ctx, param->value.s);
				talloc_free(entry->cm_ca_name);
				entry->cm_ca_name = talloc_strdup(entry,
								  ca->cm_id);
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, "NICKNAME") == 0)) {
				talloc_free(entry->cm_id);
				entry->cm_id = talloc_strdup(entry,
							     param->value.s);
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, "SUBJECT") == 0)) {
				talloc_free(entry->cm_template_subject);
				entry->cm_template_subject = maybe_strdup(entry,
									  param->value.s);
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, "KEY_PIN") == 0)) {
				talloc_free(entry->cm_key_pin);
				entry->cm_key_pin = maybe_strdup(entry,
								 param->value.s);
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, "KEY_PIN_FILE") == 0)) {
				if (cm_tdbush_check_arg_is_absolute_path(param->value.s) != 0) {
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
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, "EKU") == 0)) {
				talloc_free(entry->cm_template_eku);
				entry->cm_template_eku = cm_submit_maybe_joinv(entry,
									       ",",
									       param->value.as);
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, "PRINCIPAL") == 0)) {
				talloc_free(entry->cm_template_principal);
				entry->cm_template_principal = maybe_strdupv(entry,
									     param->value.as);
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, "DNS") == 0)) {
				talloc_free(entry->cm_template_hostname);
				entry->cm_template_hostname = maybe_strdupv(entry,
									    param->value.as);
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, "EMAIL") == 0)) {
				talloc_free(entry->cm_template_email);
				entry->cm_template_email = maybe_strdupv(entry,
									 param->value.as);
			} else {
				break;
			}
		}
		if (d[i] == NULL) {
			new_request_path = talloc_asprintf(parent, "%s/%s",
							   CM_DBUS_REQUEST_PATH,
							   entry->cm_id);
			cm_tdbusm_set_bp(rep, cm_restart_one(ctx, entry->cm_id),
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

static DBusHandlerResult
request_resubmit(DBusConnection *conn, DBusMessage *msg,
		 struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (cm_stop_one(ctx, entry->cm_id)) {
			entry->cm_state = CM_NEED_CSR;
			if (cm_start_one(ctx, entry->cm_id)) {
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

static char *
ancestor_of_base_introspect(struct cm_context *ctx, const char *path)
{
	const char *p;
	int i;
	p = CM_DBUS_BASE_PATH + strlen(path);
	p += strspn(p, "/");
	i = strcspn(p, "/");
	return talloc_asprintf(ctx, " <node name=\"%.*s\"/>\n", i, p);
}

static char *
ancestor_of_ca_introspect(struct cm_context *ctx, const char *path)
{
	const char *p;
	int i;
	p = CM_DBUS_CA_PATH + strlen(path);
	p += strspn(p, "/");
	i = strcspn(p, "/");
	return talloc_asprintf(ctx, " <node name=\"%.*s\"/>\n", i, p);
}

static char *
ancestor_of_request_introspect(struct cm_context *ctx, const char *path)
{
	const char *p;
	int i;
	p = CM_DBUS_REQUEST_PATH + strlen(path);
	p += strspn(p, "/");
	i = strcspn(p, "/");
	return talloc_asprintf(ctx, " <node name=\"%.*s\"/>\n", i, p);
}

static char *
request_introspect(struct cm_context *ctx, const char *path)
{
	return talloc_asprintf(ctx, "%s",
			       " <interface name=\""
			       CM_DBUS_REQUEST_INTERFACE
			       "\">\n"
			       "  <method name=\"get_nickname\">\n"
			       "   <arg name=\"name\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_autorenew\">\n"
			       "   <arg name=\"enabled\" type=\"b\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_cert_data\">\n"
			       "   <arg name=\"pem\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_cert_info\">\n"
			       "   <arg name=\"issuer\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"serial\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"subject\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"not_after\" type=\"x\" direction=\"out\"/>\n"
			       "   <arg name=\"email\" type=\"as\" direction=\"out\"/>\n"
			       "   <arg name=\"dns\" type=\"as\" direction=\"out\"/>\n"
			       "   <arg name=\"principal_names\" type=\"as\" direction=\"out\"/>\n"
			       "   <arg name=\"key_usage\" type=\"x\" direction=\"out\"/>\n"
			       "   <arg name=\"extended_key_usage\" type=\"as\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_cert_last_checked\">\n"
			       "   <arg name=\"date\" type=\"x\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_cert_storage_info\">\n"
			       "   <arg name=\"type\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"location_or_nickname\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"nss_token\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_csr_data\">\n"
			       "   <arg name=\"pem\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_csr_info\">\n"
			       "   <arg name=\"subject\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"email\" type=\"as\" direction=\"out\"/>\n"
			       "   <arg name=\"dns\" type=\"as\" direction=\"out\"/>\n"
			       "   <arg name=\"principal_names\" type=\"as\" direction=\"out\"/>\n"
			       "   <arg name=\"key_usage\" type=\"x\" direction=\"out\"/>\n"
			       "   <arg name=\"extended_key_usage\" type=\"as\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_key_storage_info\">\n"
			       "   <arg name=\"type\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"location_or_nickname\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"nss_token\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_key_type_and_size\">\n"
			       "   <arg name=\"type\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"size\" type=\"x\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_monitoring\">\n"
			       "   <arg name=\"enabled\" type=\"b\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_notification_info\">\n"
			       "   <arg name=\"method\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"destination\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_status\">\n"
			       "   <arg name=\"state\" type=\"s\" direction=\"out\"/>\n"
			       "   <arg name=\"blocked\" type=\"b\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_ca\">\n"
			       "   <arg name=\"name\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_submitted_cookie\">\n"
			       "   <arg name=\"cookie\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_ca_error\">\n"
			       "   <arg name=\"text\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_submitted_date\">\n"
			       "   <arg name=\"date\" type=\"x\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"modify\">\n"
			       "   <arg name=\"updates\" type=\"a{sv}\" direction=\"in\"/>\n"
			       "   <arg name=\"status\" type=\"b\" direction=\"out\"/>\n"
			       "   <arg name=\"path\" type=\"o\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"resubmit\">\n"
			       "   <arg name=\"working\" type=\"b\" direction=\"out\"/>\n"
			       "  </method>\n"
			       " </interface>\n");
}

static char *
ca_introspect(struct cm_context *ctx, const char *path)
{
	return talloc_asprintf(ctx, "%s",
			       " <interface name=\""
			       CM_DBUS_CA_INTERFACE
			       "\">\n"
			       "  <method name=\"get_nickname\">\n"
			       "   <arg name=\"name\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_is_default\">\n"
			       "   <arg name=\"is\" type=\"b\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_type\">\n"
			       "   <arg name=\"type\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_serial\">\n"
			       "   <arg name=\"serial\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_location\">\n"
			       "   <arg name=\"path\" type=\"s\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_issuer_names\">\n"
			       "   <arg name=\"names\" type=\"as\" direction=\"out\"/>\n"
			       "  </method>\n"
#if 0
			       "  <method name=\"modify\">\n"
			       "  </method>\n"
#endif
			       " </interface>\n");
}

static char *
base_introspect(struct cm_context *ctx, const char *path)
{
	char *reqs, *cas, *ret;
	reqs = is_ancestor_of_requests(ctx, path,
				       DBUS_INTERFACE_INTROSPECTABLE,
				       "Introspect") ?
	       ancestor_of_request_introspect(ctx, path) : NULL;
	cas = is_ancestor_of_cas(ctx, path,
				 DBUS_INTERFACE_INTROSPECTABLE,
				 "Introspect") ?
	      ancestor_of_ca_introspect(ctx, path) : NULL;
	ret = talloc_asprintf(ctx, "%s%s%s", reqs ? reqs : "", cas ? cas : "",
			       " <interface name=\""
			       CM_DBUS_BASE_INTERFACE
			       "\">\n"
			       "  <method name=\"add_known_ca\">\n"
			       "   <arg name=\"nickname\" type=\"s\" direction=\"in\"/>\n"
			       "   <arg name=\"command\" type=\"s\" direction=\"in\"/>\n"
			       "   <arg name=\"known_names\" type=\"as\" direction=\"in\"/>\n"
			       "   <arg name=\"status\" type=\"b\" direction=\"out\"/>\n"
			       "   <arg name=\"name\" type=\"o\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"add_request\">\n"
			       "   <arg name=\"template\" type=\"a{sv}\" direction=\"in\"/>\n"
			       "   <arg name=\"status\" type=\"b\" direction=\"out\"/>\n"
			       "   <arg name=\"name\" type=\"o\" direction=\"out\"/>\n"
			       "  </method>\n"
#if 0
			       "  <method name=\"get_defaults\">\n"
			       "   <arg name=\"defaults\" type=\"o\" direction=\"out\"/>\n"
			       "  </method>\n"
#endif
			       "  <method name=\"get_known_cas\">\n"
			       "   <arg name=\"ca_list\" type=\"ao\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_requests\">\n"
			       "   <arg name=\"req_list\" type=\"ao\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_supported_key_types\">\n"
			       "   <arg name=\"key_type_list\" type=\"as\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_supported_key_storage\">\n"
			       "   <arg name=\"key_storage_list\" type=\"as\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"get_supported_cert_storage\">\n"
			       "   <arg name=\"cert_storage_list\" type=\"as\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"remove_known_ca\">\n"
			       "   <arg name=\"ca\" type=\"o\" direction=\"in\"/>\n"
			       "   <arg name=\"status\" type=\"b\" direction=\"out\"/>\n"
			       "  </method>\n"
			       "  <method name=\"remove_request\">\n"
			       "   <arg name=\"request_id\" type=\"o\" direction=\"in\"/>\n"
			       "   <arg name=\"status\" type=\"b\" direction=\"out\"/>\n"
			       "  </method>\n"
			       " </interface>\n");
	talloc_free(reqs);
	talloc_free(cas);
	return ret;
}

static char *
request_group_introspect(struct cm_context *ctx, const char *path)
{
	int i;
	char *p = NULL, *q;
	struct cm_store_entry *entry;
	i = cm_get_n_entries(ctx) - 1;
	while (i >= 0) {
		entry = cm_get_entry_by_index(ctx, i);
		if (entry != NULL) {
			q = talloc_asprintf(ctx, " <node name=\"%s\"/>\n%s",
					    entry->cm_id, p ? p : "");
			talloc_free(p);
			p = q;
		}
		i--;
	}
	return p ? p : talloc_strdup(ctx, "");
}

static char *
ca_group_introspect(struct cm_context *ctx, const char *path)
{
	int i;
	char *p = NULL, *q;
	struct cm_store_ca *ca;
	i = cm_get_n_cas(ctx) - 1;
	while (i >= 0) {
		ca = cm_get_ca_by_index(ctx, i);
		if (ca != NULL) {
			q = talloc_asprintf(ctx, " <node name=\"%s\"/>\n%s",
					    ca->cm_id, p ? p : "");
			talloc_free(p);
			p = q;
		}
		i--;
	}
	return p ? p : talloc_strdup(ctx, "");
}

static DBusHandlerResult
generic_introspect(DBusConnection *conn, DBusMessage *msg,
		   struct cm_context *ctx)
{
	DBusHandlerResult ret;
	DBusMessage *rep;
	const char *path, *interface, *method;
	char *data = NULL, *xml;
	path = dbus_message_get_path(msg);
	interface = dbus_message_get_interface(msg);
	method = dbus_message_get_member(msg);
	ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	if (is_base(ctx, path, interface, method)) {
		data = base_introspect(ctx, path);
	} else
	if (is_ca_group(ctx, path, interface, method)) {
		data = ca_group_introspect(ctx, path);
	} else
	if (is_ca(ctx, path, interface, method)) {
		data = ca_introspect(ctx, path);
	} else
	if (is_request_group(ctx, path, interface, method)) {
		data = request_group_introspect(ctx, path);
	} else
	if (is_request(ctx, path, interface, method)) {
		data = request_introspect(ctx, path);
	} else
	if (is_ancestor_of_base(ctx, path, interface, method)) {
		data = ancestor_of_base_introspect(ctx, path);
	} else
	if (is_ancestor_of_cas(ctx, path, interface, method)) {
		data = ancestor_of_ca_introspect(ctx, path);
	} else
	if (is_ancestor_of_requests(ctx, path, interface, method)) {
		data = ancestor_of_request_introspect(ctx, path);
	}
	if (data != NULL) {
		xml = talloc_asprintf(ctx,
				      "%s\n<node name=\"%s\">\n%s</node>\n",
				      DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE,
				      path,
				      data);
		if (xml != NULL) {
			rep = dbus_message_new_method_return(msg);
			if (rep != NULL) {
				if (cm_tdbusm_set_s(rep, xml) == 0) {
					dbus_connection_send(conn, rep, NULL);
					ret = DBUS_HANDLER_RESULT_HANDLED;
				}
				dbus_message_unref(rep);
			}
			talloc_free(xml);
		}
		talloc_free(data);
	}
	return ret;
}

static struct {
	dbus_bool_t (*implements)(struct cm_context *ctx, const char *path,
				  const char *interface, const char *member);
	const char *interface;
	const char *member;
	DBusHandlerResult (*handle)(DBusConnection *conn, DBusMessage *msg,
			   struct cm_context *ctx);
} cm_tdbush_methods[] = {
	{&is_base, CM_DBUS_BASE_INTERFACE, "add_known_ca",
	 base_add_known_ca},
	{&is_base, CM_DBUS_BASE_INTERFACE, "add_request",
	 base_add_request},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_defaults",
	 base_get_defaults},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_known_cas",
	 base_get_known_cas},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_requests",
	 base_get_requests},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_supported_key_types",
	 base_get_supported_key_types},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_supported_key_storage",
	 base_get_supported_key_and_cert_storage},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_supported_cert_storage",
	 base_get_supported_key_and_cert_storage},
	{&is_base, CM_DBUS_BASE_INTERFACE, "remove_known_ca",
	 base_remove_known_ca},
	{&is_base, CM_DBUS_BASE_INTERFACE, "remove_request",
	 base_remove_request},
	{&is_ca, CM_DBUS_CA_INTERFACE, "get_nickname", ca_get_nickname},
	{&is_ca, CM_DBUS_CA_INTERFACE, "get_is_default", ca_get_is_default},
	{&is_ca, CM_DBUS_CA_INTERFACE, "get_type", ca_get_type},
	{&is_ca, CM_DBUS_CA_INTERFACE, "get_serial", ca_get_serial},
	{&is_ca, CM_DBUS_CA_INTERFACE, "get_location", ca_get_location},
	{&is_ca, CM_DBUS_CA_INTERFACE, "get_issuer_names", ca_get_issuer_names},
	{&is_ca, CM_DBUS_CA_INTERFACE, "modify", ca_modify},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_nickname",
	 request_get_nickname},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_autorenew",
	 request_get_autorenew},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_key_pin",
	 request_get_key_pin},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_key_pin_file",
	 request_get_key_pin_file},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_cert_data",
	 request_get_cert_data},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_cert_info",
	 request_get_cert_info},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_cert_last_checked",
	 request_get_cert_last_checked},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_cert_storage_info",
	 request_get_cert_storage_info},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_csr_data",
	 request_get_csr_data},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_csr_info",
	 request_get_csr_info},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_key_storage_info",
	 request_get_key_storage_info},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_key_type_and_size",
	 request_get_key_type_and_size},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_monitoring",
	 request_get_monitoring},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_notification_info",
	 request_get_notification_info},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_status",
	 request_get_status},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_ca",
	 request_get_ca},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_ca_error",
	 request_get_ca_error},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_submitted_cookie",
	 request_get_submitted_cookie},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_submitted_date",
	 request_get_submitted_date},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "modify",
	 request_modify},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "resubmit",
	 request_resubmit},
	{NULL, DBUS_INTERFACE_INTROSPECTABLE, "Introspect",
	 generic_introspect},
};

DBusHandlerResult
cm_tdbush_handle(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	const char *path, *interface, *member;
	unsigned int i;
	path = dbus_message_get_path(msg);
	interface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);
	for (i = 0;
	     i < sizeof(cm_tdbush_methods) / sizeof(cm_tdbush_methods[i]);
	     i++) {
		if (strcmp(member, cm_tdbush_methods[i].member) != 0) {
			continue;
		}
		if (strcmp(interface, cm_tdbush_methods[i].interface) != 0) {
			continue;
		}
		if ((cm_tdbush_methods[i].implements != NULL) &&
		    (!(*(cm_tdbush_methods[i].implements))(ctx, path,
							   interface,
							   member))) {
			continue;
		}
		if (cm_tdbush_methods[i].handle == NULL) {
			continue;
		}
		return (*(cm_tdbush_methods[i].handle))(conn, msg, ctx);
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
