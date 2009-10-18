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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>

#include <dbus/dbus.h>

#include "log.h"
#include "cm.h"
#include "store.h"
#include "store-int.h"
#include "tdbus.h"
#include "tdbusm.h"

/* Functions which tell us if, based on the path alone, there's an object of
 * the specified type with that path. */
static dbus_bool_t
is_base(struct cm_context *ctx, const char *path,
	const char *interface, const char *member)
{
	return (strcmp(path, CM_DBUS_BASE_PATH) == 0);
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
static DBusHandlerResult
base_add_known_ca(DBusConnection *conn, DBusMessage *msg,
		  struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

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

static char *
maybe_joinv(void *parent, const char *sep, char **s)
{
	int i, l;
	char *ret = NULL;
	for (i = 0, l = 0; (s != NULL) && (s[i] != NULL); i++) {
		l += i ? strlen(sep) + strlen(s[i]) : strlen(s[i]);
	}
	if (l > 0) {
		ret = talloc_zero_size(parent, l + 1);
		if (ret != NULL) {
			for (i = 0; s[i] != NULL; i++) {
				if (i > 0) {
					strcat(ret, sep);
				}
				strcat(ret, s[i]);
			}
		}
	}
	return ret;
}

static DBusHandlerResult
base_add_request(DBusConnection *conn, DBusMessage *msg,
		 struct cm_context *ctx)
{
	DBusMessage *rep;
	void *parent;
	struct cm_tdbusm_dict **d;
	const struct cm_tdbusm_dict *param;
	struct cm_store_entry *e, *new_entry, *defaults;
	int i, n_entries;
	enum cm_key_storage_type key_storage;
	char *key_location, *key_nickname, *key_token;
	enum cm_cert_storage_type cert_storage;
	char *cert_location, *cert_nickname, *cert_token;
	char *path;

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_d(msg, parent, &d) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	defaults = cm_store_get_defaults();

	/* Certificate storage. */
	param = cm_tdbusm_find_dict_entry(d, "CERT_STORAGE", cm_tdbusm_dict_s);
	if (param == NULL) {
		/* This is a required parameter. */
		cm_log(1, "Cert storage type not specified.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
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
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		cert_location = param->value.s;
		param = cm_tdbusm_find_dict_entry(d, "CERT_NICKNAME",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			cm_log(1, "Cert nickname not specified.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	/* Key storage.  We can afford to be a bit more lax about this because
	 * we don't require that we know anything about the key. */
	param = cm_tdbusm_find_dict_entry(d, "KEY_STORAGE", cm_tdbusm_dict_s);
	if (param == NULL) {
		key_storage = defaults->cm_key_storage_type;
		key_location = defaults->cm_key_storage_location;
		key_nickname = defaults->cm_key_nickname;
		key_token = defaults->cm_key_token;
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
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			key_location = param->value.s;
			param = cm_tdbusm_find_dict_entry(d, "KEY_NICKNAME",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				cm_log(1, "Cert nickname not specified.\n");
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
	}
	/* Okay, we can go ahead and add the entry. */
	new_entry = talloc_ptrtype(parent, new_entry);
	if (new_entry == NULL) {
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	memset(new_entry, 0, sizeof(*new_entry));
	/* Populate it with all of the information we have. */
	param = cm_tdbusm_find_dict_entry(d, "KEY_SIZE", cm_tdbusm_dict_n);
	if (param != NULL) {
		new_entry->cm_key_type_default = FALSE;
		new_entry->cm_key_type.cm_key_algorithm = cm_key_rsa;
		new_entry->cm_key_type.cm_key_size = param->value.n;
	} else {
		new_entry->cm_key_type_default = TRUE;
	}
	/* Key and certificate storage. */
	new_entry->cm_key_storage_type = key_storage;
	new_entry->cm_key_storage_location = maybe_strdup(new_entry,
							  key_location);
	new_entry->cm_key_nickname = maybe_strdup(new_entry, key_nickname);
	new_entry->cm_key_token = maybe_strdup(new_entry, key_token);
	new_entry->cm_cert_storage_type = cert_storage;
	new_entry->cm_cert_storage_location = maybe_strdup(new_entry,
							   cert_location);
	new_entry->cm_cert_nickname = maybe_strdup(new_entry, cert_nickname);
	new_entry->cm_cert_token = maybe_strdup(new_entry, cert_token);
	/* Which CA to use. */
	param = cm_tdbusm_find_dict_entry(d, "CA", cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_ca_default = FALSE;
		new_entry->cm_ca_name = maybe_strdup(new_entry, param->value.s);
	} else {
		new_entry->cm_ca_default = TRUE;
	}
	/* Behavior settings. */
	param = cm_tdbusm_find_dict_entry(d, "TRACK", cm_tdbusm_dict_b);
	if (param != NULL) {
		new_entry->cm_monitor_default = FALSE;
		new_entry->cm_monitor = param->value.b;
	} else {
		new_entry->cm_monitor_default = TRUE;
	}
	param = cm_tdbusm_find_dict_entry(d, "RENEW", cm_tdbusm_dict_b);
	if (param != NULL) {
		new_entry->cm_autorenew_default = FALSE;
		new_entry->cm_autorenew = param->value.b;
	} else {
		new_entry->cm_monitor_default = TRUE;
	}
	/* Template information. */
	param = cm_tdbusm_find_dict_entry(d, "SUBJECT", cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_template_subject = maybe_strdup(new_entry,
							      param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d, "EKU", cm_tdbusm_dict_as);
	if (param != NULL) {
		new_entry->cm_template_eku = maybe_joinv(new_entry, ",",
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
		}
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
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
	n_cas = cm_get_n_entries(ctx);
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
		cm_tdbusm_set_as(rep, (const char **) ret);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	talloc_free(ret);
	return DBUS_HANDLER_RESULT_HANDLED;
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
	}
	talloc_free(ret);
	return DBUS_HANDLER_RESULT_HANDLED;
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
	}
	return DBUS_HANDLER_RESULT_HANDLED;
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
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
base_remove_known_ca(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
base_remove_request(DBusConnection *conn, DBusMessage *msg,
		    struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Functions implemented for known CAs. */
static DBusHandlerResult
ca_get_nickname(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (ca->cm_id != NULL) {
			cm_tdbusm_set_s(rep, ca->cm_id);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
ca_get_is_default(DBusConnection *conn, DBusMessage *msg,
		  struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_b(rep, ca->cm_ca_is_default);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
ca_get_issuer_names(DBusConnection *conn, DBusMessage *msg,
		    struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char **names;
	ca = get_ca_for_request_message(msg, ctx);
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		names = (const char **) ca->cm_ca_known_issuer_names;
		cm_tdbusm_set_as(rep, names);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
ca_get_location(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, ca->cm_ca_external_helper);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
ca_get_type(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char *ca_type;
	ca = get_ca_for_request_message(msg, ctx);
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
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
ca_get_serial(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char *serial;
	ca = get_ca_for_request_message(msg, ctx);
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
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
ca_modify(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Functions implemented for request objects. */
static DBusHandlerResult
request_get_nickname(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (entry->cm_id != NULL) {
				cm_tdbusm_set_s(rep, entry->cm_id);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_autorenew(DBusConnection *conn, DBusMessage *msg,
		      struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			cm_tdbusm_set_b(rep, entry->cm_autorenew);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_cert_data(DBusConnection *conn, DBusMessage *msg,
		      struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (entry->cm_cert != NULL) {
				cm_tdbusm_set_s(rep, entry->cm_cert);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static long
ku_from_string(const char *ku)
{
	long i = 0;
	while ((ku != NULL) && (*ku != '\0')) {
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
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			eku = eku_splitv(entry->cm_cert_eku);
			cm_tdbusm_set_sssnasasasnas(rep,
						    entry->cm_cert_issuer,
						    entry->cm_cert_serial,
						    entry->cm_cert_subject,
						    entry->cm_cert_expiration,
						    (const char **) entry->cm_cert_email,
						    (const char **) entry->cm_cert_hostname,
						    (const char **) entry->cm_cert_principal,
						    ku_from_string(entry->cm_cert_eku),
						    (const char **) eku);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			talloc_free(eku);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_cert_last_checked(DBusConnection *conn, DBusMessage *msg,
			      struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (entry->cm_submitted != 0) {
				cm_tdbusm_set_n(rep, entry->cm_submitted);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_cert_storage_info(DBusConnection *conn, DBusMessage *msg,
			      struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *type, *location, *nick, *token;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
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
							   location,
							   nick,
							   token);
					dbus_connection_send(conn, rep, NULL);
				} else
				if (nick != NULL) {
					cm_tdbusm_set_sss(rep, type,
							  location,
							  nick);
					dbus_connection_send(conn, rep, NULL);
				} else {
					cm_tdbusm_set_ss(rep, type,
							 location);
					dbus_connection_send(conn, rep, NULL);
				}
				break;
			}
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_csr_data(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (entry->cm_csr != NULL) {
				cm_tdbusm_set_s(rep, entry->cm_csr);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_csr_info(DBusConnection *conn, DBusMessage *msg,
		     struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_key_storage_info(DBusConnection *conn, DBusMessage *msg,
			     struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *type, *location, *nick, *token;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
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
							   location,
							   nick, token);
					dbus_connection_send(conn, rep, NULL);
				} else
				if (nick != NULL) {
					cm_tdbusm_set_sss(rep, type,
							  location,
							  nick);
					dbus_connection_send(conn, rep, NULL);
				} else {
					cm_tdbusm_set_ss(rep, type,
							 location);
					dbus_connection_send(conn, rep, NULL);
				}
				break;
			}
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
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
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		type = "UNKNOWN";
		switch (entry->cm_key_type.cm_key_algorithm) {
		case cm_key_rsa:
			type = "RSA";
			break;
		}
		if (rep != NULL) {
			size = entry->cm_key_type.cm_key_size;
			cm_tdbusm_set_sn(rep, type, size);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_monitoring(DBusConnection *conn, DBusMessage *msg,
		       struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			cm_tdbusm_set_b(rep, entry->cm_monitor);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_notification_info(DBusConnection *conn, DBusMessage *msg,
			      struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_HANDLED;
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
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			state = cm_store_state_as_string(entry->cm_state);
			switch (entry->cm_state) {
			/* XXX */
			default:
				stuck = FALSE;
				break;
			}
			cm_tdbusm_set_sb(rep, state, FALSE);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_ca(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	void *parent;
	DBusMessage *rep;
	struct cm_store_entry *entry;
	char *path;
	parent = talloc_new(NULL);
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (entry->cm_ca_name != NULL) {
				path = talloc_asprintf(parent, "%s/%s",
						       CM_DBUS_CA_PATH,
						       entry->cm_ca_name);
				cm_tdbusm_set_p(rep, path);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	talloc_free(parent);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_submitted_cookie(DBusConnection *conn, DBusMessage *msg,
			     struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (entry->cm_ca_cookie != NULL) {
				cm_tdbusm_set_s(rep, entry->cm_ca_cookie);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_submitted_date(DBusConnection *conn, DBusMessage *msg,
			   struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (entry->cm_submitted != 0) {
				cm_tdbusm_set_n(rep, entry->cm_submitted);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_modify(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx)
{
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_reenroll(DBusConnection *conn, DBusMessage *msg,
		 struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (cm_stop_one(ctx, entry->cm_id) == 0) {
				entry->cm_state = CM_NEED_CSR;
				if (cm_start_one(ctx, entry->cm_id) == 0) {
					cm_tdbusm_set_b(rep, TRUE);
				} else {
					cm_tdbusm_set_b(rep, FALSE);
				}
			} else {
				cm_tdbusm_set_b(rep, FALSE);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_rekey_and_submit(DBusConnection *conn, DBusMessage *msg,
			 struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (cm_stop_one(ctx, entry->cm_id) == 0) {
				entry->cm_state = CM_NEED_KEY_PAIR;
				if (cm_start_one(ctx, entry->cm_id) == 0) {
					cm_tdbusm_set_b(rep, TRUE);
				} else {
					cm_tdbusm_set_b(rep, FALSE);
				}
			} else {
				cm_tdbusm_set_b(rep, FALSE);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_resubmit(DBusConnection *conn, DBusMessage *msg,
		 struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			if (cm_stop_one(ctx, entry->cm_id) == 0) {
				entry->cm_state = CM_HAVE_CSR;
				if (cm_start_one(ctx, entry->cm_id) == 0) {
					cm_tdbusm_set_b(rep, TRUE);
				} else {
					cm_tdbusm_set_b(rep, FALSE);
				}
			} else {
				cm_tdbusm_set_b(rep, FALSE);
			}
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
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
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_submitted_cookie",
	 request_get_submitted_cookie},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_submitted_date",
	 request_get_submitted_date},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "modify",
	 request_modify},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "reenroll",
	 request_reenroll},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "rekey_and_submit",
	 request_rekey_and_submit},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "resubmit",
	 request_resubmit},
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
		if (!(*(cm_tdbush_methods[i].implements))(ctx, path,
							  interface, member)) {
			continue;
		}
		if (cm_tdbush_methods[i].handle == NULL) {
			continue;
		}
		return (*(cm_tdbush_methods[i].handle))(conn, msg, ctx);
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
