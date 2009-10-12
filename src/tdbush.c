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

#define CM_DBUS_REQUEST_PATH CM_DBUS_BASE_PATH "/requests"
#define CM_DBUS_REQUEST_INTERFACE CM_DBUS_BASE_INTERFACE ".request"

/* Functions which tell us if, based on the path alone, there's an object of
 * the specified type with that path. */
static dbus_bool_t
is_base(struct cm_context *ctx, const char *path,
	const char *interface, const char *member)
{
	return (strcmp(path, CM_DBUS_BASE_PATH) == 0);
}
static dbus_bool_t
is_request(struct cm_context *ctx, const char *path,
	   const char *interface, const char *member)
{
	int initial;
	initial = strlen(CM_DBUS_REQUEST_PATH);
	return (strncmp(path, CM_DBUS_REQUEST_PATH, initial) == 0) &&
	       path[initial] == '/' &&
	       (cm_get_entry_by_id(ctx, path + initial + 1) != NULL);
}

/* Functions implemented for a specific object type. */
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
		if (cm_tdbusm_set_as(rep, (const char **) ret) == 0) {
			dbus_connection_send(conn, rep, NULL);
		}
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
		if (cm_tdbusm_set_as(rep, key_types) == 0) {
			dbus_connection_send(conn, rep, NULL);
		}
		dbus_message_unref(rep);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
base_get_supported_storage(DBusConnection *conn, DBusMessage *msg,
			   struct cm_context *ctx)
{
	const char *storage_types[] = {"NSSDB", "FILE", NULL};
	DBusMessage *rep;
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (cm_tdbusm_set_as(rep, storage_types) == 0) {
			dbus_connection_send(conn, rep, NULL);
		}
		dbus_message_unref(rep);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
request_get_monitoring(DBusConnection *conn, DBusMessage *msg,
		       struct cm_context *ctx)
{
	struct cm_store_entry *entry;
	dbus_bool_t b;
	DBusMessage *rep;
	entry = cm_get_entry_by_id(ctx,
				   dbus_message_get_path(msg) +
				   strlen(CM_DBUS_REQUEST_PATH) + 1);
	if (entry != NULL) {
		rep = dbus_message_new_method_return(msg);
		b = entry->cm_monitor;
		if (rep != NULL) {
			if (cm_tdbusm_set_b(rep, b) == 0) {
				dbus_connection_send(conn, rep, NULL);
			}
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
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_requests",
	 base_get_requests},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_supported_key_types",
	 base_get_supported_key_types},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_supported_key_storage",
	 base_get_supported_storage},
	{&is_base, CM_DBUS_BASE_INTERFACE, "get_supported_cert_storage",
	 base_get_supported_storage},
	{&is_request, CM_DBUS_REQUEST_INTERFACE, "get_monitoring",
	 request_get_monitoring},
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
