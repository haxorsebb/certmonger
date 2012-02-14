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

#ifndef cmtdbush_h
#define cmtdbush_h

struct cm_context;
DBusHandlerResult cm_tdbush_handle(DBusConnection *conn, DBusMessage *msg,
				   struct cm_context *ctx);
struct cm_context;
DBusHandlerResult cm_tdbush_handle_method_call(DBusConnection *conn,
					       DBusMessage *msg,
					       struct cm_context *ctx);
struct cm_context;
DBusHandlerResult cm_tdbush_handle_method_return(DBusConnection *conn,
						 DBusMessage *msg,
						 struct cm_context *ctx);
void cm_tdbush_property_emit_entry_changes(struct cm_context *ctx,
					   struct cm_store_entry *old_entry,
					   struct cm_store_entry *new_entry);
DBusHandlerResult cm_tdbush_property_emit_changed(struct cm_context *ctx,
						  const char *path,
						  const char *interface,
						  const char **properties);
void cm_tdbush_property_emit_entry_saved_cert(struct cm_context *ctx,
					      struct cm_store_entry *entry);
char *cm_tdbush_canonicalize_directory(void *parent, const char *path);

#endif
