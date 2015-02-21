/*
 * Copyright (C) 2009,2011,2012,2014 Red Hat, Inc.
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

#ifndef cmcm_h
#define cmcm_h

struct cm_context;
struct cm_store_entry;
struct cm_store_ca;
struct tevent_context;
enum cm_ca_phase;

int cm_init(struct tevent_context *parent, struct cm_context **context,
	    int idle_timeout, const char *gate_command);
int cm_start_all(struct cm_context *context);
void cm_reset_timeout(struct cm_context *context);
int cm_keep_going(struct cm_context *context);
void cm_stop_all(struct cm_context *context);

int cm_get_n_entries(struct cm_context *context);
struct cm_store_entry *cm_get_entry_by_index(struct cm_context *c, int i);
struct cm_store_entry *cm_get_entry_by_nickname(struct cm_context *c,
						const char *nickname);
struct cm_store_entry *cm_get_entry_by_busname(struct cm_context *c,
					       const char *busname);
int cm_add_entry(struct cm_context *context, struct cm_store_entry *new_entry);
int cm_remove_entry(struct cm_context *context, const char *nickname);
int cm_get_n_cas(struct cm_context *context);
struct cm_store_ca *cm_get_ca_by_index(struct cm_context *c, int i);
struct cm_store_ca *cm_get_ca_by_nickname(struct cm_context *c,
					  const char *nickname);
struct cm_store_ca *cm_get_ca_by_busname(struct cm_context *c,
				         const char *busname);
int cm_add_ca(struct cm_context *context, struct cm_store_ca *new_ca);
int cm_remove_ca(struct cm_context *context, const char *nickname);
dbus_bool_t cm_restart_entry(struct cm_context *c, const char *nickname);
dbus_bool_t cm_restart_entries_by_ca(struct cm_context *c,
				     const char *nickname);
dbus_bool_t cm_stop_entry(struct cm_context *c, const char *nickname);
dbus_bool_t cm_start_entry(struct cm_context *c, const char *nickname);
dbus_bool_t cm_restart_ca(struct cm_context *c, const char *nickname,
		          enum cm_ca_phase);
dbus_bool_t cm_stop_ca(struct cm_context *c, const char *nickname,
		       enum cm_ca_phase);
dbus_bool_t cm_start_ca(struct cm_context *c, const char *nickname,
		        enum cm_ca_phase);

void *cm_get_conn_ptr(struct cm_context *context);
void cm_set_conn_ptr(struct cm_context *context, void *ptr);
const char *cm_get_server_address(struct cm_context *context);
void cm_set_server_address(struct cm_context *context, const char *address);

#endif
