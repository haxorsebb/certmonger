/*
 * Copyright (C) 2012,2014 Red Hat, Inc.
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

#ifndef cmhook_h
#define cmhook_h

struct cm_hook_state;
struct cm_store_entry;
struct cm_store_ca;
struct cm_context;

/* Start doing whatever we need to before saving the certificate to the
 * configured location. */
struct cm_hook_state *cm_hook_start_presave(struct cm_store_entry *entry,
					    struct cm_context *context,
					    struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
					    int (*get_n_cas)(struct cm_context *),
					    struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
					    int (*get_n_entries)(struct cm_context *));
struct cm_hook_state *cm_hook_start_ca_presave(struct cm_store_ca *ca,
					       struct cm_context *context,
					       struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
					       int (*get_n_cas)(struct cm_context *),
					       struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
					       int (*get_n_entries)(struct cm_context *));

/* Start doing whatever we need to after saving the certificate to the
 * configured location. */
struct cm_hook_state *cm_hook_start_postsave(struct cm_store_entry *entry,
					     struct cm_context *context,
					     struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
					     int (*get_n_cas)(struct cm_context *),
					     struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
					     int (*get_n_entries)(struct cm_context *));
struct cm_hook_state *cm_hook_start_ca_postsave(struct cm_store_ca *ca,
						struct cm_context *context,
						struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
						int (*get_n_cas)(struct cm_context *),
						struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
						int (*get_n_entries)(struct cm_context *));

/* Check if something changed, for example we finished doing whatever it is
 * that we're doing. */
int cm_hook_ready(struct cm_hook_state *state);

/* Get a selectable-for-read descriptor which will either have data or be
 * closed when status changes. */
int cm_hook_get_fd(struct cm_hook_state *state);

/* Clean up after ourselves. */
void cm_hook_done(struct cm_hook_state *state);

#endif
