/*
 * Copyright (C) 2014 Red Hat, Inc.
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

#ifndef cmcasave_h
#define cmcasave_h

struct cm_context;
struct cm_store_entry;
struct cm_store_ca;
struct cm_casave_state;

/* Start saving the certificates of the entry's CA. */
struct cm_casave_state *cm_casave_start(struct cm_store_entry *entry,
					struct cm_store_ca *ca,
					struct cm_context *cm,
					struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
					int (*get_n_cas)(struct cm_context *),
					struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
					int (*get_n_entries)(struct cm_context *));

/* Check if something changed, for example we finished saving certs. */
int cm_casave_ready(struct cm_casave_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_casave_get_fd(struct cm_casave_state *state);

/* Check if we saved the certificate. */
int cm_casave_saved(struct cm_casave_state *state);

/* Check if we failed due to a subject name conflict. */
int cm_casave_conflict_subject(struct cm_casave_state *state);

/* Check if we failed due to a nickname conflict. */
int cm_casave_conflict_nickname(struct cm_casave_state *state);

/* Check if we failed due to a permissions error. */
int cm_casave_permissions_error(struct cm_casave_state *state);

/* Clean up after saving the certificate. */
void cm_casave_done(struct cm_casave_state *state);

#endif
