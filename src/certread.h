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

#ifndef cmcertread_h
#define cmcertread_h

struct cm_certread_state;
struct cm_store_entry;

/* Start refreshing the certificate and associated data from the entry from the
 * configured location. */
struct cm_certread_state *cm_certread_start(struct cm_store_entry *entry);
struct cm_certread_state *cm_certread_n_start(struct cm_store_entry *entry);
struct cm_certread_state *cm_certread_o_start(struct cm_store_entry *entry);
/* Check if something changed, for example we finished reading the cert. */
int cm_certread_ready(struct cm_certread_state *state);
/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_certread_get_fd(struct cm_certread_state *state);
/* Clean up after reading the certificate. */
void cm_certread_done(struct cm_certread_state *state);

#endif
