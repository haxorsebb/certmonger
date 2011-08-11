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

#ifndef cmkeygen_h
#define cmkeygen_h

struct cm_keygen_state;
struct cm_store_entry;

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *cm_keygen_start(struct cm_store_entry *entry);
struct cm_keygen_state *cm_keygen_n_start(struct cm_store_entry *entry);
struct cm_keygen_state *cm_keygen_o_start(struct cm_store_entry *entry);

/* Check if the keypair is ready. */
int cm_keygen_ready(struct cm_store_entry *entry,
		    struct cm_keygen_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_keygen_get_fd(struct cm_store_entry *entry,
		     struct cm_keygen_state *state);

/* Check if we need a PIN (or a new PIN) to generate a key pair. */
int cm_keygen_need_pin(struct cm_store_entry *entry,
		       struct cm_keygen_state *state);

/* Check if we need the right token to be present to generate a key pair. */
int cm_keygen_need_token(struct cm_store_entry *entry,
			 struct cm_keygen_state *state);

/* Tell us if the keypair was saved to the location specified in the entry. */
int cm_keygen_saved_keypair(struct cm_store_entry *entry,
			    struct cm_keygen_state *state);

/* Clean up after key generation. */
void cm_keygen_done(struct cm_store_entry *entry,
		    struct cm_keygen_state *state);

#endif
