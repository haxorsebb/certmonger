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

#ifndef cmkeyiread_h
#define cmkeyiread_h

struct cm_keyiread_state;
struct cm_store_entry;

/* Check if we have a key in the designated location, and report the algorithm
 * and key size. */
struct cm_keyiread_state *cm_keyiread_start(struct cm_store_entry *entry);
struct cm_keyiread_state *cm_keyiread_n_start(struct cm_store_entry *entry);
struct cm_keyiread_state *cm_keyiread_o_start(struct cm_store_entry *entry);
/* Check if something changed, for example we finished reading the key info. */
int cm_keyiread_ready(struct cm_store_entry *entry,
		      struct cm_keyiread_state *state);
/* Check if we were able to read the information. */
int cm_keyiread_finished_reading(struct cm_store_entry *entry,
				 struct cm_keyiread_state *state);
/* Check if we need to supply a PIN (or a new PIN) to try again. */
int cm_keyiread_need_pin(struct cm_store_entry *entry,
			 struct cm_keyiread_state *state);
/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_keyiread_get_fd(struct cm_store_entry *entry,
		       struct cm_keyiread_state *state);
/* Check if we need the token to be inserted to read information about the key. */
int cm_keyiread_need_token(struct cm_store_entry *entry,
			   struct cm_keyiread_state *state);
/* Clean up after reading the key info. */
void cm_keyiread_done(struct cm_store_entry *entry,
		      struct cm_keyiread_state *state);

#endif
