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

#ifndef cmkeygenint_h
#define cmkeygenint_h

struct cm_keygen_state_pvt {
	/* Check if the keypair is ready. */
	int (*ready)(struct cm_store_entry *entry,
		     struct cm_keygen_state *state);
	/* Get a selectable-for-read descriptor we can poll for status changes.
	 */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_keygen_state *state);
	/* Tell us if the keypair was saved to the right location. */
	int (*saved_keypair)(struct cm_store_entry *entry,
			     struct cm_keygen_state *state);
	/* Tell us if we need a PIN (or a new PIN) to access the key store. */
	int (*need_pin)(struct cm_store_entry *entry,
			struct cm_keygen_state *state);
	/* Tell us if we need a token to be inserted to access the key store. */
	int (*need_token)(struct cm_store_entry *entry,
			  struct cm_keygen_state *state);
	/* Clean up after key generation. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_keygen_state *state);
};

#endif
