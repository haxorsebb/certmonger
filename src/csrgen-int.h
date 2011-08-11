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

#ifndef cmcsrgenint_h
#define cmcsrgenint_h

struct cm_csrgen_state_pvt {
	/* Check if a CSR is ready. */
	int (*ready)(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state);
	/* Get a selectable-for-read descriptor we can poll for status changes.
	 */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_csrgen_state *state);
	/* Save the CSR to the entry. */
	int (*save_csr)(struct cm_store_entry *entry,
		        struct cm_csrgen_state *state);
	/* Check if we need a PIN (or a new PIN) to get at the key material. */
	int (*need_pin)(struct cm_store_entry *entry,
		        struct cm_csrgen_state *state);
	/* Check if we need the token to be inserted to get at the key
	 * material. */
	int (*need_token)(struct cm_store_entry *entry,
			  struct cm_csrgen_state *state);
	/* Clean up after CSR generation. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state);
};

#endif
