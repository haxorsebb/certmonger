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

#ifndef cmcsrgen_h
#define cmcsrgen_h

struct cm_csrgen_state;
struct cm_store_entry;

/* Start CSR generation using template information in the entry. */
struct cm_csrgen_state *cm_csrgen_start(struct cm_store_entry *entry);
struct cm_csrgen_state *cm_csrgen_n_start(struct cm_store_entry *entry);
struct cm_csrgen_state *cm_csrgen_o_start(struct cm_store_entry *entry);

/* Check if a CSR is ready. */
int cm_csrgen_ready(struct cm_store_entry *entry,
		    struct cm_csrgen_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_csrgen_get_fd(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state);

/* Check if we need a PIN (or a new PIN) to generate a CSR. */
int cm_csrgen_need_pin(struct cm_store_entry *entry,
		       struct cm_csrgen_state *state);

/* Check if we need the right token to be present to generate a CSR. */
int cm_csrgen_need_token(struct cm_store_entry *entry,
			 struct cm_csrgen_state *state);

/* Save the CSR to the entry. */
int cm_csrgen_save_csr(struct cm_store_entry *entry,
		       struct cm_csrgen_state *state);

/* Clean up after CSR generation. */
void cm_csrgen_done(struct cm_store_entry *entry,
		    struct cm_csrgen_state *state);

#endif
