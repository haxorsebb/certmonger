/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#ifndef cmscepgen_h
#define cmscepgen_h

struct cm_scepgen_state;
struct cm_store_ca;
struct cm_store_entry;

/* Start SCEP request generation using template information in the entry. */
struct cm_scepgen_state *cm_scepgen_start(struct cm_store_ca *ca,
					  struct cm_store_entry *entry);
struct cm_scepgen_state *cm_scepgen_n_start(struct cm_store_ca *ca,
					    struct cm_store_entry *entry);
struct cm_scepgen_state *cm_scepgen_o_start(struct cm_store_ca *ca,
					    struct cm_store_entry *entry);

/* Check if SCEP request data is ready. */
int cm_scepgen_ready(struct cm_scepgen_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_scepgen_get_fd(struct cm_scepgen_state *state);

/* Check if we need a PIN (or a new PIN) to sign SCEP requests. */
int cm_scepgen_need_pin(struct cm_scepgen_state *state);

/* Check if we need the right token to be present to sign SCEP requests. */
int cm_scepgen_need_token(struct cm_scepgen_state *state);

/* Check if we need the server's certificates to encrypt SCEP requests. */
int cm_scepgen_need_encryption_certs(struct cm_scepgen_state *state);

/* Check if we need a different key type. */
int cm_scepgen_need_different_key_type(struct cm_scepgen_state *state);

/* Save the SCEP request data to the entry. */
int cm_scepgen_save_scep(struct cm_scepgen_state *state);

/* Clean up after SCEP request generation. */
void cm_scepgen_done(struct cm_scepgen_state *state);

#endif
