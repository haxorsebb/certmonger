/*
 * Copyright (C) 2009,2014 Red Hat, Inc.
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

#ifndef cmsubmitint_h
#define cmsubmitint_h

struct cm_store_entry;
struct cm_submit_state {
	/* The parent usually needs a pointer to the entry for updating. */
	struct cm_store_entry *entry;
	/* The parent uses this to manage the subprocess that's doing the heavy
	 * lifting. */
	struct cm_subproc_state *subproc;
	/* Check if the CSR was submitted to the CA yet, or we determined that
	 * doing so was not possible at this time. */
	int (*ready)(struct cm_submit_state *state);
	/* Save CA-specific identifier for our submitted request. */
	int (*save_ca_cookie)(struct cm_submit_state *state);
	/* Check if the certificate was issued. */
	int (*issued)(struct cm_submit_state *state);
	/* Check if the certificate request was rejected. */
	int (*rejected)(struct cm_submit_state *state);
	/* Check if we need SCEP-specific data to be provided. */
	int (*need_scep_messages)(struct cm_submit_state *state);
	/* Check if we need to try again with different keys. */
	int (*need_rekey)(struct cm_submit_state *state);
	/* Check if the CA was unreachable for some reason. */
	int (*unreachable)(struct cm_submit_state *state);
	/* Check if the CA was unconfigured in some way. */
	int (*unconfigured)(struct cm_submit_state *state);
	/* Check if we can't submit requests to the CA. */
	int (*unsupported)(struct cm_submit_state *state);
	/* Done talking to the CA. */
	void (*done)(struct cm_submit_state *state);
	/* Recommended delay before the next connection to the CA. */
	int delay;
	/* Reserved for implementation use.  Currently only used by the
	 * "external" submission implementations. */
	void *reserved;
};

struct cm_submit_state *cm_submit_e_start(struct cm_store_ca *ca,
					  struct cm_store_entry *entry);
struct cm_submit_state *cm_submit_sn_start(struct cm_store_ca *ca,
					   struct cm_store_entry *entry);
struct cm_submit_state *cm_submit_so_start(struct cm_store_ca *ca,
					   struct cm_store_entry *entry);

#define CM_BASIC_CONSTRAINT_NOT_CA "3000"
char *cm_submit_maybe_joinv(void *parent, const char *sep, char **s);

struct cm_submit_decrypt_envelope_args {
	struct cm_store_ca *ca;
	struct cm_store_entry *entry;
};
void cm_submit_o_decrypt_envelope(const unsigned char *envelope,
				  size_t length,
				  void *decrypt_userdata,
				  unsigned char **payload,
				  size_t *payload_length);
void cm_submit_n_decrypt_envelope(const unsigned char *envelope,
				  size_t length,
				  void *decrypt_userdata,
				  unsigned char **payload,
				  size_t *payload_length);

#endif
