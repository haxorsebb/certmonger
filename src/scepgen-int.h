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

#ifndef cmscepgenint_h
#define cmscepgenint_h

struct cm_scepgen_state_pvt {
	/* Check if the SCEP request data is ready. */
	int (*ready)(struct cm_scepgen_state *state);
	/* Get a selectable-for-read descriptor which will either have data or
	 * be closed when status changes. */
	int (*get_fd)(struct cm_scepgen_state *state);
	/* Save the SCEP data to the entry. */
	int (*save_scep)(struct cm_scepgen_state *state);
	/* Check if we need a PIN (or a new PIN) to get at the key material. */
	int (*need_pin)(struct cm_scepgen_state *state);
	/* Check if we need the token to be inserted to get at the key
	 * material. */
	int (*need_token)(struct cm_scepgen_state *state);
	/* Check if we need the server's encryption certs in order to be able
	 * to generate request data. */
	int (*need_encryption_certs)(struct cm_scepgen_state *state);
	/* Check if we need a different key type, because SCEP only works with
	 * RSA keys. */
	int (*need_different_key_type)(struct cm_scepgen_state *state);
	/* Clean up after SCEP request generation. */
	void (*done)(struct cm_scepgen_state *state);
};

void cm_scepgen_o_cooked(struct cm_store_ca *ca, struct cm_store_entry *entry,
			 unsigned char *nonce, size_t nonce_length,
			 EVP_PKEY *old_pkey, EVP_PKEY *new_pkey,
			 PKCS7 **csr_new, PKCS7 **csr_old,
			 PKCS7 **ias_new, PKCS7 **ias_old);
char *cm_scepgen_o_b64_from_p7(void *parent, PKCS7 *p7);

#endif
