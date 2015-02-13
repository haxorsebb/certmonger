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

#ifndef cmpkcs7_h
#define cmpkcs7_h

#define CM_PKCS7_LEAF_PREFER_ENCRYPT (1 << 0)
int cm_pkcs7_parsev(unsigned int flags, void *parent,
		    char **certleaf, char **certtop, char ***certothers,
		    int n_buffers,
		    const unsigned char **buffers, size_t *lengths);
int cm_pkcs7_parse(unsigned int flags, void *parent,
		   char **certleaf, char **certtop, char ***certothers,
		   const unsigned char *buffer, size_t length, ...);

int cm_pkcs7_envelope_data(char *encryption_cert,
			   unsigned char *data, size_t dlength,
			   unsigned char **enveloped, size_t *length);
int cm_pkcs7_envelope_csr(char *encryption_cert, char *csr,
			  unsigned char **enveloped, size_t *length);
int cm_pkcs7_generate_ias(char *cacert, char *minicert,
			  unsigned char **ias, size_t *length);
int cm_pkcs7_envelope_ias(char *encryption_cert, char *cacert, char *minicert,
			  unsigned char **enveloped, size_t *length);
int cm_pkcs7_verify_signed(unsigned char *data, size_t length,
			   const char **roots, const char **othercerts,
			   int expected_content_type,
			   void *parent,
			   char **tx, char **msgtype,
			   char **pkistatus, char **failinfo,
			   unsigned char **sender_nonce,
			   size_t *sender_nonce_length,
			   unsigned char **recipient_nonce,
			   size_t *recipient_nonce_length,
			   unsigned char **payload, size_t *payload_length);


#endif
