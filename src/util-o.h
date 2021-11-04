/*
 * Copyright (C) 2010,2012,2014,2015 Red Hat, Inc.
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

#ifndef utilo_h
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define utilo_h

struct cm_store_entry;

void util_o_init(void);
char *util_build_next_filename(const char *prefix, const char *marker);
char *util_build_old_filename(const char *prefix, const char *serial);
void util_set_fd_owner_perms(int fd, const char *filename,
			     const char *owner, mode_t perms);
void util_set_fd_entry_key_owner(int keyfd, const char *filename,
				 struct cm_store_entry *entry);
void util_set_fd_entry_cert_owner(int certfd, const char *filename,
				  struct cm_store_entry *entry);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int util_o_cert_cmp(const X509 *const *a, const X509 *const *b);
#else
int util_o_cert_cmp(const void *a, const void *b);
#endif

ASN1_BIT_STRING *util_ASN1_BIT_STRING_new(void);
ASN1_GENERALIZEDTIME *util_ASN1_GENERALIZEDTIME_new(void);
ASN1_IA5STRING *util_ASN1_IA5STRING_new(void);
ASN1_INTEGER *util_ASN1_INTEGER_new(void);
ASN1_OCTET_STRING *util_ASN1_OCTET_STRING_new(void);
int util_ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);
ASN1_PRINTABLESTRING *util_ASN1_PRINTABLESTRING_new(void);
const unsigned char *util_ASN1_STRING_get0_data(const ASN1_STRING *x);
int util_ASN1_STRING_length(const ASN1_STRING *x);
ASN1_STRING *util_ASN1_STRING_new(void);
ASN1_TIME *util_ASN1_TIME_dup(ASN1_TIME *t);
ASN1_TIME *util_ASN1_TIME_new(void);
ASN1_TIME *util_ASN1_TIME_set(ASN1_TIME *str, time_t t);
int util_EVP_PKEY_base_id(const EVP_PKEY *pkey);
int util_EVP_PKEY_id(const EVP_PKEY *pkey);
const unsigned char *util_OBJ_get0_data(const ASN1_OBJECT *obj);
size_t util_OBJ_length(const ASN1_OBJECT *obj);
ASN1_OBJECT *util_X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *a);
const ASN1_TIME *util_X509_get0_notAfter(X509 *x);
EVP_PKEY *util_X509_get0_pubkey(X509 *cert);
const ASN1_INTEGER *util_X509_get0_serialNumber(X509 *cert);
X509_NAME *util_X509_get0_issuer_name(X509 *x);
uint32_t util_X509_get_key_usage(X509 *x);
X509_NAME *util_X509_get0_subject_name(X509 *x);
EVP_PKEY *util_X509_REQ_get0_pubkey(X509_REQ *req);
void util_X509_REQ_get0_signature(const X509_REQ *req, const ASN1_BIT_STRING **psig, const X509_ALGOR **palg);
int util_X509_set_pubkey(X509 *cert, EVP_PKEY *pkey);
int util_X509_REQ_set_subject_name(X509_REQ *req, X509_NAME *name);
int util_X509_set1_notAfter(X509 *x, ASN1_TIME *tm);
int util_X509_set1_notBefore(X509 *x, ASN1_TIME *tm);
int util_X509_set_issuer_name(X509 *x, X509_NAME *name);
int util_X509_set_subject_name(X509 *x, X509_NAME *name);
int util_X509_set1_version(X509 *x, ASN1_INTEGER *version);
void util_NETSCAPE_SPKI_set_sig_alg(NETSCAPE_SPKI *spki, const X509_ALGOR *sig_alg);
EVP_PKEY *util_public_EVP_PKEY_dup(EVP_PKEY *pkey);
EVP_PKEY *util_private_EVP_PKEY_dup(EVP_PKEY *pkey);
int validate_pem(void *parent, const char *path);

#endif
