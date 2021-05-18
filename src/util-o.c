/*
 * Copyright (C) 2010,2015,2017 Red Hat, Inc.
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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <pwd.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "cm.h"
#include "log.h"
#include "store-int.h"
#include "util-o.h"

void
util_o_init(void)
{
#if OPENSSL_VERSION_MAJOR < 3
#if defined(HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS) && HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS
	OpenSSL_add_all_algorithms();
#elif defined(HAVE_DECL_OPENSSL_ADD_SSL_ALGORITHMS) && HAVE_DECL_OPENSSL_ADD_SSL_ALGORITHMS
	OpenSSL_add_ssl_algorithms();
#else
	SSL_library_init();
#endif
#endif
}

char *
util_build_next_filename(const char *prefix, const char *marker)
{
	size_t len;
	char *ret;

	len = strlen(prefix) + strlen(marker) + sizeof("%s.%s.key");
	ret = malloc(len + 1);
	if (ret != NULL) {
		snprintf(ret, len, "%s.%s.key", prefix, marker);
	}
	return ret;
}

char *
util_build_old_filename(const char *prefix, const char *serial)
{
	size_t len;
	char *ret;

	len = strlen(prefix) + strlen(serial) + sizeof("%s.%s.key");
	ret = malloc(len + 1);
	if (ret != NULL) {
		snprintf(ret, len, "%s.%s.key", prefix, serial);
	}
	return ret;
}

void
util_set_fd_owner_perms(int fd, const char *filename,
			const char *owner, mode_t perms)
{
	char *user, *group;
	struct passwd *pwd;
	struct group *grp;
	uid_t uid;
	gid_t gid;

	if (filename == NULL) {
		return;
	}
	if (owner != NULL) {
		user = strdup(owner);
		group = strchr(user, ':');
		if (group != NULL) {
			*group++ = '\0';
			if (strlen(group) == 0) {
				group = NULL;
			}
		}
		pwd = getpwnam(user);
		if (pwd == NULL) {
			cm_log(1, "Error looking up user \"%s\", "
			       "not setting ownership of \"%s\".\n",
			       user, filename);
		} else {
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			if (group != NULL) {
				grp = getgrnam(group);
				if (grp != NULL) {
					gid = grp->gr_gid;
				} else {
					cm_log(1, "Error looking up group "
					       "\"%s\", setting group of \"%s\""
					       " to primary group of \"%s\".\n",
					       group, filename, user);
				}
			}
			if (fchown(fd, uid, gid) == -1) {
				cm_log(1, "Error setting ownership on "
				       "file \"%s\": %s.  Continuing\n",
				       filename, strerror(errno));
			}
		}
		free(user);
	}
	if (perms != 0) {
		if (fchmod(fd, perms) == -1) {
			cm_log(1, "Error setting permissions on "
			       "file \"%s\": %s.  Continuing\n",
			       filename, strerror(errno));
		}
	}
}

void
util_set_fd_entry_key_owner(int keyfd, const char *filename,
			    struct cm_store_entry *entry)
{
	util_set_fd_owner_perms(keyfd, filename, entry->cm_key_owner,
				entry->cm_key_perms);
}

void
util_set_fd_entry_cert_owner(int certfd, const char *filename,
			     struct cm_store_entry *entry)
{
	util_set_fd_owner_perms(certfd, filename, entry->cm_cert_owner,
				entry->cm_cert_perms);
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int
util_o_cert_cmp(const X509 *const *a, const X509 *const *b)
{
	return X509_cmp(*a, *b);
}
#else
int
util_o_cert_cmp(const void *a, const void *b)
{
	X509 * const *x, * const *y;

	x = a;
	y = b;
	return X509_cmp(*x, *y);
}
#endif

ASN1_BIT_STRING *
util_ASN1_BIT_STRING_new(void)
{
#ifdef HAVE_ASN1_BIT_STRING_NEW
	return ASN1_BIT_STRING_new();
#else
	return M_ASN1_BIT_STRING_new();
#endif
}

ASN1_GENERALIZEDTIME *
util_ASN1_GENERALIZEDTIME_new(void)
{
#ifdef HAVE_ASN1_GENERALIZEDTIME_NEW
	return ASN1_GENERALIZEDTIME_new();
#else
	return M_ASN1_GENERALIZEDTIME_new();
#endif
}

ASN1_IA5STRING *
util_ASN1_IA5STRING_new(void)
{
#ifdef HAVE_ASN1_IA5STRING_NEW
	return ASN1_IA5STRING_new();
#else
	return M_ASN1_IA5STRING_new();
#endif
}

ASN1_INTEGER *
util_ASN1_INTEGER_new(void)
{
#ifdef HAVE_ASN1_INTEGER_NEW
	return ASN1_INTEGER_new();
#else
	return M_ASN1_INTEGER_new();
#endif
}

ASN1_OCTET_STRING *
util_ASN1_OCTET_STRING_new(void)
{
#ifdef HAVE_ASN1_OCTET_STRING_NEW
	return ASN1_OCTET_STRING_new();
#else
	return M_ASN1_OCTET_STRING_new();
#endif
}

int
util_ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data,
			   int len)
{
#ifdef HAVE_ASN1_OCTET_STRING_SET
	return ASN1_OCTET_STRING_set(str, data, len);
#else
	return M_ASN1_OCTET_STRING_set(str, data, len);
#endif
}

ASN1_PRINTABLESTRING *
util_ASN1_PRINTABLESTRING_new(void)
{
#ifdef HAVE_ASN1_PRINTABLESTRING_NEW
	return ASN1_PRINTABLESTRING_new();
#else
	return M_ASN1_PRINTABLESTRING_new();
#endif
}

const unsigned char *
util_ASN1_STRING_get0_data(const ASN1_STRING *x)
{
#ifdef HAVE_ASN1_STRING_GET0_DATA
	return ASN1_STRING_get0_data(x);
#elif defined(HAVE_ASN1_STRING_GET_DATA)
	return ASN1_STRING_get_data(x);
#else
	return M_ASN1_STRING_data(x);
#endif
}

int
util_ASN1_STRING_length(const ASN1_STRING *x)
{
#ifdef HAVE_ASN1_STRING_LENGTH
	return ASN1_STRING_length(x);
#else
	return M_ASN1_STRING_length(x);
#endif
}

ASN1_STRING *
util_ASN1_STRING_new(void)
{
#ifdef HAVE_ASN1_STRING_NEW
	return ASN1_STRING_new();
#else
	return M_ASN1_STRING_new();
#endif
}

ASN1_TIME *
util_ASN1_TIME_dup(ASN1_TIME *t)
{
	unsigned char *p, *pp;
	const unsigned char *cp;
	long len;

	len = i2d_ASN1_TIME(t, NULL);
	p = malloc(len);
	if (p != NULL) {
		pp = p;
		if (i2d_ASN1_TIME(t, &pp) < 0) {
			free(p);
			return NULL;
		}
		cp = p;
		t = d2i_ASN1_TIME(NULL, &cp, len);
		if (cp - p != len) {
			t = NULL;
		}
		free(p);
		return t;
	}
	return NULL;
}

ASN1_TIME *
util_ASN1_TIME_new(void)
{
#ifdef HAVE_ASN1_TIME_NEW
	return ASN1_TIME_new();
#else
	return M_ASN1_TIME_new();
#endif
}

ASN1_TIME *
util_ASN1_TIME_set(ASN1_TIME *str, time_t t)
{
#ifdef HAVE_ASN1_TIME_SET
	return ASN1_TIME_set(str, t);
#else
	return M_ASN1_TIME_set(str, t);
#endif
}

int
util_EVP_PKEY_id(const EVP_PKEY *pkey)
{
#if defined(HAVE_EVP_PKEY_ID) || defined(HAVE_EVP_PKEY_GET_ID)
	return EVP_PKEY_id(pkey);
#else
	return pkey->type;
#endif
}

int
util_EVP_PKEY_base_id(const EVP_PKEY *pkey)
{
#ifdef HAVE_EVP_PKEY_BASE_ID
	return EVP_PKEY_base_id(pkey);
#else
	return EVP_PKEY_type(util_EVP_PKEY_id(pkey));
#endif
}

const unsigned char *
util_OBJ_get0_data(const ASN1_OBJECT *obj)
{
#ifdef HAVE_OBJ_GET0_DATA
	return OBJ_get0_data(obj);
#else
	return obj->data;
#endif
}

size_t
util_OBJ_length(const ASN1_OBJECT *obj)
{
#ifdef HAVE_OBJ_LENGTH
	return OBJ_length(obj);
#else
	return obj->length;
#endif
}

ASN1_OBJECT *
util_X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *a)
{
#ifdef HAVE_X509_ATTRIBUTE_GET0_OBJECT
	return X509_ATTRIBUTE_get0_object(a);
#else
	return a->object;
#endif
}

const ASN1_TIME *
util_X509_get0_notAfter(X509 *x)
{
#ifdef HAVE_X509_GET0_NOTAFTER
	return X509_get0_notAfter(x);
#else
	return x->cert_info->validity->notAfter;
#endif
}

EVP_PKEY *
util_X509_get0_pubkey(X509 *cert)
{
#ifdef HAVE_X509_GET0_PUBKEY
	return X509_get0_pubkey(cert);
#else
	return X509_PUBKEY_get(cert->cert_info->key);
#endif
}

const ASN1_INTEGER *
util_X509_get0_serialNumber(X509 *cert)
{
#ifdef HAVE_X509_GET0_SERIALNUMBER
	return X509_get0_serialNumber(cert);
#else
	return cert->cert_info->serialNumber;
#endif
}

X509_NAME *
util_X509_get0_issuer_name(X509 *x)
{
#ifdef HAVE_X509_GET_ISSUER_NAME
	return X509_get_issuer_name(x);
#else
	return x->cert_info->issuer;
#endif
}

uint32_t
util_X509_get_key_usage(X509 *x)
{
#ifdef HAVE_X509_GET_KEY_USAGE
	return X509_get_key_usage(x);
#else
	/* Call for side-effect of computing hash and caching extensions */
	X509_check_purpose(x, -1, -1);
	return x->ex_kusage;
#endif
}

X509_NAME *
util_X509_get0_subject_name(X509 *x)
{
#ifdef HAVE_X509_GET_SUBJECT_NAME
	return X509_get_subject_name(x);
#else
	return x->cert_info->subject;
#endif
}

EVP_PKEY *
util_X509_REQ_get0_pubkey(X509_REQ *req)
{
#ifdef HAVE_X509_REQ_GET0_PUBKEY
	return X509_REQ_get0_pubkey(req);
#else
	return X509_PUBKEY_get(req->req_info->pubkey);
#endif
}

void
util_X509_REQ_get0_signature(const X509_REQ *req, const ASN1_BIT_STRING **psig,
			     const X509_ALGOR **palg)
{
#ifdef HAVE_X509_REQ_GET0_SIGNATURE
	X509_REQ_get0_signature(req, psig, palg);
#else
	if (psig != NULL) {
		*psig = req->signature;
	}
	if (palg != NULL) {
		*palg = req->sig_alg;
	}
#endif
}

int
util_X509_set_pubkey(X509 *cert, EVP_PKEY *pkey)
{
	return X509_set_pubkey(cert, pkey);
}

int
util_X509_REQ_set_subject_name(X509_REQ *req, X509_NAME *name)
{
#ifdef HAVE_X509_REQ_SET_SUBJECT_NAME
	return X509_REQ_set_subject_name(req, name);
#else
	return X509_NAME_set(&req->req_info->subject, name);
#endif
}

int
util_X509_set1_notAfter(X509 *x, ASN1_TIME *tm)
{
#ifdef HAVE_X509_SET1_NOTAFTER
	return X509_set1_notAfter(x, tm);
#else
	if (x != NULL) {
		x->cert_info->validity->notAfter = tm;
		return 1;
	}
	return 0;
#endif
}

int
util_X509_set1_notBefore(X509 *x, ASN1_TIME *tm)
{
#ifdef HAVE_X509_SET1_NOTBEFORE
	return X509_set1_notBefore(x, tm);
#else
	if (x != NULL) {
		x->cert_info->validity->notBefore = tm;
		return 1;
	}
	return 0;
#endif
}

int
util_X509_set_issuer_name(X509 *x, X509_NAME *name)
{
#ifdef HAVE_X509_SET_ISSUER_NAME
	return X509_set_issuer_name(x, name);
#else
	return X509_NAME_set(&x->cert_info->issuer, name);
#endif
}

int
util_X509_set_subject_name(X509 *x, X509_NAME *name)
{
#ifdef HAVE_X509_SET_SUBJECT_NAME
	return X509_set_subject_name(x, name);
#else
	return X509_NAME_set(&x->cert_info->subject, name);
#endif
}

int
util_X509_set1_version(X509 *x, ASN1_INTEGER *version)
{
#ifdef HAVE_X509_CERT_INFO
	x->cert_info->version = ASN1_INTEGER_dup(version);
	return x->cert_info->version != NULL;
#else
	return X509_set_version(x, ASN1_INTEGER_get(version));
#endif
}

void
util_NETSCAPE_SPKI_set_sig_alg(NETSCAPE_SPKI *spki, const X509_ALGOR *sig_alg)
{
#ifdef CM_NETSCAPE_SPKI_SIG_ALGOR_IS_POINTER
	spki->sig_algor = X509_ALGOR_dup((X509_ALGOR *)sig_alg);
#else
	spki->sig_algor = *X509_ALGOR_dup((X509_ALGOR *)sig_alg);
#endif
}

static EVP_PKEY *
util_EVP_PKEY_dup(EVP_PKEY *pkey,
		  int (*i2d)(EVP_PKEY *, unsigned char **),
		  EVP_PKEY *(*d2i)(int, EVP_PKEY **, const unsigned char **, long))
{
	EVP_PKEY *k;
	unsigned char *p, *q;
	const unsigned char *d;
	int l, len;

	l = i2d(pkey, NULL);
	if (l < 0) {
		cm_log(1, "Error determining size of key.");
		return NULL;
	}
	p = q = malloc(l);
	if (p == NULL) {
		cm_log(1, "Out of memory copying key.");
		return NULL;
	}
	len = i2d(pkey, &q);
	if (len != l) {
		cm_log(1, "Unexpected error copying key.");
		memset(p, 0, l);
		free(p);
		return NULL;
	}
	d = p;
	k = d2i(util_EVP_PKEY_base_id(pkey), NULL, &d, len);
	memset(p, 0, l);
	free(p);
	if (k == NULL) {
		cm_log(1, "Unexpected error decoding copy of key.");
		return NULL;
	}
	return k;
}

EVP_PKEY *
util_public_EVP_PKEY_dup(EVP_PKEY *pkey)
{
	return util_EVP_PKEY_dup(pkey, i2d_PublicKey, d2i_PublicKey);
}

EVP_PKEY *
util_private_EVP_PKEY_dup(EVP_PKEY *pkey)
{
	return util_EVP_PKEY_dup(pkey, i2d_PrivateKey, d2i_PrivateKey);
}
