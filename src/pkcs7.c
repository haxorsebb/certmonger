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

#include "config.h"

#include <sys/types.h>
#include <unistd.h>

#include <krb5.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <talloc.h>

#include "log.h"
#include "pkcs7.h"
#include "store.h"
#include "submit-u.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

/* Return 0 if we think "issuer" could have issued "issued". */
static int
issuerissued(X509 *issuer, X509 *issued)
{
	GENERAL_NAME *gn;
	int i;

	if ((issuer->skid != NULL) &&
	    (issued->akid != NULL) &&
	    (issued->akid->keyid != NULL)) {
		if (M_ASN1_OCTET_STRING_cmp(issuer->skid,
					    issued->akid->keyid) == 0) {
			return 0;
		}
	}
	if ((issued->akid != NULL) &&
	    (issued->akid->issuer != NULL) &&
	    (issued->akid->serial != NULL)) {
		for (i = 0;
		     i < sk_GENERAL_NAME_num(issued->akid->issuer);
		     i++) {
			gn = sk_GENERAL_NAME_value(issued->akid->issuer, i);
			if ((gn->type == GEN_DIRNAME) &&
			    (X509_NAME_cmp(issuer->cert_info->issuer,
					   gn->d.dirn) == 0) &&
			    (M_ASN1_INTEGER_cmp(issuer->cert_info->serialNumber,
						issued->akid->serial) == 0)) {
				return 0;
			}
		}
	}
	return X509_name_cmp(issuer->cert_info->subject,
			     issued->cert_info->issuer);
}

/* Render the certificate as a PEM string. */
static char *
pemx509(void *parent, X509 *x)
{
	char *b64, *pem, *ret;
	unsigned char *der, *p;
	ssize_t length;

	length = i2d_X509(x, NULL);
	if (length < 0) {
		return NULL;
	}
	der = talloc_size(parent, length);
	if (der == NULL) {
		return NULL;
	}
	p = (unsigned char *) der;
	if (i2d_X509(x, &p) < 0) {
		return NULL;
	}
	b64 = cm_store_base64_from_bin(parent, der, length);
	if (b64 == NULL) {
		return NULL;
	}
	pem = cm_submit_u_pem_from_base64("CERTIFICATE", 0, b64);
	if (pem == NULL) {
		return NULL;
	}
	ret = talloc_strdup(parent, pem);
	free(pem);
	return ret;
}

/* Wrap the comparison function to handle the callback indirection. */
static int
cert_cmp(const void *a, const void *b)
{
	X509 * const *x, * const *y;
	x = a;
	y = b;
	return X509_cmp(*x, *y);
}

/* Return 0 if "candidate" is more like what we're looking for than "current". */
static int
betterleaf(X509 *candidate, X509 *current, unsigned int flags)
{
	if (flags & CM_PKCS7_LEAF_PREFER_ENCRYPT) {
		if (((candidate->ex_kusage & (KU_KEY_ENCIPHERMENT | KU_DATA_ENCIPHERMENT)) != 0) &&
		    ((current->ex_kusage & (KU_KEY_ENCIPHERMENT | KU_DATA_ENCIPHERMENT)) == 0)) {
			return 0;
		}
	}
	return -1;
}
static int
bettertop(X509 *candidate, X509 *current, unsigned int flags)
{
	return -1;
}

/* Given either a single certificate or a PKCS#7 signed-data message, pull out
 * the end-entity certificate and, if there is one, the top-level certificate,
 * and if there are any others, any others. */
int
cm_pkcs7_parse(const unsigned char *buffer, size_t length, unsigned int flags,
	       void *parent,
	       char **certleaf, char **certtop, char ***certothers)
{
	PKCS7 *p7 = NULL;
	X509 *x = NULL, *a, *b;
	STACK_OF(X509) *sk;
	const unsigned char *p;
	char *cleaf = NULL, *ctop = NULL, **cothers = NULL;
	int leaf, top, n_certs, i, j;

	if (certleaf != NULL) {
		*certleaf = NULL;
	}
	if (certothers != NULL) {
		*certothers = NULL;
	}
	if (certtop != NULL) {
		*certtop = NULL;
	}

	sk = sk_X509_new(cert_cmp);
	if (sk == NULL) {
		return -1;
	}
	/* First, try to parse as a PKCS#7 signed data item. */
	p = buffer;
	p7 = d2i_PKCS7(NULL, &p, length);
	if (p7 != NULL) {
		/* Is it a signed-data item? */
		if (PKCS7_type_is_signed(p7)) {
			for (i = 0;
			     i < sk_X509_num(p7->d.sign->cert);
			     i++) {
				x = sk_X509_value(p7->d.sign->cert, i);
				if (sk_X509_find(sk, x) < 0) {
					sk_X509_push(sk, X509_dup(x));
				}
			}
		}
		PKCS7_free(p7);
	} else {
		/* Not PKCS#7?  Try to parse as a plain certificate. */
		p = buffer;
		x = d2i_X509(NULL, &p, length);
		if (x != NULL) {
			if (sk_X509_find(sk, x) < 0) {
				sk_X509_push(sk, X509_dup(x));
			}
		}
		X509_free(x);
	}
	/* Count the number of certificates. */
	n_certs = sk_X509_num(sk);
	/* Find one that didn't issue any of the others. */
	leaf = -1;
	for (i = 0; i < n_certs; i++) {
		a = sk_X509_value(sk, i);
		for (j = 0; j < n_certs; j++) {
			if (j == i) {
				continue;
			}
			b = sk_X509_value(sk, j);
			if (issuerissued(a, b) == 0) {
				break;
			}
		}
		if (j == sk_X509_num(sk)) {
			if (leaf == -1) {
				leaf = i;
			} else {
				if (betterleaf(a,
					       sk_X509_value(sk, leaf),
					       flags) == 0) {
					leaf = i;
				}
			}
		}
	}
	/* Find one that isn't issued by any of the others. */
	top = -1;
	for (i = 0; i < n_certs; i++) {
		a = sk_X509_value(sk, i);
		for (j = 0; j < n_certs; j++) {
			if (j == i) {
				continue;
			}
			b = sk_X509_value(sk, j);
			if (issuerissued(b, a) == 0) {
				break;
			}
		}
		if (j == sk_X509_num(sk)) {
			if (top == -1) {
				top = i;
			} else {
				if (bettertop(a,
					      sk_X509_value(sk, top),
					      flags) == 0) {
					top = i;
				}
			}
		}
	}
	/* Set the output values. */
	if (leaf != -1) {
		cleaf = pemx509(parent, sk_X509_value(sk, leaf));
		n_certs--;
	}
	if ((top != -1) && (top != leaf)) {
		ctop = pemx509(parent, sk_X509_value(sk, top));
		n_certs--;
	}
	if (n_certs > 0) {
		cothers = talloc_array_ptrtype(parent, *certothers,
					       n_certs + 1);
		if (cothers != NULL) {
			for (i = 0, j = 0; i < sk_X509_num(sk); i++) {
				if ((i != leaf) && (i != top)) {
					cothers[j++] = pemx509(parent,
							       sk_X509_value(sk, i));
				}
			}
			cothers[j] = NULL;
		}
	}
	/* Clean up. */
	if (certleaf != NULL) {
		*certleaf = cleaf;
	}
	if (certothers != NULL) {
		*certothers = cothers;
	}
	if (certtop != NULL) {
		*certtop = ctop;
	}
	while ((x = sk_X509_pop(sk)) != NULL) {
		X509_free(x);
	}
	sk_X509_free(sk);
	return 0;
}
