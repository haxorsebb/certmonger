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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <krb5.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <nss.h>
#include <secasn1.h>
#include <secitem.h>

#include <talloc.h>

#include "log.h"
#include "pkcs7.h"
#include "prefs-o.h"
#include "store.h"
#include "submit-u.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

/* Return 0 if we think "issuer" could have issued "issued", which includes
 * self-signing. */
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
static void cm_pkcs7_parse_buffer(const unsigned char *buffer,
				  size_t length, STACK_OF(X509) *sk);
static void
cm_pkcs7_parse_pem(const char *pem, size_t length,
		   STACK_OF(X509) *sk)
{
	const char *p, *q;
	unsigned char *buf;
	size_t len;
	int decoded;

	if (strncmp(pem, "-----BEGIN", 10) == 0) {
		p = pem;
		p += strcspn(p, "\r\n");
		p += strspn(p, "\r\n");
		q = p;
		while (q < pem + length) {
			q = q + strcspn(q, "\r\n");
			q += strspn(q, "\r\n");
			if (strncmp(q, "-----END", 8) == 0) {
				len = q - p;
				buf = malloc(len);
				if (buf != NULL) {
					decoded = cm_store_base64_to_bin(p,
									 q - p,
									 buf,
									 len);
					if (decoded > 0) {
						cm_pkcs7_parse_buffer(buf,
								      decoded,
								      sk);
					}
					free(buf);
				}
			}
		}
	}
}
static void
cm_pkcs7_parse_buffer(const unsigned char *buffer, size_t length,
		      STACK_OF(X509) *sk)
{
	PKCS7 *p7;
	X509 *x;
	const unsigned char *p;
	char *s, *sp, *sq;
	int i;

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
			X509_free(x);
		} else {
			/* Not a certificate.  Maybe it's PEM.  Check if it's
			 * all ASCII. */
			for (p = buffer; p < buffer + length; p++) {
				if ((*p & 0x80) != 0) {
					break;
				}
			}
			if (p == buffer + length) {
				s = malloc(length + 1);
				if (s == NULL) {
					return;
				}
				memcpy(s, buffer, length);
				s[length] = '\0';
				sp = s;
				while ((sp = strstr(sp, "-----BEGIN")) != NULL) {
					sq = strstr(sp, "-----END");
					if (sq != NULL) {
						sq += strcspn(sq, "\r\n");
						sq += strspn(sq, "\r\n");
						cm_pkcs7_parse_pem(sp, sq - sp,
								   sk);
						sp = sq;
					}
				}
				free(s);
			}
		}
	}
}

int
cm_pkcs7_parse(unsigned int flags, void *parent,
	       char **certleaf, char **certtop, char ***certothers,
	       const unsigned char *buffer, size_t length, ...)
{
	X509 *x = NULL, *a, *b, **certs;
	STACK_OF(X509) *sk;
	char *cleaf = NULL, *ctop = NULL, **cothers = NULL;
	int leaf, top, n_certs, sorted, i, j;
	va_list args;

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
	cm_pkcs7_parse_buffer(buffer, length, sk);
	va_start(args, length);
	while ((buffer = va_arg(args, const unsigned char *)) != NULL) {
		length = va_arg(args, size_t);
		cm_pkcs7_parse_buffer(buffer, length, sk);
	}
	va_end(args);
	/* Count the number of certificates. */
	n_certs = sk_X509_num(sk);
	/* Find one that didn't issue any of the others. */
	leaf = -1;
	for (i = 0; i < n_certs; i++) {
		/* Start with a candidate. */
		a = sk_X509_value(sk, i);
		/* Look for any that it issued. */
		for (j = 0; j < n_certs; j++) {
			if (j == i) {
				continue;
			}
			b = sk_X509_value(sk, j);
			if (issuerissued(a, b) == 0) {
				break;
			}
		}
		/* If it didn't issue any, then we found it. */
		if (j == sk_X509_num(sk)) {
			if (leaf == -1) {
				leaf = i;
			} else {
				/* Or we may have found a better one. */
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
		/* Start with a candidate. */
		a = sk_X509_value(sk, i);
		/* Look for any that issued it. */
		for (j = 0; j < n_certs; j++) {
			if (j == i) {
				continue;
			}
			b = sk_X509_value(sk, j);
			if (issuerissued(b, a) == 0) {
				break;
			}
		}
		/* If we found none, then it's the top. */
		if (j == sk_X509_num(sk)) {
			if (top == -1) {
				top = i;
			} else {
				/* Or we may have found a better one. */
				if (bettertop(a,
					      sk_X509_value(sk, top),
					      flags) == 0) {
					top = i;
				}
			}
		}
	}
	/* Set the output values.  Leaf and top first. */
	if (leaf != -1) {
		cleaf = pemx509(parent, sk_X509_value(sk, leaf));
		n_certs--;
	}
	if ((top != -1) && (top != leaf)) {
		ctop = pemx509(parent, sk_X509_value(sk, top));
		n_certs--;
	}
	/* Now the rest, which may be in between the top and leaf. */
	if (n_certs > 0) {
		/* We need a plain array for sorting. */
		certs = talloc_array_ptrtype(parent, certs,
					     n_certs);
		for (i = 0, j = 0; i < sk_X509_num(sk); i++) {
			if ((i != top) && (i != leaf)) {
				certs[j++] = sk_X509_value(sk, i);
			}
		}
		sorted = 0;
		do {
			/* Find a leaf among the rest. */
			leaf = -1;
			for (i = sorted; i < n_certs - 1; i++) {
				for (j = i + 1; j < n_certs; j++) {
					/* If it issued another, then it's not a leaf. */
					if (issuerissued(certs[i], certs[j]) == 0) {
						break;
					}
				}
				/* If it didn't issue any others, then it goes first. */
				if (j == n_certs) {
					leaf = j;
					break;
				}
			}
			if (leaf != -1) {
				/* Move the leaf to the front of the list. */
				x = certs[leaf];
				certs[leaf] = certs[sorted];
				certs[sorted] = x;
				sorted++;
			}
		} while (leaf != -1);
		/* Dump them into an array of PEM data. */
		cothers = talloc_array_ptrtype(parent, *certothers,
					       n_certs + 1);
		if (cothers != NULL) {
			for (i = 0; i < n_certs; i++) {
				cothers[i] = pemx509(parent, certs[i]);
			}
			cothers[i] = NULL;
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

/* Envelope some data for the recipient. */
int
cm_pkcs7_envelope_data(char *encryption_cert,
		       unsigned char *data, size_t dlength,
		       unsigned char **enveloped, size_t *length)
{
	STACK_OF(X509) *recipients = NULL;
	X509 *recipient = NULL;
	BIO *in = NULL;
	PKCS7 *p7 = NULL;
	unsigned char *dp7 = NULL, *u = NULL;
	int ret = -1, len;

	*enveloped = NULL;
	*length = 0;

	in = BIO_new_mem_buf(encryption_cert, -1);
	if (in == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	recipient = PEM_read_bio_X509(in, NULL, NULL, NULL);
	if (recipient == NULL) {
		cm_log(1, "Error parsing recipient certificate.\n");
		goto done;
	}
	BIO_free(in);

	recipients = sk_X509_new(cert_cmp);
	if (recipients == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	sk_X509_push(recipients, recipient);

	in = BIO_new_mem_buf(data, dlength);
	if (in == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	p7 = PKCS7_encrypt(recipients, in, cm_prefs_ossl_cipher(),
			   PKCS7_BINARY);
	BIO_free(in);

	if (p7 == NULL) {
		cm_log(1, "Error encrypting signing request.\n");
		goto done;
	}
	len = i2d_PKCS7_ENVELOPE(p7->d.enveloped, NULL);
	if (len < 0) {
		cm_log(1, "Error encoding encrypted signing request.\n");
		goto done;
	}
	dp7 = malloc(len);
	if (dp7 == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	u = dp7;
	if (i2d_PKCS7_ENVELOPE(p7->d.enveloped, &u) != len) {
		cm_log(1, "Error encoding encrypted signing request.\n");
		goto done;
	}
	*enveloped = dp7;
	*length = len;

	ret = 0;
done:
	if (recipients != NULL) {
		sk_X509_free(recipients);
	}
	if (recipient != NULL) {
		X509_free(recipient);
	}
	return ret;
}

int
cm_pkcs7_envelope_csr(char *encryption_cert, char *csr,
		      unsigned char **enveloped, size_t *length)
{
	BIO *in;
	X509_REQ *req = NULL;
	int dlen, ret = -1;
	unsigned char *dreq = NULL, *u;

	*enveloped = NULL;
	*length = 0;

	in = BIO_new_mem_buf(csr, -1);
	if (in == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
	BIO_free(in);
	if (req == NULL) {
		cm_log(1, "Error parsing certificate signing request.\n");
		goto done;
	}

	dlen = i2d_X509_REQ(req, NULL);
	if (dlen < 0) {
		cm_log(1, "Error encoding certificate signing request.\n");
		goto done;
	}
	dreq = malloc(dlen);
	if (dreq == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	u = dreq;
	if (i2d_X509_REQ(req, &u) != dlen) {
		cm_log(1, "Error encoding certificate signing request.\n");
		goto done;
	}
	ret = cm_pkcs7_envelope_data(encryption_cert, dreq, dlen,
				     enveloped, length);
done:
	if (req != NULL) {
		X509_REQ_free(req);
	}
	free(dreq);
	return ret;
}

struct cm_pkcs7_ias {
	SECItem issuer, subject;
};
static const SEC_ASN1Template
cm_pkcs7_ias_template[] = {
	{
		.kind = SEC_ASN1_SEQUENCE,
		.offset = 0,
		.sub = NULL,
		.size = sizeof(struct cm_pkcs7_ias),
	},
	{
		.kind = SEC_ASN1_ANY,
		.offset = offsetof(struct cm_pkcs7_ias, issuer),
		.sub = &SEC_ASN1_GET(SEC_AnyTemplate),
		.size = sizeof(SECItem),
	},
	{
		.kind = SEC_ASN1_ANY,
		.offset = offsetof(struct cm_pkcs7_ias, subject),
		.sub = &SEC_ASN1_GET(SEC_AnyTemplate),
		.size = sizeof(SECItem),
	},
	{ 0, 0, NULL, 0 },
};

int
cm_pkcs7_generate_ias(char *cacert, char *minicert,
		      unsigned char **ias, size_t *length)
{
	BIO *in;
	X509 *ca = NULL, *mini = NULL;
	int subjectlen, issuerlen, ret = -1;
	unsigned char *issuer = NULL, *subject = NULL, *u;
	struct cm_pkcs7_ias issuerandsubject;
	SECItem encoded;

	*ias = NULL;
	*length = 0;
	memset(&encoded, 0, sizeof(encoded));

	in = BIO_new_mem_buf(cacert, -1);
	if (in == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	ca = PEM_read_bio_X509(in, NULL, NULL, NULL);
	BIO_free(in);
	if (ca == NULL) {
		cm_log(1, "Error parsing CA certificate.\n");
		goto done;
	}

	in = BIO_new_mem_buf(minicert, -1);
	if (in == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	mini = PEM_read_bio_X509(in, NULL, NULL, NULL);
	BIO_free(in);
	if (mini == NULL) {
		cm_log(1, "Error parsing client certificate.\n");
		goto done;
	}

	issuerlen = i2d_X509_NAME(ca->cert_info->issuer, NULL);
	if (issuerlen < 0) {
		cm_log(1, "Error encoding CA certificate issuer name.\n");
		goto done;
	}
	issuer = malloc(issuerlen);
	if (issuer == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	u = issuer;
	if (i2d_X509_NAME(ca->cert_info->issuer, &u) != issuerlen) {
		cm_log(1, "Error encoding CA certificate issuer name.\n");
		goto done;
	}

	subjectlen = i2d_X509_NAME(mini->cert_info->subject, NULL);
	if (subjectlen < 0) {
		cm_log(1, "Error encoding client certificate subject name.\n");
		goto done;
	}
	subject = malloc(subjectlen);
	if (subject == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	u = subject;
	if (i2d_X509_NAME(mini->cert_info->subject, &u) != subjectlen) {
		cm_log(1, "Error encoding client certificate subject name.\n");
		goto done;
	}
	memset(&issuerandsubject, 0, sizeof(issuerandsubject));
	issuerandsubject.issuer.data = issuer;
	issuerandsubject.issuer.len = issuerlen;
	issuerandsubject.subject.data = subject;
	issuerandsubject.subject.len = subjectlen;
	if (SEC_ASN1EncodeItem(NULL, &encoded, &issuerandsubject,
			       cm_pkcs7_ias_template) != &encoded) {
		cm_log(1, "Error encoding issuer and subject names.\n");
		goto done;
	}
	*ias = malloc(encoded.len);
	if (*ias != NULL) {
		memcpy(*ias, encoded.data, encoded.len);
		*length = encoded.len;
		ret = 0;
	}
done:
	if (encoded.data != NULL) {
		SECITEM_FreeItem(&encoded, PR_FALSE);
	}
	if (mini != NULL) {
		X509_free(mini);
	}
	if (ca != NULL) {
		X509_free(ca);
	}
	free(issuer);
	free(subject);
	return ret;
}

int
cm_pkcs7_envelope_ias(char *encryption_cert, char *cacert, char *minicert,
		      unsigned char **enveloped, size_t *length)
{
	int ret = -1;
	unsigned char *dias = NULL;
	size_t dlen;

	*enveloped = NULL;
	*length = 0;

	if ((cacert == NULL) || (strlen(cacert) == 0)) {
		cacert = encryption_cert;
	}

	ret = cm_pkcs7_generate_ias(cacert, minicert, &dias, &dlen);
	if (ret != 0) {
		goto done;
	}

	ret = cm_pkcs7_envelope_data(encryption_cert, dias, dlen,
				     enveloped, length);
done:
	free(dias);
	return ret;
}
