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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <nss.h>
#include <secasn1.h>
#include <secitem.h>

#include <talloc.h>

#include "log.h"
#include "pkcs7.h"
#include "prefs.h"
#include "prefs-o.h"
#include "scep-o.h"
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
				  size_t length,
				  void (*decrypt_envelope)(const unsigned char *envelope,
							   size_t length,
							   void *decrypt_userdata,
							   unsigned char **payload,
							   size_t *payload_length),
				  void *decrypt_userdata,
				  STACK_OF(X509) *sk);
static void
cm_pkcs7_parse_pem(const char *pem, size_t length,
		   void (*decrypt_envelope)(const unsigned char *envelope,
					    size_t length,
					    void *decrypt_userdata,
					    unsigned char **payload,
					    size_t *payload_length),
		   void *decrypt_userdata,
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
								      decrypt_envelope,
								      decrypt_userdata,
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
		      void (*decrypt_envelope)(const unsigned char *envelope,
					       size_t length,
					       void *decrypt_userdata,
					       unsigned char **payload,
					       size_t *payload_length),
		      void *decrypt_userdata,
		      STACK_OF(X509) *sk)
{
	PKCS7 *p7;
	X509 *x;
	const unsigned char *p;
	char *s, *sp, *sq;
	unsigned char *enveloped = NULL;
	size_t enveloped_length = 0;
	int i;

	if (length == 0) {
		return;
	}
	if (length == (size_t) -1) {
		length = strlen((const char *) buffer);
	}
	/* First, try to parse as a PKCS#7 signed or enveloped data item. */
	p = buffer;
	p7 = d2i_PKCS7(NULL, &p, length);
	if ((p7 != NULL) && (p == buffer + length)) {
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
		} else
		/* Is it an enveloped-data item that we can try to decrypt? */
		if (PKCS7_type_is_enveloped(p7) &&
		    (decrypt_envelope != NULL)) {
		      decrypt_envelope(buffer, length, decrypt_userdata,
				       &enveloped, &enveloped_length);
		      if ((enveloped != NULL) && (enveloped_length > 0)) {
			      /* Parse out the payload. */
			      cm_pkcs7_parse_buffer(enveloped,
						    enveloped_length,
						    decrypt_envelope,
						    decrypt_userdata,
						    sk);
		      }
		}
		PKCS7_free(p7);
	} else {
		/* Not PKCS#7?  Try to parse as a plain certificate. */
		p = buffer;
		x = d2i_X509(NULL, &p, length);
		if ((x != NULL) && (p == buffer + length)) {
			if (sk_X509_find(sk, x) < 0) {
				sk_X509_push(sk, X509_dup(x));
			}
			X509_free(x);
		} else {
			/* Not PKCS#7 binary data that we recognized, and not a
			 * binary certificate.  Maybe it's a PEM-formatted
			 * version of one of those.  Check if it's all ASCII. */
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
								   decrypt_envelope,
								   decrypt_userdata,
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
cm_pkcs7_parsev(unsigned int flags, void *parent,
		char **certleaf, char **certtop, char ***certothers,
		void (*decrypt_envelope)(const unsigned char *envelope,
					 size_t length,
					 void *decrypt_userdata,
					 unsigned char **payload,
					 size_t *payload_length),
		void *decrypt_userdata,
		int n_buffers,
		const unsigned char **buffer, size_t *length)
{
	X509 *x = NULL, *a, *b, **certs;
	STACK_OF(X509) *sk;
	char *cleaf = NULL, *ctop = NULL, **cothers = NULL;
	int leaf, top, n_certs, sorted, i, j;

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
	for (i = 0; i < n_buffers; i++) {
		cm_pkcs7_parse_buffer(buffer[i], length[i],
				      decrypt_envelope, decrypt_userdata, sk);
	}
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
		if (i == leaf) {
			continue;
		}
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
			for (i = sorted; i < n_certs; i++) {
				for (j = sorted; j < n_certs; j++) {;
					if (j == i) {
						continue;
					}
					/* If it issued another, then it's not a leaf. */
					if (issuerissued(certs[i], certs[j]) == 0) {
						break;
					}
				}
				/* If it didn't issue any others, then it goes first. */
				if (j == n_certs) {
					leaf = i;
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

int
cm_pkcs7_parse(unsigned int flags, void *parent,
	       char **certleaf, char **certtop, char ***certothers,
	       void (*decrypt_envelope)(const unsigned char *envelope,
					size_t length,
					void *decrypt_userdata,
					unsigned char **payload,
					size_t *payload_length),
	       void *decrypt_userdata,
	       const unsigned char *buffer, size_t length, ...)
{
	va_list args;
	const unsigned char **buffers = NULL;
	size_t *lengths = NULL;
	int n_buffers = 0, ret;

	if (buffer != NULL) {
		buffers = talloc_realloc_size(parent, buffers,
					      sizeof(buffers[0]) *
					      (n_buffers + 1));
		lengths = talloc_realloc_size(parent, lengths,
					      sizeof(lengths[0]) *
					      (n_buffers + 1));
		if ((buffers == NULL) || (lengths == NULL)) {
			return -1;
		}
		buffers[n_buffers] = buffer;
		lengths[n_buffers] = length;
		n_buffers++;
	}
	va_start(args, length);
	while ((buffer = va_arg(args, const unsigned char *)) != NULL) {
		length = va_arg(args, size_t);
		buffers = talloc_realloc_size(parent, buffers,
					      sizeof(buffers[0]) *
					      (n_buffers + 1));
		lengths = talloc_realloc_size(parent, lengths,
					      sizeof(lengths[0]) *
					      (n_buffers + 1));
		if ((buffers == NULL) || (lengths == NULL)) {
			va_end(args);
			return -1;
		}
		buffers[n_buffers] = buffer;
		lengths[n_buffers] = length;
		n_buffers++;
	}
	va_end(args);
	ret = cm_pkcs7_parsev(flags, parent, certleaf, certtop, certothers,
			      decrypt_envelope, decrypt_userdata,
			      n_buffers, buffers, lengths);
	talloc_free(buffers);
	talloc_free(lengths);
	return ret;
}

/* Envelope some data for the recipient. */
int
cm_pkcs7_envelope_data(char *encryption_cert, enum cm_prefs_cipher cipher,
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
	p7 = PKCS7_encrypt(recipients, in, cm_prefs_ossl_cipher_by_pref(cipher),
			   PKCS7_BINARY);
	BIO_free(in);

	if (p7 == NULL) {
		cm_log(1, "Error encrypting signing request.\n");
		goto done;
	}
	len = i2d_PKCS7(p7, NULL);
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
	if (i2d_PKCS7(p7, &u) != len) {
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
cm_pkcs7_envelope_csr(char *encryption_cert, enum cm_prefs_cipher cipher,
		      char *csr, unsigned char **enveloped, size_t *length)
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
	ret = cm_pkcs7_envelope_data(encryption_cert, cipher, dreq, dlen,
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
cm_pkcs7_envelope_ias(char *encryption_cert, enum cm_prefs_cipher cipher,
		      char *cacert, char *minicert, unsigned char **enveloped,
		      size_t *length)
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

	ret = cm_pkcs7_envelope_data(encryption_cert, cipher, dias, dlen,
				     enveloped, length);
done:
	free(dias);
	return ret;
}

static char *
get_pstring_attribute(void *parent, STACK_OF(X509_ATTRIBUTE) *attrs, int nid)
{
	X509_ATTRIBUTE *a;
	ASN1_TYPE *value;
	ASN1_PRINTABLESTRING *p;
	int i, len;
	const char *s;
	char *ret;

	if (attrs == NULL) {
		return NULL;
	}
	for (i = 0; i < sk_X509_ATTRIBUTE_num(attrs); i++) {
		a = sk_X509_ATTRIBUTE_value(attrs, i);
		if (OBJ_obj2nid(a->object) != nid) {
			continue;
		}
		if (a->single) {
			value = a->value.single;
		} else {
			if (sk_ASN1_TYPE_num(a->value.set) == 1) {
				value = sk_ASN1_TYPE_value(a->value.set, 0);
			} else {
				value = NULL;
			}
		}
		if ((value != NULL) && (value->type == V_ASN1_PRINTABLESTRING)) {
			p = value->value.printablestring;
			if (p != NULL) {
				len = ASN1_STRING_length(p);
				s = (const char *) ASN1_STRING_data(p);
				ret = talloc_size(parent, len + 1);
				if (ret != NULL) {
					memcpy(ret, s, len);
					ret[len] = '\0';
					return ret;
				}
			}
		}
	}
	return NULL;
}

static void
get_ostring_attribute(void *parent, STACK_OF(X509_ATTRIBUTE) *attrs, int nid,
		      unsigned char **ret, size_t *length)
{
	X509_ATTRIBUTE *a;
	ASN1_TYPE *value;
	ASN1_OCTET_STRING *p;
	const unsigned char *s;
	int i;

	*ret = NULL;
	*length = 0;
	if (attrs == NULL) {
		return;
	}
	for (i = 0; i < sk_X509_ATTRIBUTE_num(attrs); i++) {
		a = sk_X509_ATTRIBUTE_value(attrs, i);
		if (OBJ_obj2nid(a->object) != nid) {
			continue;
		}
		if (a->single) {
			value = a->value.single;
		} else {
			if (sk_ASN1_TYPE_num(a->value.set) == 1) {
				value = sk_ASN1_TYPE_value(a->value.set, 0);
			} else {
				value = NULL;
			}
		}
		if ((value != NULL) && (value->type == V_ASN1_OCTET_STRING)) {
			p = value->value.octet_string;
			if (p != NULL) {
				i = ASN1_STRING_length(p);
				s = ASN1_STRING_data(p);
				*ret = talloc_size(parent, i + 1);
				if (*ret != NULL) {
					memcpy(*ret, s, i);
					*length = i;
					return;
				}
			}
		}
	}
	return;
}

static int
ignore_purpose_errors(int ok, X509_STORE_CTX *ctx)
{
	switch (X509_STORE_CTX_get_error(ctx)) {
	case X509_V_ERR_INVALID_PURPOSE:
	case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
		/* Ignore purpose and usage checks. */
		return 1;
		break;
	default:
		/* Otherwise go with the library's default behavior. */
		return ok;
		break;
	}
}

int
cm_pkcs7_verify_signed(unsigned char *data, size_t length,
		       const char **roots, const char **othercerts,
		       int expected_content_type,
		       void *parent, char **digest,
		       char **tx, char **msgtype,
		       char **pkistatus, char **failinfo,
		       unsigned char **sender_nonce,
		       size_t *sender_nonce_length,
		       unsigned char **recipient_nonce,
		       size_t *recipient_nonce_length,
		       unsigned char **payload, size_t *payload_length)
{
	PKCS7 *p7 = NULL, *encapsulated;
	X509 *x;
	STACK_OF(X509) *certs = NULL;
	STACK_OF(X509_ATTRIBUTE) *attrs;
	X509_STORE *store = NULL;
	X509_ALGOR *algor = NULL;
	PKCS7_SIGNED *p7s;
	PKCS7_SIGNER_INFO *si;
	BIO *in, *out = NULL;
	const unsigned char *u;
	char *s, buf[LINE_MAX], *p, *q;
	int ret = -1, i;
	long error;

	if (digest != NULL) {
		*digest = NULL;
	}
	if (tx != NULL) {
		*tx = NULL;
	}
	if (msgtype != NULL) {
		*msgtype = NULL;
	}
	if (pkistatus != NULL) {
		*pkistatus = NULL;
	}
	if (failinfo != NULL) {
		*failinfo = NULL;
	}
	if (sender_nonce != NULL) {
		*sender_nonce = NULL;
	}
	if (sender_nonce_length != NULL) {
		*sender_nonce_length = 0;
	}
	if (recipient_nonce != NULL) {
		*recipient_nonce = NULL;
	}
	if (recipient_nonce_length != NULL) {
		*recipient_nonce_length = 0;
	}
	if (payload != NULL) {
		*payload = NULL;
	}
	if (payload_length != NULL) {
		*payload_length = 0;
	}
	u = data;
	p7 = d2i_PKCS7(NULL, &u, length);
	if ((p7 == NULL) || (u != data + length)) {
		cm_log(1, "Error parsing what should be PKCS#7 signed-data.\n");
		goto done;
	}
	if ((p7->type == NULL) || (OBJ_obj2nid(p7->type) != NID_pkcs7_signed)) {
		cm_log(1, "PKCS#7 data is not signed-data.\n");
		goto done;
	}
	store = X509_STORE_new();
	if (store == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	X509_STORE_set_verify_cb_func(store, &ignore_purpose_errors);
	certs = sk_X509_new(cert_cmp);
	if (certs == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	for (i = 0; (roots != NULL) && (roots[i] != NULL); i++) {
		s = talloc_strdup(parent, roots[i]);
		if (s == NULL) {
			cm_log(1, "Out of memory.\n");
			goto done;
		}
		/* In case one of these is multiple PEM certificates
		 * concatenated, always break them up. */
		p = s;
		while ((p != NULL) && (*p != '\0')) {
			if (strncmp(p, "-----BEGIN", 10) != 0) {
				break;
			}
			q = strstr(p, "----END");
			if (q == NULL) {
				break;
			}
			q += strcspn(q, "\n");
			if (*q == '\n') {
				q++;
			}
			in = BIO_new_mem_buf(p, q - p);
			if (in == NULL) {
				cm_log(1, "Out of memory.\n");
				goto done;
			}
			x = PEM_read_bio_X509(in, NULL, NULL, NULL);
			BIO_free(in);
			if (x == NULL) {
				cm_log(1, "Error parsing chain certificate.\n");
				goto done;
			}
			X509_STORE_add_cert(store, x);
			X509_free(x);
			p = q;
		}
		talloc_free(s);
	}
	for (i = 0; (othercerts != NULL) && (othercerts[i] != NULL); i++) {
		s = talloc_strdup(parent, othercerts[i]);
		if (s == NULL) {
			cm_log(1, "Out of memory.\n");
			goto done;
		}
		/* In case one of these is multiple PEM certificates
		 * concatenated, always break them up. */
		p = s;
		while ((p != NULL) && (*p != '\0')) {
			if (strncmp(p, "-----BEGIN", 10) != 0) {
				break;
			}
			q = strstr(p, "----END");
			if (q == NULL) {
				break;
			}
			q += strcspn(q, "\n");
			if (*q == '\n') {
				q++;
			}
			in = BIO_new_mem_buf(p, q - p);
			if (in == NULL) {
				cm_log(1, "Out of memory.\n");
				goto done;
			}
			x = PEM_read_bio_X509(in, NULL, NULL, NULL);
			BIO_free(in);
			if (x == NULL) {
				cm_log(1, "Error parsing chain certificate.\n");
				goto done;
			}
			sk_X509_push(certs, x);
			p = q;
		}
		talloc_free(s);
	}
	out = BIO_new(BIO_s_mem());
	if (out == NULL) {
		cm_log(1, "Out of memory.\n");
		goto done;
	}
	if (roots != NULL) {
		/* When PKCS7_verify() goes to verify the signer certificate,
		 * it uses the trust store we pass in, but it only searches the
		 * list of certificates in the signed-data for intermediates,
		 * ignoring the list of non-trusted certificates we passed in.
		 * Merge our list into the one in the signed-data, to ensure
		 * that they can be found. */
		for (i = 0; i < sk_X509_num(certs); i++) {
			x = X509_dup(sk_X509_value(certs, i));
			if (x == NULL) {
				cm_log(1, "Out of memory.\n");
				goto done;
			}
			PKCS7_add_certificate(p7, x);
		}
		if (PKCS7_verify(p7, certs, store, NULL, out, 0) != 1) {
			cm_log(1, "Message failed verification.\n");
			goto done;
		}
	}
	p7s = p7->d.sign;
	if (sk_PKCS7_SIGNER_INFO_num(p7s->signer_info) != 1) {
		cm_log(1, "Number of PKCS#7 signed-data signers != 1.\n");
		goto done;
	}
	si = sk_PKCS7_SIGNER_INFO_value(p7s->signer_info, 0);
	attrs = si->auth_attr;
	encapsulated = p7s->contents;
	if (expected_content_type != NID_undef) {
		if (encapsulated == NULL) {
			cm_log(1, "Error parsing PKCS#7 encapsulated content.\n");
			goto done;
		}
		if ((encapsulated->type == NULL) ||
		    (OBJ_obj2nid(encapsulated->type) != expected_content_type)) {
			cm_log(1, "PKCS#7 encapsulated data is not %s (%s).\n",
			       OBJ_nid2ln(expected_content_type),
			       encapsulated->type ?
			       OBJ_nid2ln(OBJ_obj2nid(encapsulated->type)) :
			       "type not set");
			goto done;
		}
	}
	if (attrs == NULL) {
		cm_log(1, "PKCS#7 signed-data contains no signed attributes.\n");
		goto done;
	}
	ret = 0;
	if (digest != NULL) {
		algor = si->digest_alg;
		switch (OBJ_obj2nid(algor->algorithm)) {
		case NID_md5:
			*digest = talloc_strdup(parent, "md5");
			break;
		case NID_sha512:
			*digest = talloc_strdup(parent, "sha512");
			break;
		case NID_sha384:
			*digest = talloc_strdup(parent, "sha384");
			break;
		case NID_sha256:
			*digest = talloc_strdup(parent, "sha256");
			break;
		case NID_sha1:
			*digest = talloc_strdup(parent, "sha1");
			break;
		}
	}
	if (tx != NULL) {
		*tx = get_pstring_attribute(parent, attrs,
					    cm_scep_o_get_tx_nid());
	}
	if (msgtype != NULL) {
		*msgtype = get_pstring_attribute(parent, attrs,
						 cm_scep_o_get_msgtype_nid());
	}
	if (pkistatus != NULL) {
		*pkistatus = get_pstring_attribute(parent, attrs,
						   cm_scep_o_get_pkistatus_nid());
	}
	if (failinfo != NULL) {
		*failinfo = get_pstring_attribute(parent, attrs,
						  cm_scep_o_get_failinfo_nid());
	}
	if ((sender_nonce != NULL) && (sender_nonce_length != NULL)) {
		get_ostring_attribute(parent, attrs,
				      cm_scep_o_get_sender_nonce_nid(),
				      sender_nonce, sender_nonce_length);
	}
	if ((recipient_nonce != NULL) && (recipient_nonce_length != NULL)) {
		get_ostring_attribute(parent, attrs,
				      cm_scep_o_get_recipient_nonce_nid(),
				      recipient_nonce, recipient_nonce_length);
	}
	if ((payload != NULL) && (payload_length != NULL)) {
		*payload_length = BIO_get_mem_data(out, &s);
		if (*payload_length > 0) {
			*payload = talloc_size(parent, *payload_length + 1);
			if (*payload == NULL) {
				cm_log(1, "Out of memory.\n");
				goto done;
			}
			memcpy(*payload, s, *payload_length);
			(*payload)[*payload_length] = '\0';
		}
	}
done:
	if (ret != 0) {
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
	}
	if (p7 != NULL) {
		PKCS7_free(p7);
	}
	if (certs != NULL) {
		sk_X509_pop_free(certs, X509_free);
	}
	if (store != NULL) {
		X509_STORE_free(store);
	}
	if (out != NULL) {
		BIO_free(out);
	}
	return ret;
}
