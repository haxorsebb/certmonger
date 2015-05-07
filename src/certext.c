/*
 * Copyright (C) 2009,2011,2012,2013,2014,2015 Red Hat, Inc.
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
#include <sys/param.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <nss.h>
#include <certt.h>
#include <cert.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <secoid.h>
#include <secoidt.h>
#include <secasn1.h>

#include <talloc.h>

#include <krb5.h>

#ifdef CM_USE_IDN
#include <idna.h>
#endif

#include "certext.h"
#include "certext-n.h"
#include "log.h"
#include "oiddict.h"
#include "store.h"
#include "store-int.h"
#include "util-n.h"

/* Structures and templates for creating and parsing principal name otherName
 * values. */
struct realm {
	SECItem name;
};
struct principal_name {
	SECItem name_type;
	SECItem **name_string;
};
struct kerberos_principal_name {
	struct realm realm;
	struct principal_name principal_name;
};
struct ms_template {
	SECItem id;
	SECItem major;
	SECItem *minor;
};

/* KerberosString: RFC 4120, 5.2.1 */
static const SEC_ASN1Template
cm_kerberos_string_template[] = {
	{
	.kind = SEC_ASN1_GENERAL_STRING,
	.offset = 0,
	.sub = NULL,
	.size = sizeof(SECItem),
	},
};

/* Realm == KerberosString: RFC 4120, 5.2.2 */
static const SEC_ASN1Template
cm_realm_template[] = {
	{
	.kind = SEC_ASN1_GENERAL_STRING,
	.offset = 0,
	.sub = NULL,
	.size = sizeof(SECItem),
	},
};

static const SEC_ASN1Template
cm_sequence_of_kerberos_string_template[] = {
	{
	.kind = SEC_ASN1_SEQUENCE_OF,
	.offset = 0,
	.sub = &cm_kerberos_string_template,
	.size = 0,
	},
};

/* PrincipalName: RFC 4120, 5.2.2 */
static const SEC_ASN1Template
cm_principal_name_template[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof(struct principal_name),
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(struct principal_name, name_type),
	.sub = &SEC_IntegerTemplate,
	.size = sizeof(SECItem),
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 1 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(struct principal_name, name_string),
	.sub = cm_sequence_of_kerberos_string_template,
	.size = sizeof(struct SECItem**),
	},
	{0, 0, NULL, 0},
};

/* KRB5PrincipalName: RFC 4556, 3.2.2 */
const SEC_ASN1Template
cm_kerberos_principal_name_template[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof(struct kerberos_principal_name),
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(struct kerberos_principal_name, realm),
	.sub = &cm_realm_template,
	.size = sizeof(struct realm),
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 1 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(struct kerberos_principal_name, principal_name),
	.sub = &cm_principal_name_template,
	.size = sizeof(struct principal_name),
	},
	{0, 0, NULL, 0},
};

/* V1 templates, identified by name. */
static SEC_ASN1Template
cm_ms_upn_name_template[] = {
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_EXPLICIT |
		SEC_ASN1_CONSTRUCTED,
	.offset = 0,
	.sub = SEC_UTF8StringTemplate,
	.size = sizeof(SECItem),
	},
};

/* A guess at what V2 template identifiers look like. */
const SEC_ASN1Template
cm_ms_template_template[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof(struct kerberos_principal_name),
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(struct ms_template, id),
	.sub = SEC_ObjectIDTemplate,
	.size = sizeof(SECItem),
	},
	{
	.kind = SEC_ASN1_INTEGER,
	.offset = offsetof(struct ms_template, major),
	.sub = SEC_IntegerTemplate,
	.size = sizeof(SECItem),
	},
	{
	.kind = SEC_ASN1_INTEGER | SEC_ASN1_OPTIONAL,
	.offset = offsetof(struct ms_template, minor),
	.sub = SEC_IntegerTemplate,
	.size = sizeof(SECItem),
	},
	{0, 0, NULL, 0},
};

/* RFC 5280, 4.1 */
const SEC_ASN1Template
cm_certext_cert_extension_template[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof(CERTCertExtension),
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(CERTCertExtension, id),
	.sub = NULL,
	.size = sizeof(SECItem),
	},
	{
	.kind = SEC_ASN1_BOOLEAN,
	.offset = offsetof(CERTCertExtension, critical),
	.sub = NULL,
	.size = sizeof(SECItem),
	},
	{
	.kind = SEC_ASN1_OCTET_STRING,
	.offset = offsetof(CERTCertExtension, value),
	.sub = NULL,
	.size = sizeof(SECItem),
	},
	{0, 0, NULL, 0},
};
const SEC_ASN1Template
cm_certext_sequence_of_cert_extension_template[] = {
	{
	.kind = SEC_ASN1_SEQUENCE_OF,
	.offset = 0,
	.sub = cm_certext_cert_extension_template,
	.size = sizeof(CERTCertExtension **),
	},
};

/* Windows 2000-style UPN */
static unsigned char oid_ms_upn_name_bytes[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03};
static const SECOidData oid_ms_upn_name = {
	.oid = {
		.data = oid_ms_upn_name_bytes,
		.len = 10,
	},
	.offset = 0,
	.desc = "Microsoft Windows User Principal Name",
	.mechanism = 0,
	.supportedExtension = UNSUPPORTED_CERT_EXTENSION,
};

/* pkinit-SAN 1.3.6.1.5.2.2 */
static unsigned char oid_pkinit_san_bytes[] = {0x2b, 0x06, 0x01, 0x05, 0x02, 0x02};
static const SECOidData oid_pkinit_san = {
	.oid = {
		.data = oid_pkinit_san_bytes,
		.len = 6,
	},
	.offset = 0,
	.desc = "PKINIT Subject Alternate Name",
	.mechanism = 0,
	.supportedExtension = UNSUPPORTED_CERT_EXTENSION,
};

/* XCN_OID_ENROLL_CERTTYPE_EXTENSION 1.3.6.1.4.1.311.20.2 */
static unsigned char oid_microsoft_certtype_bytes[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02};
static const SECOidData oid_microsoft_certtype = {
	.oid = {
		.data = oid_microsoft_certtype_bytes,
		.len = 9,
	},
	.offset = 0,
	.desc = "Microsoft Certificate Template Name",
	.mechanism = 0,
	.supportedExtension = UNSUPPORTED_CERT_EXTENSION,
};

/* XCN_OID_CERTIFICATE_TEMPLATE 1.3.6.1.4.1.311.21.7 */
static unsigned char oid_microsoft_certificate_template_bytes[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x07};
static const SECOidData oid_microsoft_certificate_template = {
	.oid = {
		.data = oid_microsoft_certificate_template_bytes,
		.len = 9,
	},
	.offset = 0,
	.desc = "Microsoft Certificate Template",
	.mechanism = 0,
	.supportedExtension = UNSUPPORTED_CERT_EXTENSION,
};

/* Read the keyUsage extension and store it as a string in the entry, with each
 * bit being represented by either a "1" or a "0", most significant bit first.
 * */
static void
cm_certext_read_ku(struct cm_store_entry *entry, PLArenaPool *arena,
		   CERTCertExtension *ku_ext)
{
	SECItem item;
	unsigned int i, bit;
	if (SEC_ASN1DecodeItem(arena, &item, SEC_BitStringTemplate,
			       &ku_ext->value) == SECSuccess) {
		talloc_free(entry->cm_cert_ku);
		/* A bitString decodes with length == number of bits, not
		 * bytes, which is what we want anyway. */
		entry->cm_cert_ku = talloc_zero_size(entry, item.len + 1);
		for (i = 0; i < item.len; i++) {
			bit = (item.data[i / 8] & (0x80 >> (i % 8))) ? 1 : 0;
			sprintf(entry->cm_cert_ku + i, "%.*u", 1, bit);
		}
	}
}

/* Build a BitString extension value from a string, with each bit being
 * represented by either a "1" or a "0", most significant bit first. */
static SECItem *
cm_certext_build_bitstring(struct cm_store_entry *entry, PLArenaPool *arena,
			   const char *bitstring)
{
	SECItem *ret, encoded, *bits;
	unsigned int i, used, val, len;

	if ((bitstring == NULL) || (strlen(bitstring) == 0)) {
		/* Nothing to encode, so don't include this extension. */
		return NULL;
	}
	len = strlen(bitstring) + 1;
	bits = SECITEM_AllocItem(arena, NULL, len);
	memset(bits->data, '\0', len);
	for (i = 0, used = 0;
	     (bitstring != NULL) && (bitstring[i] != '\0');
	     i++) {
		val = ((bitstring[i] == '1') ? 0x80 : 0x00) >> (i % 8);
		bits->data[i / 8] |= val;
		if (val != 0) {
			used = i + 1;
		}
	}
	/* A bitString encodes with length == number of bits, not bytes, but
	 * luckily we have that information. */
	bits->len = used;
	memset(&encoded, 0, sizeof(encoded));
	if (SEC_ASN1EncodeItem(arena, &encoded, bits,
			       SEC_BitStringTemplate) != &encoded) {
		ret = NULL;
	} else {
		ret = SECITEM_ArenaDupItem(arena, &encoded);
	}
	return ret;
}

/* Build a keyUsage extension value from a string, with each bit being
 * represented by either a "1" or a "0", most significant bit first. */
static SECItem *
cm_certext_build_ku(struct cm_store_entry *entry, PLArenaPool *arena,
		    const char *ku_value)
{
	return cm_certext_build_bitstring(entry, arena, ku_value);
}

/* Convert an OID to a printable string.  For now, we're limited to components
 * that will fit into a "long". */
static char *
oid_to_string(void *parent, SECItem *oid)
{
	char *s, *t;
	unsigned char *p;
	unsigned long l;
	unsigned int n;
	s = NULL;
	l = 0;
	n = 0;
	for (p = oid->data; p < oid->data + oid->len; p++) {
		/* Add seven more bits. */
		l <<= 7;
		l |= (*p & 0x7f);
		n++;
		/* Check for overflow. */
		if ((n * 7) > sizeof(l) * 8) {
			return NULL;
		}
		/* If this is the last byte, save it. */
		if ((*p & 0x80) == 0) {
			if (s != NULL) {
				/* Directly. */
				t = talloc_asprintf(parent, "%s.%lu", s, l);
				talloc_free(s);
				s = t;
			} else {
				/* The first two items are in the first byte. */
				s = talloc_asprintf(parent, "%lu.%lu",
						    l / 40, l % 40);
			}
			l = 0;
			n = 0;
		}
	}
	return s;
}

/* Convert an OID from a printable string into binary form.  For now, we're
 * limited to components that will fit into a "long". */
SECItem *
oid_from_string(const char *oid, int n, PLArenaPool *arena)
{
	unsigned long *l, val;
	int i, more;
	char *p, *endptr;
	unsigned char *up, u;
	SECItem *ret;
	if (n == -1) {
		n = strlen(oid);
	}
	p = PORT_ArenaZAlloc(arena, n + 1);
	l = PORT_ArenaZAlloc(arena, (n + 1) * sizeof(*l));
	if ((p == NULL) || (l == NULL)) {
		return NULL;
	}
	/* Make sure we've got a NUL-terminator. */
	memcpy(p, oid, n);
	p[n] = '\0';
	n = 0;
	endptr = p;
	/* Parse the values as longs into an array. */
	while ((*endptr != '\0') && (*p != '.')) {
		l[n] = strtoul(p, &endptr, 10);
		if (endptr == NULL) {
			return NULL;
		}
		switch (*endptr) {
		case '.':
			n++;
			p = endptr + 1;
			break;
		case '\0':
			n++;
			break;
		default:
			return NULL;
			break;
		}
	}
	/* Merge the first two values, if we have at least two. */
	if (n >= 2) {
		l[0] = l[0] * 40 + l[1];
		memmove(l + 1, l + 2, sizeof(unsigned long) * (n - 2));
		n--;
	}
	ret = SECITEM_AllocItem(arena, NULL,
				(n + 1) *
				howmany(sizeof(unsigned long) * 8, 7));
	if (ret == NULL) {
		return NULL;
	}
	/* Spool the list of values out, last section last, in LSB
	 * order. */
	up = ret->data;
	for (i = n - 1; i >= 0; i--) {
		val = l[i];
		more = 0;
		do {
			*up = val & 0x7f;
			if (more) {
				*up |= 0x80;
			}
			val >>= 7;
			more = 1;
			up++;
		} while (val != 0);
	}
	/* Reverse the order of bytes in the buffer. */
	ret->len = (up - ret->data);
	for (i = 0; i < (int) (ret->len / 2); i++) {
		u = ret->data[i];
		ret->data[i] = ret->data[ret->len - 1 - i];
		ret->data[ret->len - 1 - i] = u;
	}
	return ret;
}

/* Read an extendedKeyUsage value, convert it into a comma-separated list of
 * string-formatted OIDs, and store it in the entry. */
static void
cm_certext_read_eku(struct cm_store_entry *entry, PLArenaPool *arena,
		    CERTCertExtension *eku_ext)
{
	SECItem **oids;
	unsigned int i;
	char *s, *p;
	if (SEC_ASN1DecodeItem(arena, &oids, SEC_SequenceOfObjectIDTemplate,
			       &eku_ext->value) == SECSuccess) {
		talloc_free(entry->cm_cert_eku);
		entry->cm_cert_eku = NULL;
		for (i = 0; oids[i] != NULL; i++) {
			if (entry->cm_cert_eku != NULL) {
				p = oid_to_string(entry, oids[i]);
#if 1
				/* Yeah, gotta sanity-check myself here. XXX */
				if (strcmp(oid_to_string(entry,
							 oid_from_string(p,
									 -1,
									 arena)),
					   p) != 0) {
					cm_log(1, "Internal error: converting "
					       "string to binary OID to string "
					       "didn't produce the expected "
					       "result.\n");
				}
#endif
				s = talloc_asprintf(entry, "%s,%s",
						    entry->cm_cert_eku, p);
				talloc_free(entry->cm_cert_eku);
				entry->cm_cert_eku = s;
			} else {
				s = oid_to_string(entry, oids[i]);
				talloc_free(entry->cm_cert_eku);
				entry->cm_cert_eku = s;
			}
		}
	}
}

/* Build an extendedKeyUsage value from the comma-separated list stored in the
 * entry. */
static SECItem *
cm_certext_build_eku(struct cm_store_entry *entry, PLArenaPool *arena,
		     const char *eku_value)
{
	int i;
	const char *p, *q;
	char *numeric, *symbolic;
	void *tctx;
	SECItem **oids = NULL, **tmp, encoded, *ret;

	if ((eku_value == NULL) || (strlen(eku_value) == 0)) {
		return NULL;
	}
	p = eku_value;
	i = 0;
	tctx = talloc_new(NULL);
	while ((p != NULL) && (*p != '\0')) {
		/* Find the first (or next) value. */
		q = p + strcspn(p, ",");
		/* Make a copy and convert it to binary form. */
		tmp = PORT_ArenaZAlloc(arena, sizeof(SECItem *) * (i + 2));
		if (tmp != NULL) {
			if (i > 0) {
				memcpy(tmp, oids, sizeof(SECItem *) * i);
			}
			symbolic = talloc_strndup(tctx, p, q - p);
			numeric = cm_oid_from_name(tctx, symbolic);
			if (numeric != NULL) {
				tmp[i] = oid_from_string(numeric, -1, arena);
				i++;
			} else {
				cm_log(1,
				       "Couldn't parse OID \"%.*s\", "
				       "ignoring.\n", (int) (q - p), p);
			}
			oids = tmp;
		}
		/* Do we have any more? */
		if (*q == ',') {
			p = q + 1;
		} else {
			p = q;
		}
	}
	talloc_free(tctx);
	/* Encode the sequence of OIDs. */
	memset(&encoded, 0, sizeof(encoded));
	if (SEC_ASN1EncodeItem(arena, &encoded, &oids,
			       SEC_SequenceOfObjectIDTemplate) != &encoded) {
		ret = NULL;
	} else {
		ret = SECITEM_ArenaDupItem(arena, &encoded);
	}
	return ret;
}

/* Pull the nth component out of a principal name structure.  Treat numbers
 * less than zero as a request for the realm name. */
static unsigned char *
cm_certext_princ_data(krb5_context ctx, krb5_principal princ, int i)
{
	if (i < 0) {
#if HAVE_DECL_KRB5_PRINC_COMPONENT
		return (unsigned char *) (krb5_princ_realm(ctx, princ))->data;
#else
		return (unsigned char *) princ->realm;
#endif
	} else {
#if HAVE_DECL_KRB5_PRINC_COMPONENT
		return (unsigned char *) (krb5_princ_component(ctx, princ, i))->data;
#else
		return (unsigned char *) princ->name.name_string.val[i];
#endif
	}
}

/* Return the length of the data that cm_certext_princ_data() will return for a
 * given index. */
static int
cm_certext_princ_len(krb5_context ctx, krb5_principal princ, int i)
{
	if (i < 0) {
#if HAVE_DECL_KRB5_PRINC_COMPONENT
		return (krb5_princ_realm(ctx, princ))->length;
#else
		return strlen(princ->realm);
#endif
	} else {
#if HAVE_DECL_KRB5_PRINC_COMPONENT
		return (krb5_princ_component(ctx, princ, i))->length;
#else
		return strlen(princ->name.name_string.val[i]);
#endif
	}
}

/* Return a the name-type from a principal name structure. */
static int
cm_certext_princ_get_type(krb5_context ctx, krb5_principal princ)
{
#if HAVE_DECL_KRB5_PRINC_TYPE
	return krb5_princ_type(ctx, princ);
#else
	return princ->name.name_type;
#endif
}

/* Set the name-type in a principal name structure. */
static void
cm_certext_princ_set_type(krb5_context ctx, krb5_principal princ, int nt)
{
#if HAVE_DECL_KRB5_PRINC_TYPE
	krb5_princ_type(ctx, princ) = nt;
#else
	princ->name.name_type = nt;
#endif
}

/* Free an unparsed principal name. */
static void
cm_certext_free_unparsed_name(krb5_context ctx, char *name)
{
#ifdef HAVE_KRB5_FREE_UNPARSED_NAME
	krb5_free_unparsed_name(ctx, name);
#else
	free(name);
#endif
}

/* Check how many components are in a principal name. */
static int
cm_certext_princ_get_length(krb5_context ctx, krb5_principal princ)
{
#if HAVE_DECL_KRB5_PRINC_SIZE
	return krb5_princ_size(ctx, princ);
#else
	return princ->name.name_string.len;
#endif
}

/* Set how many components are in a principal name. */
static void
cm_certext_princ_set_length(krb5_context ctx, krb5_principal princ, int length)
{
#if HAVE_DECL_KRB5_PRINC_SIZE
	krb5_princ_size(ctx, princ) = length;
#else
	princ->name.name_string.len = length;
#endif
}

/* Set a realm name in a principal name to point to a copy of the passed-in
 * name owned by "parent". */
static void
cm_certext_princ_set_realm(krb5_context ctx, void *parent, krb5_principal princ,
			   int length, char *name)
{
#if HAVE_DECL_KRB5_PRINC_SET_REALM_LENGTH
	char *p;
	p = talloc_zero_size(parent, length);
	if (p != NULL) {
		krb5_princ_set_realm_length(ctx, princ, length);
		krb5_princ_set_realm_data(ctx, princ, p);
		memcpy(p, name, length);
	}
#else
	princ->realm = talloc_strndup(parent, name, length);
#endif
}

/* Append a component to a principal name, using storage owned by "parent" to
 * hold a copy of the passed-in component value. */
static void
cm_certext_princ_append_comp(krb5_context ctx, void *parent,
			     krb5_principal princ, char *name, int length)
{
#if HAVE_DECL_KRB5_PRINC_NAME
	krb5_data *comps;
	int i;
	i = cm_certext_princ_get_length(ctx, princ);
	comps = talloc_zero_array(parent, krb5_data, i + 1);
	if (i > 0) {
		memcpy(comps, krb5_princ_name(ctx, princ),
		       sizeof(krb5_data) * i);
	}
	comps[i].data = talloc_zero_size(parent, length);
	if (comps[i].data != NULL) {
		memcpy(comps[i].data, name, length);
		comps[i].length = length;
		krb5_princ_name(ctx, princ) = comps;
		cm_certext_princ_set_length(ctx, princ, i + 1);
	}
#else
	int i;
	char **comps;
	i = cm_certext_princ_get_length(ctx, princ);
	comps = talloc_zero_array(parent, char *, i + 1);
	if (comps != NULL) {
		memcpy(comps, princ->name.name_string.val, sizeof(char *) * i);
		comps[i] = talloc_strndup(parent, name, length);
		if (comps[i] != NULL) {
			princ->name.name_string.val = comps;
			cm_certext_princ_set_length(ctx, princ, i + 1);
		}
	}
#endif
}

/* Convert a principal name structure into a string. */
static char *
cm_certext_parse_principal(void *parent, struct kerberos_principal_name *p)
{
	SECItem **comps;
	krb5_context ctx;
	krb5_principal_data princ;
	char *unparsed, *ret;
	int i, j;
	unsigned long name_type;
	void *tctx;
	ret = NULL;
	ctx = NULL;
	tctx = talloc_new(parent);
	if (krb5_init_context(&ctx) == 0) {
		memset(&princ, 0, sizeof(princ));
		/* Copy the realm over. */
		cm_certext_princ_set_realm(ctx, tctx, &princ,
					   (int) p->realm.name.len,
					   (char *) p->realm.name.data);
		/* Count the number of name components. */
		comps = p->principal_name.name_string;
		for (i = 0; (comps != NULL) && (comps[i] != NULL); i++) {
			continue;
		}
		/* Set the number of name components. */
		cm_certext_princ_set_length(ctx, &princ, 0);
		/* Allocate and populate the name components. */
		for (j = 0; j < i; j++) {
			cm_certext_princ_append_comp(ctx, tctx, &princ,
						     (char *) comps[j]->data,
						     (int) comps[j]->len);
		}
		/* Try to decode the name type. */
		if (SEC_ASN1DecodeInteger(&p->principal_name.name_type,
					  &name_type) != SECSuccess) {
			/* Try to decode the name type. */
			name_type = KRB5_NT_UNKNOWN;
		}
		cm_certext_princ_set_type(ctx, &princ, name_type);
		/* Convert that into a string.  Use the library function so
		 * that it can take care of escaping. */
		if (krb5_unparse_name(ctx, &princ, &unparsed) == 0) {
			ret = talloc_strdup(parent, unparsed);
			cm_certext_free_unparsed_name(ctx, unparsed);
		}
		talloc_free(tctx);
		krb5_free_context(ctx);
	}
	return ret;
}

static void
cm_certext_remove_duplicates(char **p)
{
	int n, i, j;
	for (n = 0; (p != NULL) && (p[n] != NULL); n++) {
		continue;
	}
	i = 0;
	while (i < n) {
		j = i + 1;
		while (j < n) {
			if (strcmp(p[i], p[j]) == 0) {
				memmove(&p[j], &p[j + 1],
					sizeof(p[j]) * (n - j));
				n--;
			} else {
				j++;
			}
		}
		i++;
	}
}

/* Read an otherName, which might be either a Kerberos principal name or just
 * an NT principal name. */
static void
cm_certext_read_other_name(struct cm_store_entry *entry, PLArenaPool *arena,
			   CERTGeneralName *name)
{
	SECItem *item, upn;
	struct kerberos_principal_name p;
	char **names;
	int i;

	item = &name->name.OthName.name;
	/* The Kerberos principal name case. */
	if (SECITEM_ItemsAreEqual(&name->name.OthName.oid,
				  &oid_pkinit_san.oid)) {
		memset(&p, 0, sizeof(p));
		if (SEC_ASN1DecodeItem(arena, &p,
				       cm_kerberos_principal_name_template,
				       item) == SECSuccess) {
			/* Add it to the array. */
			for (i = 0;
			     (entry->cm_cert_principal != NULL) &&
			     (entry->cm_cert_principal[i] != NULL);
			     i++) {
				continue;
			}
			names = talloc_zero_array(entry, char *, i + 2);
			if (i > 0) {
				memcpy(names, entry->cm_cert_principal,
				       sizeof(char *) * i);
			}
			names[i] = cm_certext_parse_principal(entry, &p);
			entry->cm_cert_principal = names;
		}
	}
	/* The NT principal name case. */
	if (SECITEM_ItemsAreEqual(&name->name.OthName.oid,
				  &oid_ms_upn_name.oid)) {
		memset(&upn, 0, sizeof(upn));
		if (SEC_ASN1DecodeItem(arena, &upn,
				       cm_ms_upn_name_template,
				       item) == SECSuccess) {
			/* Add it to the array. */
			for (i = 0;
			     (entry->cm_cert_principal != NULL) &&
			     (entry->cm_cert_principal[i] != NULL);
			     i++) {
				continue;
			}
			names = talloc_zero_array(entry, char *, i + 2);
			if (i > 0) {
				memcpy(names, entry->cm_cert_principal,
				       sizeof(char *) * i);
			}
			names[i] = talloc_strndup(entry,
						  (char *) upn.data, upn.len);
			entry->cm_cert_principal = names;
		} else
		if (SEC_ASN1DecodeItem(arena, &upn,
				       SEC_UTF8StringTemplate,
				       item) == SECSuccess) {
			/* Add it to the array. */
			for (i = 0;
			     (entry->cm_cert_principal != NULL) &&
			     (entry->cm_cert_principal[i] != NULL);
			     i++) {
				continue;
			}
			names = talloc_zero_array(entry, char *, i + 2);
			if (i > 0) {
				memcpy(names, entry->cm_cert_principal,
				       sizeof(char *) * i);
			}
			names[i] = talloc_strndup(entry,
						  (char *) upn.data, upn.len);
			entry->cm_cert_principal = names;
		}
	}
	/* Prune duplicates.  We don't distinguish between the two cases, and
	 * we throw the name_type away, so there's no point in listing any
	 * value more than once. */
	cm_certext_remove_duplicates(entry->cm_cert_principal);
}

/* Extract applicable subjectAltName values. */
static void
cm_certext_read_san(struct cm_store_entry *entry, PLArenaPool *arena,
		    CERTCertExtension *san_ext)
{
	CERTGeneralName *name, *san;
	unsigned int i, j;
	char **s, abuf[64];

	name = CERT_DecodeAltNameExtension(arena, &san_ext->value);
	san = name;
	i = 0;
	talloc_free(entry->cm_cert_hostname);
	entry->cm_cert_hostname = NULL;
	talloc_free(entry->cm_cert_email);
	entry->cm_cert_email = NULL;
	talloc_free(entry->cm_cert_principal);
	entry->cm_cert_principal = NULL;
	while (san != NULL) {
		switch (san->type) {
		case certDNSName:
			/* A dnsName is just a string. */
			for (j = 0;
			     (entry->cm_cert_hostname != NULL) &&
			     (entry->cm_cert_hostname[j] != NULL);
			     j++) {
				continue;
			}
			s = talloc_zero_array(entry, char *, j + 2);
			if (j > 0) {
				memcpy(s, entry->cm_cert_hostname,
				       sizeof(char *) * j);
			}
			s[j] = talloc_strndup(entry,
					      (char *) san->name.other.data,
					      san->name.other.len);
			entry->cm_cert_hostname = s;
			cm_certext_remove_duplicates(entry->cm_cert_hostname);
			break;
		case certIPAddress:
			/* An IPv4 or IPv6 address. */
			if (!((san->name.other.len == 16) &&
			      (inet_ntop(AF_INET6, san->name.other.data,
					 abuf, sizeof(abuf)) != NULL)) &&
			    !((san->name.other.len == 4) &&
			      (inet_ntop(AF_INET, san->name.other.data,
					 abuf, sizeof(abuf)) != NULL))) {
				continue;
			}
			for (j = 0;
			     (entry->cm_cert_ipaddress != NULL) &&
			     (entry->cm_cert_ipaddress[j] != NULL);
			     j++) {
				continue;
			}
			s = talloc_zero_array(entry, char *, j + 2);
			if (j > 0) {
				memcpy(s, entry->cm_cert_ipaddress,
				       sizeof(char *) * j);
			}
			s[j] = talloc_strdup(entry, abuf);
			entry->cm_cert_ipaddress = s;
			cm_certext_remove_duplicates(entry->cm_cert_ipaddress);
			break;
		case certRFC822Name:
			/* An email address is just a string. */
			for (j = 0;
			     (entry->cm_cert_email != NULL) &&
			     (entry->cm_cert_email[j] != NULL);
			     j++) {
				continue;
			}
			s = talloc_zero_array(entry, char *, j + 2);
			if (j > 0) {
				memcpy(s, entry->cm_cert_email,
				       sizeof(char *) * j);
			}
			s[j] = talloc_strndup(entry,
					      (char *) san->name.other.data,
					      san->name.other.len);
			entry->cm_cert_email = s;
			cm_certext_remove_duplicates(entry->cm_cert_email);
			break;
		case certOtherName:
			/* need to parse these to recover principal names */
			cm_certext_read_other_name(entry, arena, san);
			break;
		case certURI:
		case certDirectoryName:
		case certRegisterID:
		case certEDIPartyName:
		case certX400Address:
			/* we currently don't support these */
			break;
		}
		san = CERT_GetNextGeneralName(san);
		if (san == name) {
			break;
		}
		i++;
	}
}

/* Build an NT principal name binary value. */
static SECItem *
cm_certext_build_upn(struct cm_store_entry *entry, PLArenaPool *arena,
		     const char *principal)
{
	SECItem upn, princ;

	if ((principal == NULL) || (strlen(principal) == 0)) {
		return NULL;
	}
	memset(&upn, 0, sizeof(upn));
	memset(&princ, 0, sizeof(princ));
	princ.len = strlen(principal);
	princ.data = (unsigned char *) principal;
	if (SEC_ASN1EncodeItem(arena, &upn, &princ,
			       SEC_UTF8StringTemplate
			       /* cm_ms_upn_name_template */) != &upn) {
		return NULL;
	}
	return SECITEM_ArenaDupItem(arena, &upn);
}

/* Build a Kerberos principal name binary value. */
static SECItem *
cm_certext_build_principal(struct cm_store_entry *entry, PLArenaPool *arena,
			   const char *principal)
{
	SECItem *comp, **comps, encoded;
	struct kerberos_principal_name p;
	krb5_context ctx;
	krb5_principal princ;
	int i;

	if ((principal == NULL) || (strlen(principal) == 0)) {
		return NULL;
	}
	ctx = NULL;
	if (krb5_init_context(&ctx) != 0) {
		return NULL;
	}
	princ = NULL;
	/* Use the library routine to let it handle escaping for us. */
	if (krb5_parse_name(ctx, principal, &princ) != 0) {
		krb5_free_context(ctx);
		return NULL;
	}
	/* Now stuff the values into a structure we can encode. */
	memset(&p, 0, sizeof(p));
	/* realm */
	p.realm.name.data = cm_certext_princ_data(ctx, princ, -1);
	p.realm.name.len = cm_certext_princ_len(ctx, princ, -1);
	/* name type */
	if (SEC_ASN1EncodeInteger(arena, &p.principal_name.name_type,
				  cm_certext_princ_get_type(ctx, princ)) !=
	    &p.principal_name.name_type) {
		memset(&p.principal_name.name_type, 0,
		       sizeof(p.principal_name.name_type));
	}
	/* the component names */
	i = cm_certext_princ_get_length(ctx, princ);
	comp = PORT_ArenaZAlloc(arena, sizeof(SECItem) * (i + 1));
	comps = PORT_ArenaZAlloc(arena, sizeof(SECItem *) * (i + 1));
	if (comp != NULL) {
		for (i = 0; i < cm_certext_princ_get_length(ctx, princ); i++) {
			comp[i].len = cm_certext_princ_len(ctx, princ, i);
			comp[i].data = cm_certext_princ_data(ctx, princ, i);
			comps[i] = &comp[i];
		}
		p.principal_name.name_string = comps;
	} else {
		p.principal_name.name_string = NULL;
	}
	/* encode */
	if (SEC_ASN1EncodeItem(arena, &encoded, &p,
			       cm_kerberos_principal_name_template) != &encoded) {
		krb5_free_principal(ctx, princ);
		krb5_free_context(ctx);
		return NULL;
	}
	krb5_free_principal(ctx, princ);
	krb5_free_context(ctx);
	return SECITEM_ArenaDupItem(arena, &encoded);
}

/* Build up a subjectAltName extension value using information for the entry. */
static SECItem *
cm_certext_build_san(struct cm_store_entry *entry, PLArenaPool *arena,
		     char **hostname, char **email, char **principal,
		     char **ipaddress)
{
	CERTGeneralName *name, *next;
	SECItem encoded, *item;
	int i, j;
	struct in_addr ip;
	struct in6_addr ip6;
	char *p;

	/* Anything to do? */
	if ((hostname == NULL) && (email == NULL) && (principal == NULL) &&
	    (ipaddress == NULL)) {
		return NULL;
	}
	name = NULL;
	/* Build a list of dnsName values. */
	for (i = 0; (hostname != NULL) && (hostname[i] != NULL); i++) {
		if (strlen(hostname[i]) == 0) {
			continue;
		}
		next = PORT_ArenaZAlloc(arena, sizeof(*next));
		if (next != NULL) {
			next->type = certDNSName;
			p = hostname[i];
#ifdef CM_USE_IDN
			if (idna_to_ascii_lz(p, &p, 0) != IDNA_SUCCESS) {
				cm_log(1, "Unable to convert hostname \"%s\" "
				       "to an ASCII-compatible name.\n",
				       hostname[i]);
				continue;
			}
#endif
			next->name.other.data =
				(unsigned char *) PORT_ArenaStrdup(arena, p);
			next->name.other.len = strlen(p);
			if (p != hostname[i]) {
				free(p);
			}
			if (name == NULL) {
				name = next;
				PR_INIT_CLIST(&name->l);
			} else {
				PR_APPEND_LINK(&next->l, &name->l);
			}
		}
	}
	/* Build a list of email address values. */
	for (i = 0; (email != NULL) && (email[i] != NULL); i++) {
		if (strlen(email[i]) == 0) {
			continue;
		}
		next = PORT_ArenaZAlloc(arena, sizeof(*next));
		if (next != NULL) {
			next->type = certRFC822Name;
			next->name.other.len = strlen(email[i]);
			next->name.other.data = (unsigned char *) email[i];
			if (name == NULL) {
				name = next;
				PR_INIT_CLIST(&name->l);
			} else {
				PR_APPEND_LINK(&next->l, &name->l);
			}
		}
	}
	/* Build a list of otherName values. Encode every principal name in two
	 * forms. */
	for (i = 0; (principal != NULL) && (principal[i] != NULL); i++) {
		if (strlen(principal[i]) == 0) {
			continue;
		}
		for (j = 0; (j < i) && (principal[j] != NULL); j++) {
			if (strcmp(principal[i], principal[j]) == 0) {
				/* We've already seen [i]; skip it. */
				break;
			}
		}
		if (j != i) {
			continue;
		}
		item = cm_certext_build_upn(entry, arena, principal[i]);
		if (item != NULL) {
			next = PORT_ArenaZAlloc(arena, sizeof(*next));
			if (next != NULL) {
				next->type = certOtherName;
				next->name.OthName.name = *item;
				next->name.OthName.oid = oid_ms_upn_name.oid;
				if (name == NULL) {
					name = next;
					PR_INIT_CLIST(&name->l);
				} else {
					PR_APPEND_LINK(&next->l, &name->l);
				}
			}
		}
		item = cm_certext_build_principal(entry, arena, principal[i]);
		if (item != NULL) {
			next = PORT_ArenaZAlloc(arena, sizeof(*next));
			if (next != NULL) {
				next->type = certOtherName;
				next->name.OthName.name = *item;
				next->name.OthName.oid = oid_pkinit_san.oid;
				if (name == NULL) {
					name = next;
					PR_INIT_CLIST(&name->l);
				} else {
					PR_APPEND_LINK(&next->l, &name->l);
				}
			}
		}
	}
	/* Build a list of IP address values. */
	for (i = 0; (ipaddress != NULL) && (ipaddress[i] != NULL); i++) {
		if (strlen(ipaddress[i]) == 0) {
			continue;
		}
		next = PORT_ArenaZAlloc(arena, sizeof(*next));
		if (next != NULL) {
			next->type = certIPAddress;
			memset(&encoded, 0, sizeof(encoded));
			if (inet_pton(AF_INET6, ipaddress[i], &ip6) == 1) {
				encoded.len = 16;
				encoded.data = (unsigned char *) &ip6;
			} else if (inet_pton(AF_INET, ipaddress[i], &ip) == 1) {
				encoded.len = 4;
				encoded.data = (unsigned char *) &ip;
			} else {
				cm_log(1, "Internal error: unable to parse "
				       "\"%s\" as an IP address, ignoring.\n",
				       ipaddress[i]);
				continue;
			}
			item = SECITEM_ArenaDupItem(arena, &encoded);
			if (item == NULL) {
				continue;
			}
			next->name.other = *item;
			if (name == NULL) {
				name = next;
				PR_INIT_CLIST(&name->l);
			} else {
				PR_APPEND_LINK(&next->l, &name->l);
			}
		}
	}
	/* Encode all of the values. */
	memset(&encoded, 0, sizeof(encoded));
	if ((name != NULL) &&
	    (CERT_EncodeAltNameExtension(arena, name,
					 &encoded) == SECSuccess)) {
		item = SECITEM_ArenaDupItem(arena, &encoded);
	} else {
		item = NULL;
	}
	return item;
}

/* Build a basicConstraints extension value. */
static SECItem *
cm_certext_build_basic(struct cm_store_entry *entry, PLArenaPool *arena,
		       int is_ca, int path_length)
{
	CERTBasicConstraints value;
	SECItem encoded, *item;

	memset(&value, 0, sizeof(value));
	value.isCA = (is_ca != 0);
	value.pathLenConstraint = value.isCA ? path_length : -1;
	memset(&encoded, 0, sizeof(encoded));
	if (CERT_EncodeBasicConstraintValue(arena, &value,
					    &encoded) == SECSuccess) {
		item = SECITEM_ArenaDupItem(arena, &encoded);
	} else {
		item = NULL;
	}
	return item;
}

/* Build an authorityKeyIdentifier extension value that points to our key. */
static SECItem *
cm_certext_build_self_akid(struct cm_store_entry *entry, PLArenaPool *arena)
{
	CERTAuthKeyID value;
	CERTSubjectPublicKeyInfo *spki;
	SECItem pubkeyinfo, pubkey, encoded, *item;
	unsigned char digest[CM_DIGEST_MAX];
	const char *pubkey_info;
	size_t len;

	memset(&pubkey, 0, sizeof(pubkey));
	if (entry->cm_key_pubkey != NULL) {
		pubkey.len = strlen(entry->cm_key_pubkey) / 2;
		pubkey.data = PORT_ArenaZAlloc(arena, pubkey.len);
		if (pubkey.data != NULL) {
			pubkey.len = cm_store_hex_to_bin(entry->cm_key_pubkey,
							 pubkey.data,
							 pubkey.len);
		}
	}
	if (pubkey.data == NULL) {
		if (entry->cm_key_pubkey_info != NULL) {
			pubkey_info = entry->cm_key_pubkey_info;
		} else {
			pubkey_info = entry->cm_cert_spki;
		}
		if (pubkey_info != NULL) {
			memset(&pubkeyinfo, 0, sizeof(pubkeyinfo));
			pubkeyinfo.len = strlen(pubkey_info) / 2;
			pubkeyinfo.data = PORT_ArenaZAlloc(arena,
							   pubkeyinfo.len);
			spki = NULL;
			if (pubkeyinfo.data != NULL) {
				len = cm_store_hex_to_bin(pubkey_info,
							  pubkeyinfo.data,
							  pubkeyinfo.len);
				pubkeyinfo.len = len;
				spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&pubkeyinfo);
			}
			if (spki != NULL) {
				pubkey.len = spki->subjectPublicKey.len / 8;
				pubkey.data = PORT_ArenaZAlloc(arena,
							       pubkey.len);
				if (pubkey.data != NULL) {
					memcpy(pubkey.data,
					       spki->subjectPublicKey.data,
					       pubkey.len);
				}
				SECKEY_DestroySubjectPublicKeyInfo(spki);
			}
		}
	}
	if (pubkey.data != NULL) {
		if (PK11_HashBuf(SEC_OID_SHA1, digest,
				 pubkey.data,
				 pubkey.len) != SECSuccess) {
			return NULL;
		}
		memset(&value, 0, sizeof(value));
		value.keyID.data = digest;
		value.keyID.len = 20;
		memset(&encoded, 0, sizeof(encoded));
		if (CERT_EncodeAuthKeyID(arena, &value,
					 &encoded) == SECSuccess) {
			item = SECITEM_ArenaDupItem(arena, &encoded);
		} else {
			item = NULL;
		}
		return item;
	}
	return NULL;
}

/* Build a subjectKeyIdentifier extension value. */
static SECItem *
cm_certext_build_skid(struct cm_store_entry *entry, PLArenaPool *arena)
{
	CERTSubjectPublicKeyInfo *spki;
	SECItem pubkeyinfo, pubkey, value, encoded, *item;
	unsigned char digest[CM_DIGEST_MAX];
	const char *pubkey_info;
	size_t len;

	memset(&pubkey, 0, sizeof(pubkey));
	if (entry->cm_key_pubkey != NULL) {
		pubkey.len = strlen(entry->cm_key_pubkey) / 2;
		pubkey.data = PORT_ArenaZAlloc(arena, pubkey.len);
		if (pubkey.data != NULL) {
			len = cm_store_hex_to_bin(entry->cm_key_pubkey,
						  pubkey.data, pubkey.len);
			pubkey.len = len;
		}
	}
	if (pubkey.data == NULL) {
		if (entry->cm_key_pubkey_info != NULL) {
			pubkey_info = entry->cm_key_pubkey_info;
		} else {
			pubkey_info = entry->cm_cert_spki;
		}
		if (pubkey_info != NULL) {
			memset(&pubkeyinfo, 0, sizeof(pubkeyinfo));
			pubkeyinfo.len = strlen(pubkey_info) / 2;
			pubkeyinfo.data = PORT_ArenaZAlloc(arena,
							   pubkeyinfo.len);
			spki = NULL;
			if (pubkeyinfo.data != NULL) {
				len = cm_store_hex_to_bin(pubkey_info,
							  pubkeyinfo.data,
							  pubkeyinfo.len);
				pubkeyinfo.len = len;
				spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&pubkeyinfo);
			}
			if (spki != NULL) {
				pubkey.len = spki->subjectPublicKey.len / 8;
				pubkey.data = PORT_ArenaZAlloc(arena,
							       pubkey.len);
				if (pubkey.data != NULL) {
					memcpy(pubkey.data,
					       spki->subjectPublicKey.data,
					       pubkey.len);
				}
				SECKEY_DestroySubjectPublicKeyInfo(spki);
			}
		}
	}
	if (pubkey.data != NULL) {
		if (PK11_HashBuf(SEC_OID_SHA1, digest,
				 pubkey.data,
				 pubkey.len) != SECSuccess) {
			return NULL;
		}
		memset(&value, 0, sizeof(value));
		value.data = digest;
		value.len = 20;
		memset(&encoded, 0, sizeof(encoded));
		if (CERT_EncodeSubjectKeyID(arena, &value,
					    &encoded) == SECSuccess) {
			item = SECITEM_ArenaDupItem(arena, &encoded);
		} else {
			item = NULL;
		}
		return item;
	}
	return NULL;
}

/* Build an authorityInformationAccess extension value. */
static SECItem *
cm_certext_build_aia(struct cm_store_entry *entry, PLArenaPool *arena,
		     char **ocsp_location)
{
	CERTAuthInfoAccess *value, **values;
	CERTGeneralName *location;
	SECItem encoded, *item;
	SECOidData *oid;
	unsigned char *tmp;
	unsigned int i, j, n;

	oid = SECOID_FindOIDByTag(SEC_OID_PKIX_OCSP);
	if (oid == NULL) {
		return NULL;
	}
	for (n = 0;
	     (ocsp_location != NULL) && (ocsp_location[n] != NULL);
	     n++) {
		continue;
	}
	if (n == 0) {
		return NULL;
	}
	location = PORT_ArenaZAlloc(arena, sizeof(*location) * n);
	if (location == NULL) {
		return NULL;
	}
	value = PORT_ArenaZAlloc(arena, sizeof(*value) * n);
	if (value == NULL) {
		return NULL;
	}
	values = PORT_ArenaZAlloc(arena, sizeof(*values) * (n + 1));
	if (values == NULL) {
		return NULL;
	}
	for (i = 0, j = 0; i < n; i++) {
		if (strlen(ocsp_location[i]) == 0) {
			continue;
		}
		location[j].type = certURI;
		tmp = (unsigned char *) ocsp_location[i];
		location[j].name.other.data = tmp;
		location[j].name.other.len = strlen(ocsp_location[i]);
		value[j].method = oid->oid;
		value[j].location = &location[j];
		values[j] = &value[j];
		j++;
	}
	memset(&encoded, 0, sizeof(encoded));
	if (CERT_EncodeInfoAccessExtension(arena, values,
					   &encoded) == SECSuccess) {
		item = SECITEM_ArenaDupItem(arena, &encoded);
	} else {
		item = NULL;
	}
	return item;
}

/* Build a CRL distribution points or freshest CRL extension value. */
static SECItem *
cm_certext_build_crldp(struct cm_store_entry *entry, PLArenaPool *arena,
		       char **crldp)
{
	CERTCrlDistributionPoints decoded;
	CRLDistributionPoint *value, **values;
	CERTGeneralName *location;
	SECItem encoded, *item;
	unsigned int i, j, n;

	for (n = 0; (crldp != NULL) && (crldp[n] != NULL); n++) {
		continue;
	}
	if (n == 0) {
		return NULL;
	}
	location = PORT_ArenaZAlloc(arena, sizeof(*location) * n);
	if (location == NULL) {
		return NULL;
	}
	value = PORT_ArenaZAlloc(arena, sizeof(*value) * n);
	if (value == NULL) {
		return NULL;
	}
	values = PORT_ArenaZAlloc(arena, sizeof(*values) * (n + 1));
	if (values == NULL) {
		return NULL;
	}
	for (i = 0, j = 0; i < n; i++) {
		if (strlen(crldp[i]) == 0) {
			continue;
		}
		location[j].type = certURI;
		location[j].name.other.data = (unsigned char *) crldp[i];
		location[j].name.other.len = strlen(crldp[i]);
		location[j].l.next = &location[j].l;
		value[j].distPointType = generalName;
		value[j].distPoint.fullName = &location[j];
		values[j] = &value[j];
		j++;
	}
	decoded.distPoints = values;
	memset(&encoded, 0, sizeof(encoded));
	if (CERT_EncodeCRLDistributionPoints(arena, &decoded,
					     &encoded) == SECSuccess) {
		item = SECITEM_ArenaDupItem(arena, &encoded);
	} else {
		item = NULL;
	}
	return item;
}

/* Build a Netscape comment extension value. */
static SECItem *
cm_certext_build_ns_comment(struct cm_store_entry *entry, PLArenaPool *arena,
			    char *comment)
{
	SECItem value, encoded, *item;

	if (strlen(comment) == 0) {
		return NULL;
	}
	memset(&value, 0, sizeof(value));
	value.data = (unsigned char *) comment;
	value.len = strlen(comment);
	memset(&encoded, 0, sizeof(encoded));
	if (SEC_ASN1EncodeItem(arena, &encoded, &value,
			       SEC_IA5StringTemplate) == &encoded) {
		item = SECITEM_ArenaDupItem(arena, &encoded);
	} else {
		item = NULL;
	}
	return item;
}

/* Build a no-ocsp-checking extension value. */
static SECItem *
cm_certext_build_ocsp_no_check(struct cm_store_entry *entry,
			       PLArenaPool *arena)
{
	SECItem value, encoded, *item;

	memset(&value, 0, sizeof(value));
	value.data = NULL;
	value.len = 0;
	memset(&encoded, 0, sizeof(encoded));
	if (SEC_ASN1EncodeItem(arena, &encoded, &value,
			       SEC_NullTemplate) == &encoded) {
		item = SECITEM_ArenaDupItem(arena, &encoded);
	} else {
		item = NULL;
	}
	return item;
}

/* Build a Microsoft certtype extension value. */
static SECItem *
cm_certext_build_profile(struct cm_store_entry *entry,
			 PLArenaPool *arena,
			 char *profile)
{
	SECItem value, encoded, *item;
	unsigned int len = 0;

	if (strlen(profile) == 0) {
		return NULL;
	}
	memset(&value, 0, sizeof(value));
	memset(&encoded, 0, sizeof(encoded));
	if (cm_store_utf8_to_bmp_string(profile, &value.data, &len) != -1) {
		value.len = len;
		if (SEC_ASN1EncodeItem(arena, &encoded, &value,
				       SEC_BMPStringTemplate) == &encoded) {
			item = SECITEM_ArenaDupItem(arena, &encoded);
		} else {
			item = NULL;
		}
		free(value.data);
	} else {
		item = NULL;
	}
	return item;
}

/* Build a Netscape certtype extension value. */
static SECItem *
cm_certext_build_ns_certtype(struct cm_store_entry *entry,
			     PLArenaPool *arena,
			     char *certtype)
{
	char bitstring[] = "00000000";
	char *p, *q;
	int len = 0;

	if (strlen(certtype) == 0) {
		return NULL;
	}
	p = certtype;
	while (*p != '\0') {
		q = p + strcspn(p, ",");
		if (strncasecmp(p, "client", q - p) == 0) {
			bitstring[0] = '1';
		} else
		if (strncasecmp(p, "server", q - p) == 0) {
			bitstring[1] = '1';
		} else
		if (strncasecmp(p, "email", q - p) == 0) {
			bitstring[2] = '1';
		} else
		if (strncasecmp(p, "objsign", q - p) == 0) {
			bitstring[3] = '1';
		} else
		if (strncasecmp(p, "reserved", q - p) == 0) {
			bitstring[4] = '1';
		} else
		if (strncasecmp(p, "sslca", q - p) == 0) {
			bitstring[5] = '1';
		} else
		if (strncasecmp(p, "emailca", q - p) == 0) {
			bitstring[6] = '1';
		} else
		if (strncasecmp(p, "objca", q - p) == 0) {
			bitstring[7] = '1';
		}
		p = q + strspn(q, ",");
	}
	if (strchr(bitstring, '1') != NULL) {
		len = strrchr(bitstring, '1') - bitstring;
		p[len + 1] = '\0';
		return cm_certext_build_bitstring(entry, arena, bitstring);
	} else {
		return NULL;
	}
}

/* Build a requestedExtensions attribute. */
void
cm_certext_build_csr_extensions(struct cm_store_entry *entry,
				NSSInitContext *ctx,
				unsigned char **extensions, size_t *length)
{
	PLArenaPool *arena;
	CERTCertExtension ext[13], *exts[14], **exts_ptr;
	SECOidData *oid;
	SECItem *item, encoded;
	SECItem der_false = {
		.len = 1,
		.data = (unsigned char *) "\000",
	};
	SECItem der_true = {
		.len = 1,
		.data = (unsigned char *) "\377",
	};
	int i;
	char **tmp, *comment;
	const char *reason;
	NSSInitContext *local_ctx = NULL;
	const SEC_ASN1Template *template;

	*extensions = NULL;
	*length = 0;
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		return;
	}
	memset(&ext, 0, sizeof(ext));
	memset(&exts, 0, sizeof(exts));

	if (ctx == NULL) {
		local_ctx = NSS_InitContext(entry->cm_key_storage_location,
					    NULL, NULL, NULL, NULL,
					    NSS_INIT_READONLY |
					    NSS_INIT_NOCERTDB |
					    NSS_INIT_NOROOTINIT);
		if (local_ctx == NULL) {
			cm_log(1, "Error initializing NSS.\n");
			return;
		}
		reason = util_n_fips_hook();
		if (reason != NULL) {
			cm_log(1, "Error putting NSS into FIPS mode: %s\n",
			       reason);
			return;
		}
	}

	/* Build the extensions. */
	i = 0;
	item = cm_certext_build_ku(entry, arena, entry->cm_template_ku);
	if (item != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_KEY_USAGE);
		if (oid != NULL) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	item = cm_certext_build_san(entry, arena,
				    entry->cm_template_hostname,
				    entry->cm_template_email,
				    entry->cm_template_principal,
				    entry->cm_template_ipaddress);
	if (item != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_SUBJECT_ALT_NAME);
		if (oid != NULL) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	item = cm_certext_build_eku(entry, arena, entry->cm_template_eku);
	if (item != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_EXT_KEY_USAGE);
		if (oid != NULL) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	item = cm_certext_build_basic(entry, arena,
				      entry->cm_template_is_ca,
				      entry->cm_template_ca_path_length);
	if (item != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_BASIC_CONSTRAINTS);
		if (oid != NULL) {
			ext[i].id = oid->oid;
			ext[i].critical = der_true;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	if (entry->cm_template_is_ca) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_AUTH_KEY_ID);
		item = cm_certext_build_self_akid(entry, arena);
		if ((item != NULL) && (oid != NULL)) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	item = cm_certext_build_skid(entry, arena);
	if (item != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_SUBJECT_KEY_ID);
		if (oid != NULL) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	if (entry->cm_template_ocsp_location != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_AUTH_INFO_ACCESS);
		item = cm_certext_build_aia(entry, arena,
					    entry->cm_template_ocsp_location);
		if ((item != NULL) && (oid != NULL)) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	if (entry->cm_template_crl_distribution_point != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_CRL_DIST_POINTS);
		tmp = entry->cm_template_crl_distribution_point;
		item = cm_certext_build_crldp(entry, arena, tmp);
		if ((item != NULL) && (oid != NULL)) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	if (entry->cm_template_freshest_crl != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_X509_FRESHEST_CRL);
		tmp = entry->cm_template_freshest_crl;
		item = cm_certext_build_crldp(entry, arena, tmp);
		if ((item != NULL) && (oid != NULL)) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	if (entry->cm_template_ns_comment != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_NS_CERT_EXT_COMMENT);
		comment = entry->cm_template_ns_comment;
		item = cm_certext_build_ns_comment(entry, arena, comment);
		if ((item != NULL) && (oid != NULL)) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	if (entry->cm_template_no_ocsp_check) {
		oid = SECOID_FindOIDByTag(SEC_OID_PKIX_OCSP_NO_CHECK);
		item = cm_certext_build_ocsp_no_check(entry, arena);
		if ((item != NULL) && (oid != NULL)) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	if (entry->cm_template_profile != NULL) {
		oid = (SECOidData *) &oid_microsoft_certtype;
		item = cm_certext_build_profile(entry, arena,
						entry->cm_template_profile);
		if ((item != NULL) && (oid != NULL)) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	if (entry->cm_template_ns_certtype != NULL) {
		oid = SECOID_FindOIDByTag(SEC_OID_NS_CERT_EXT_CERT_TYPE);
		item = cm_certext_build_ns_certtype(entry, arena,
						    entry->cm_template_ns_certtype);
		if ((item != NULL) && (oid != NULL)) {
			ext[i].id = oid->oid;
			ext[i].critical = der_false;
			ext[i].value = *item;
			exts[i] = &ext[i];
			i++;
		}
	}
	exts[i++] = NULL;
	exts_ptr = exts;
	/* Encode the sequence. */
	memset(&encoded, 0, sizeof(encoded));
	if (i > 1) {
		template = cm_certext_sequence_of_cert_extension_template;
		if (SEC_ASN1EncodeItem(arena, &encoded, &exts_ptr,
				       template) == &encoded) {
			*extensions = talloc_memdup(entry, encoded.data,
						    encoded.len);
			if (*extensions != NULL) {
				*length = encoded.len;
			}
		}
	} else {
		*extensions = NULL;
		*length = 0;
	}

	if (ctx == NULL) {
		if (NSS_ShutdownContext(local_ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
	}

	PORT_FreeArena(arena, PR_TRUE);
}

/* Read a basicConstraints extension. */
static void
cm_certext_read_basic(struct cm_store_entry *entry, PLArenaPool *arena,
		      CERTCertExtension *ext)
{
	CERTBasicConstraints basic;

	if (CERT_DecodeBasicConstraintValue(&basic,
					    &ext->value) != SECSuccess) {
		return;
	}
	entry->cm_cert_is_ca = (basic.isCA != PR_FALSE);
	if (entry->cm_cert_is_ca) {
		entry->cm_cert_ca_path_length = basic.pathLenConstraint;
	} else {
		entry->cm_cert_ca_path_length = -1;
	}
}

/* Read a Netscape comment extension. */
static void
cm_certext_read_nsc(struct cm_store_entry *entry, PLArenaPool *arena,
		    CERTCertExtension *ext)
{
	SECItem comment;
	char *tmp;

	if (SEC_ASN1DecodeItem(arena, &comment,
			       SEC_IA5StringTemplate,
			       &ext->value) != SECSuccess) {
		return;
	}
	talloc_free(entry->cm_cert_ns_comment);
	if (comment.len > 0) {
		tmp = (char *) comment.data;
		entry->cm_cert_ns_comment = talloc_strndup(entry, tmp,
							   comment.len);
	} else {
		entry->cm_cert_ns_comment = NULL;
	}
}

/* Read an authorityInformationAccess extension, and keep track of any OCSP
 * responders that we find in it. */
static void
cm_certext_read_aia(struct cm_store_entry *entry, PLArenaPool *arena,
		    CERTCertExtension *ext)
{
	CERTAuthInfoAccess **aia;
	SECOidData *oid;
	SECItem uri;
	char *tmp;
	unsigned i, n;

	aia = CERT_DecodeAuthInfoAccessExtension(arena, &ext->value);
	if ((aia == NULL) || (aia[0] == NULL)) {
		return;
	}
	oid = SECOID_FindOIDByTag(SEC_OID_PKIX_OCSP);
	if (oid == NULL) {
		return;
	}
	for (i = 0, n = 0; aia[i] != NULL; i++) {
		if (SECITEM_ItemsAreEqual(&aia[i]->method, &oid->oid) &&
		    (aia[i]->location != NULL) &&
		    (aia[i]->location->type == certURI) &&
		    (aia[i]->location->name.other.len > 0)) {
			n++;
		}
	}
	talloc_free(entry->cm_cert_ocsp_location);
	entry->cm_cert_ocsp_location = talloc_zero_array(entry, char *, n + 1);
	if (entry->cm_cert_ocsp_location == NULL) {
		return;
	}
	for (i = 0, n = 0; aia[i] != NULL; i++) {
		if (SECITEM_ItemsAreEqual(&aia[i]->method, &oid->oid) &&
		    (aia[i]->location != NULL) &&
		    (aia[i]->location->type == certURI) &&
		    (aia[i]->location->name.other.len > 0)) {
			uri = aia[i]->location->name.other;
			tmp = talloc_strndup(entry->cm_cert_ocsp_location,
					     (char *) uri.data, uri.len);
			entry->cm_cert_ocsp_location[n++] = tmp;
		}
	}
}

/* Read a CRL distribution points or freshest CRL extension, and return any
 * locations that we find in it. */
static void
cm_certext_read_crlext(struct cm_store_entry *entry, PLArenaPool *arena,
		       CERTCertExtension *ext, char ***dest)
{
	CERTCrlDistributionPoints *crldp;
	CERTGeneralName *name;
	SECItem uri;
	void *parent;
	char *tmp, **list = *dest;
	unsigned i, n;

	crldp = CERT_DecodeCRLDistributionPoints(arena, &ext->value);
	if ((crldp == NULL) || (crldp->distPoints == NULL)) {
		return;
	}
	for (i = 0, n = 0; crldp->distPoints[i] != NULL; i++) {
		if ((crldp->distPoints[i]->distPointType == generalName) &&
		    (crldp->distPoints[i]->distPoint.fullName != NULL)) {
			name = crldp->distPoints[i]->distPoint.fullName;
			if (name->type == certURI) {
				n++;
			}
		}
	}
	talloc_free(list);
	list = talloc_zero_array(entry, char *, n + 1);
	if (list == NULL) {
		*dest = list;
		return;
	}
	for (i = 0, n = 0; crldp->distPoints[i] != NULL; i++) {
		if ((crldp->distPoints[i]->distPointType == generalName) &&
		    (crldp->distPoints[i]->distPoint.fullName != NULL)) {
			name = crldp->distPoints[i]->distPoint.fullName;
			if (name->type == certURI) {
				uri = name->name.other;
				parent = list;
				tmp = talloc_strndup(parent,
						     (char *) uri.data,
						     uri.len);
				list[n++] = tmp;
			}
		}
	}
	*dest = list;
}

/* Read the list of CRL distribution points. */
static void
cm_certext_read_crldp(struct cm_store_entry *entry, PLArenaPool *arena,
		      CERTCertExtension *ext)
{
	cm_certext_read_crlext(entry, arena, ext,
			       &entry->cm_cert_crl_distribution_point);
}

/* Read the list of locations where we can find the freshest CRL. */
static void
cm_certext_read_freshest_crl(struct cm_store_entry *entry, PLArenaPool *arena,
			     CERTCertExtension *ext)
{
	cm_certext_read_crlext(entry, arena, ext, &entry->cm_cert_freshest_crl);
}

/* Parse the data from a Microsoft certificate type extension. */
static void
cm_certext_read_profile(struct cm_store_entry *entry, PLArenaPool *arena,
			CERTCertExtension *ext)
{
	SECItem profile;
	char *tmp;

	memset(&profile, 0, sizeof(profile));
	if (SEC_ASN1DecodeItem(arena, &profile,
			       SEC_BMPStringTemplate,
			       &ext->value) != SECSuccess) {
		return;
	}
	talloc_free(entry->cm_cert_profile);
	entry->cm_cert_profile = NULL;
	if (profile.len > 0) {
		tmp = cm_store_utf8_from_bmp_string(profile.data, profile.len);
		if (tmp != NULL) {
			entry->cm_cert_profile = talloc_strdup(entry, tmp);
			free(tmp);
		}
	}
}

/* Parse the data from a Netscape certificate type extension. */
static void
cm_certext_read_ns_certtype(struct cm_store_entry *entry, PLArenaPool *arena,
			    CERTCertExtension *ext)
{
	SECItem item;
	unsigned int i, bit;
	char *tmp = NULL, *t = NULL;

	if (SEC_ASN1DecodeItem(arena, &item, SEC_BitStringTemplate,
			       &ext->value) == SECSuccess) {
		/* A bitString decodes with length == number of bits, not
		 * bytes, which is what we want anyway. */
		tmp = talloc_zero_size(entry, item.len + 1);
		for (i = 0; i < item.len; i++) {
			bit = (item.data[i / 8] & (0x80 >> (i % 8))) ? 1 : 0;
			sprintf(tmp + i, "%.*u", 1, bit);
		}
	}
	talloc_free(entry->cm_cert_ns_certtype);
	entry->cm_cert_ns_certtype = NULL;
	if (tmp == NULL) {
		return;
	}
	t = talloc_strdup(entry, "");
	if ((tmp != NULL) && (strlen(tmp) > 0)) {
		if (tmp[0] == '1') {
			t = talloc_strdup_append(t, ",client");
		}
	}
	if ((tmp != NULL) && (strlen(tmp) > 1)) {
		if (tmp[1] == '1') {
			t = talloc_strdup_append(t, ",server");
		}
	}
	if ((tmp != NULL) && (strlen(tmp) > 2)) {
		if (tmp[2] == '1') {
			t = talloc_strdup_append(t, ",email");
		}
	}
	if ((tmp != NULL) && (strlen(tmp) > 3)) {
		if (tmp[3] == '1') {
			t = talloc_strdup_append(t, ",objsign");
		}
	}
	if ((tmp != NULL) && (strlen(tmp) > 4)) {
		if (tmp[4] == '1') {
			t = talloc_strdup_append(t, ",reserved");
		}
	}
	if ((tmp != NULL) && (strlen(tmp) > 5)) {
		if (tmp[5] == '1') {
			t = talloc_strdup_append(t, ",sslCA");
		}
	}
	if ((tmp != NULL) && (strlen(tmp) > 6)) {
		if (tmp[6] == '1') {
			t = talloc_strdup_append(t, ",emailCA");
		}
	}
	if ((tmp != NULL) && (strlen(tmp) > 7)) {
		if (tmp[7] == '1') {
			t = talloc_strdup_append(t, ",objCA");
		}
	}
	if (strlen(t) > 0) {
		entry->cm_cert_ns_certtype = talloc_strdup(entry, t + 1);
	}
	talloc_free(t);
}

/* Read the extensions from a certificate. */
void
cm_certext_read_extensions(struct cm_store_entry *entry, PLArenaPool *arena,
			   CERTCertExtension **extensions)
{
	int i;
	PLArenaPool *local_arena;
	SECOidData *ku_oid, *eku_oid, *san_oid, *freshest_crl_oid;
	SECOidData *basic_oid, *nsc_oid, *aia_oid, *crldp_oid, *profile_oid;
	SECOidData *no_ocsp_check_oid, *ns_certtype_oid;

	if (extensions == NULL) {
		return;
	}

	if (arena == NULL) {
		local_arena = PORT_NewArena(sizeof(double));
		arena = local_arena;
	} else {
		local_arena = NULL;
	}

	ku_oid = SECOID_FindOIDByTag(SEC_OID_X509_KEY_USAGE);
	if (ku_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "certificate key usage extension.\n");
		return;
	}
	eku_oid = SECOID_FindOIDByTag(SEC_OID_X509_EXT_KEY_USAGE);
	if (eku_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "certificate extended key usage extension.\n");
		return;
	}
	san_oid = SECOID_FindOIDByTag(SEC_OID_X509_SUBJECT_ALT_NAME);
	if (san_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "certificate subject alternative name extension.\n");
		return;
	}
	basic_oid = SECOID_FindOIDByTag(SEC_OID_X509_BASIC_CONSTRAINTS);
	if (basic_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "certificate basic constraints extension.\n");
		return;
	}
	nsc_oid = SECOID_FindOIDByTag(SEC_OID_NS_CERT_EXT_COMMENT);
	if (nsc_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "certificate netscape comment extension.\n");
		return;
	}
	aia_oid = SECOID_FindOIDByTag(SEC_OID_X509_AUTH_INFO_ACCESS);
	if (aia_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "certificate authority information access extension.\n");
		return;
	}
	crldp_oid = SECOID_FindOIDByTag(SEC_OID_X509_CRL_DIST_POINTS);
	if (crldp_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "certificate revocation list distribution points "
		       "extension.\n");
		return;
	}
	freshest_crl_oid = SECOID_FindOIDByTag(SEC_OID_X509_FRESHEST_CRL);
	if (freshest_crl_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "freshest certificate revocation list extension.\n");
		return;
	}
	no_ocsp_check_oid = SECOID_FindOIDByTag(SEC_OID_PKIX_OCSP_NO_CHECK);
	if (no_ocsp_check_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "no-OCSP-check extension.\n");
		return;
	}
	profile_oid = (SECOidData *) &oid_microsoft_certtype;
	ns_certtype_oid = SECOID_FindOIDByTag(SEC_OID_NS_CERT_EXT_CERT_TYPE);
	if (ns_certtype_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "nsCertType extension.\n");
		return;
	}
	entry->cm_cert_no_ocsp_check = FALSE;
	for (i = 0; extensions[i] != NULL; i++) {
		if (SECITEM_ItemsAreEqual(&ku_oid->oid, &extensions[i]->id)) {
			cm_certext_read_ku(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&eku_oid->oid, &extensions[i]->id)) {
			cm_certext_read_eku(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&san_oid->oid, &extensions[i]->id)) {
			cm_certext_read_san(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&basic_oid->oid,
					  &extensions[i]->id)) {
			cm_certext_read_basic(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&nsc_oid->oid, &extensions[i]->id)) {
			cm_certext_read_nsc(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&aia_oid->oid, &extensions[i]->id)) {
			cm_certext_read_aia(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&crldp_oid->oid,
					  &extensions[i]->id)) {
			cm_certext_read_crldp(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&freshest_crl_oid->oid,
					  &extensions[i]->id)) {
			cm_certext_read_freshest_crl(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&profile_oid->oid,
					  &extensions[i]->id)) {
			cm_certext_read_profile(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&no_ocsp_check_oid->oid,
					  &extensions[i]->id)) {
			entry->cm_cert_no_ocsp_check = TRUE;
		}
		if (SECITEM_ItemsAreEqual(&ns_certtype_oid->oid,
					  &extensions[i]->id)) {
			cm_certext_read_ns_certtype(entry, arena, extensions[i]);
		}
	}
	if (arena == local_arena) {
		PORT_FreeArena(local_arena, PR_TRUE);
	}
}
