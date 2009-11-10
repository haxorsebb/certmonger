/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#include <nss.h>
#include <certt.h>
#include <cert.h>
#include <secoid.h>
#include <secoidt.h>
#include <secasn1.h>

#include <talloc.h>

#include <krb5.h>

#include "certext.h"
#include "certext-n.h"
#include "log.h"
#include "oiddict.h"
#include "store.h"
#include "store-int.h"

/* Structures and templates for parsing principal name otherName values. */
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
			sprintf(entry->cm_cert_ku + i, "%.*d", 1, bit);
		}
	}
}

/* Build a keyUsage extension value from a string, with each bit being
 * represented by either a "1" or a "0", most significant bit first. */
static SECItem *
cm_certext_build_ku(struct cm_store_entry *entry, PLArenaPool *arena,
		    const char *ku_value)
{
	SECItem *ret, encoded, *bits;
	unsigned int i, val, len;
	if ((ku_value == NULL) || (strlen(ku_value) == 0)) {
		return NULL;
	}
	len = strlen(ku_value ? ku_value : "") + 1;
	bits = SECITEM_AllocItem(arena, NULL, len);
	memset(bits->data, '\0', len);
	for (i = 0; (ku_value != NULL) && (ku_value[i] != '\0'); i++) {
		val = ((ku_value[i] == '1') ? 0x80 : 0x00) >> (i % 8);
		bits->data[i / 8] |= val;
	}
	/* A bitString encodes with length == number of bits, not bytes, but
	 * luckily we have that information. */
	bits->len = i;
	memset(&encoded, 0, sizeof(encoded));
	if (SEC_ASN1EncodeItem(arena, &encoded, bits,
			       SEC_BitStringTemplate) != &encoded) {
		ret = NULL;
	} else {
		ret = SECITEM_ArenaDupItem(arena, &encoded);
	}
	return ret;
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
				       "Couldn't parse OID \"%s\", ignoring.\n",
				       q - p, p);
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
	ret = NULL;
	ctx = NULL;
	if (krb5_init_context(&ctx) == 0) {
		memset(&princ, 0, sizeof(princ));
		/* Copy the realm over. */
		princ.realm.length = p->realm.name.len;
		princ.realm.data = (char *) p->realm.name.data;
		/* Count the number of name components. */
		comps = p->principal_name.name_string;
		for (i = 0; (comps != NULL) && (comps[i] != NULL); i++) {
			continue;
		}
		/* Set the number of name components. */
		princ.length = i;
		/* Allocate and populate the name components. */
		princ.data = talloc_zero_array(parent, krb5_data, i);
		if (princ.data != NULL) {
			for (j = 0; j < i; j++) {
				princ.data[j].length = comps[j]->len;
				princ.data[j].data = (char *) comps[j]->data;
			}
		}
		/* Try to decode the name type. */
		if (SEC_ASN1DecodeInteger(&p->principal_name.name_type,
					  &name_type) != SECSuccess) {
			/* Try to decode the name type. */
			name_type = KRB5_NT_UNKNOWN;
		}
		princ.type = name_type;
		/* Convert that into a string.  Use the library function so
		 * that it can take care of escaping. */
		if (krb5_unparse_name(ctx, &princ, &unparsed) == 0) {
			ret = talloc_strdup(parent, unparsed);
			krb5_free_unparsed_name(ctx, unparsed);
		}
		talloc_free(princ.data);
		krb5_free_context(ctx);
	}
	return ret;
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
}

/* Extract applicable subjectAltName values. */
static void
cm_certext_read_san(struct cm_store_entry *entry, PLArenaPool *arena,
		    CERTCertExtension *san_ext)
{
	CERTGeneralName *name, *san;
	unsigned int i, j;
	char **s;
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
			break;
		case certIPAddress:
			/* binary data - see rfc5280 - XXX */
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
	p.realm.name.data = (unsigned char *) krb5_princ_realm(ctx, princ)->data;
	p.realm.name.len = krb5_princ_realm(ctx, princ)->length;
	/* name type */
	if (SEC_ASN1EncodeInteger(arena, &p.principal_name.name_type,
				  krb5_princ_type(ctx, princ)) !=
	    &p.principal_name.name_type) {
		memset(&p.principal_name.name_type, 0,
		       sizeof(p.principal_name.name_type));
	}
	/* the component names */
	comp = PORT_ArenaZAlloc(arena,
				sizeof(SECItem) * krb5_princ_size(ctx, princ));
	comps = PORT_ArenaZAlloc(arena,
				 sizeof(SECItem *) * (krb5_princ_size(ctx, princ) + 1));
	if (comp != NULL) {
		for (i = 0; i < krb5_princ_size(ctx, princ); i++) {
			comp[i].len = krb5_princ_component(ctx, princ, i)->length;
			comp[i].data = (unsigned char *) krb5_princ_component(ctx, princ, i)->data;
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
		     char **hostname, char **email, char **principal)
{
	CERTGeneralName *name, *next;
	SECItem encoded, *item;
	int i, j;
	/* Anything to do? */
	if ((hostname == NULL) && (email == NULL) && (principal == NULL)) {
		return NULL;
	}
	name = NULL;
	/* Build a list of dnsName values. */
	for (i = 0; (hostname != NULL) && (hostname[i] != NULL); i++) {
		next = PORT_ArenaZAlloc(arena, sizeof(*next));
		if (next != NULL) {
			next->type = certDNSName;
			next->name.other.len = strlen(hostname[i]);
			next->name.other.data = (unsigned char *) hostname[i];
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

/* Build a requestedExtensions attribute. */
void
cm_certext_build_csr_extensions(struct cm_store_entry *entry,
				unsigned char **extensions, size_t *length)
{
	PLArenaPool *arena;
	CERTCertExtension ext[3], *exts[4], **exts_ptr;
	SECOidData *oid;
	SECItem *item, encoded;
	SECItem der_false = {
		.len = 1,
		.data = (unsigned char *) "\000",
	};
	int i;

	*extensions = NULL;
	*length = 0;
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		return;
	}
	memset(&ext, 0, sizeof(ext));
	memset(&exts, 0, sizeof(exts));

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
				    entry->cm_template_principal);
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
	exts[i++] = NULL;
	exts_ptr = exts;
	/* Encode the sequence. */
	memset(&encoded, 0, sizeof(encoded));
	if (i > 1) {
		if (SEC_ASN1EncodeItem(arena, &encoded, &exts_ptr,
				       cm_certext_sequence_of_cert_extension_template) == &encoded) {
			*extensions = talloc_memdup(entry, encoded.data, encoded.len);
			if (*extensions != NULL) {
				*length = encoded.len;
			}
		}
	} else {
		*extensions = NULL;
		*length = 0;
	}
	PORT_FreeArena(arena, PR_TRUE);
}

/* Read the extensions from a certificate. */
void
cm_certext_read_extensions(struct cm_store_entry *entry, PLArenaPool *arena,
			   CERTCertExtension **extensions)
{
	int i;
	char *ku, *eku, *principal, *hostname, *email;
	PLArenaPool *local_arena;

	SECOidData *ku_oid, *eku_oid, *san_oid;
	if (extensions == NULL) {
		return;
	}

	if (arena == NULL) {
		local_arena = PORT_NewArena(sizeof(double));
		arena = local_arena;
	} else {
		local_arena = NULL;
	}

	ku = NULL;
	eku = NULL;
	principal = NULL;
	hostname = NULL;
	email = NULL;
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
	}
	if (arena == local_arena) {
		PORT_FreeArena(local_arena, PR_TRUE);
	}
}
