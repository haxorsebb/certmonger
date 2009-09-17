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
#include "log.h"
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

static void
cm_certext_read_ku(struct cm_store_entry *entry, PLArenaPool *arena,
		   CERTCertExtension *ku_ext)
{
	SECItem item;
	unsigned int i, bit;
	if (SEC_ASN1DecodeItem(arena, &item, SEC_BitStringTemplate,
			       &ku_ext->value) == SECSuccess) {
		talloc_free(entry->cm_cert_ku);
		entry->cm_cert_ku = talloc_zero_size(entry, item.len + 1);
		for (i = 0; i < item.len; i++) {
			bit = (item.data[i / 8] & (0x80 >> (i % 8))) ? 1 : 0;
			sprintf(entry->cm_cert_ku + i, "%.*d", 1, bit);
		}
	}
}

SECItem *
cm_certext_build_ku(struct cm_store_entry *entry, PLArenaPool *arena)
{
	SECItem *ret, encoded, *bits;
	unsigned int i, val, len;
	if (entry->cm_cert_ku == NULL) {
		return NULL;
	}
	bits = SECITEM_AllocItem(arena, NULL, strlen(entry->cm_cert_ku));
	if (bits == NULL) {
		return NULL;
	}
	for (i = 0;
	     (entry->cm_cert_ku != NULL) && (entry->cm_cert_ku[i] != '\0');
	     i++) {
		val = (entry->cm_cert_ku[i] == '1') << (i % 8);
		bits->data[i / 8] |= val;
	}
	len = bits->len;
	bits->len = i;
	memset(&encoded, 0, sizeof(encoded));
	if (SEC_ASN1EncodeItem(arena, &encoded, &bits,
			       SEC_BitStringTemplate) != &encoded) {
		ret = NULL;
	} else {
		ret = SECITEM_ArenaDupItem(arena, &encoded);
	}
	bits->len = len;
	return ret;
}

static void
cm_certext_read_eku(struct cm_store_entry *entry, PLArenaPool *arena,
		    CERTCertExtension *eku_ext)
{
	SECItem **oids;
	SECOidData *oid;
	unsigned int i;
	char *s;
	if (SEC_ASN1DecodeItem(arena, &oids, SEC_SequenceOfObjectIDTemplate,
			       &eku_ext->value) == SECSuccess) {
		talloc_free(entry->cm_cert_eku);
		entry->cm_cert_eku = NULL;
		for (i = 0; oids[i] != NULL; i++) {
			oid = SECOID_FindOID(oids[i]);
			if (oid != NULL) {
				if (entry->cm_cert_eku != NULL) {
					s = talloc_asprintf(entry, "%s,%s",
							    entry->cm_cert_eku,
							    oid->desc);
					talloc_free(entry->cm_cert_eku);
					entry->cm_cert_eku = s;
				} else {
					s = talloc_strdup(entry, oid->desc);
					talloc_free(entry->cm_cert_eku);
					entry->cm_cert_eku = s;
				}
			}
		}
	}
}

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
		/* Convert that into a string. */
		if (krb5_unparse_name(ctx, &princ, &unparsed) == 0) {
			ret = talloc_strdup(parent, unparsed);
			krb5_free_unparsed_name(ctx, unparsed);
		}
		talloc_free(princ.data);
		krb5_free_context(ctx);
	}
	return ret;
}

static void
cm_certext_read_other_name(struct cm_store_entry *entry, PLArenaPool *arena,
			   CERTGeneralName *name)
{
	SECItem *item, upn;
	struct kerberos_principal_name p;
	item = &name->name.OthName.name;
	if (SECITEM_ItemsAreEqual(&name->name.OthName.oid,
				  &oid_pkinit_san.oid)) {
		memset(&p, 0, sizeof(p));
		if (SEC_ASN1DecodeItem(arena, &p,
				       cm_kerberos_principal_name_template,
				       item) == SECSuccess) {
			entry->cm_cert_principal = cm_certext_parse_principal(entry, &p);
		}
	}
	if (SECITEM_ItemsAreEqual(&name->name.OthName.oid,
				  &oid_ms_upn_name.oid)) {
		memset(&upn, 0, sizeof(upn));
		if (SEC_ASN1DecodeItem(arena, &upn,
				       cm_ms_upn_name_template,
				       item) == SECSuccess) {
			entry->cm_cert_principal = talloc_strndup(entry,
								  (char *)
								  upn.data,
								  upn.len);
		} else
		if (SEC_ASN1DecodeItem(arena, &upn,
				       SEC_UTF8StringTemplate,
				       item) == SECSuccess) {
			entry->cm_cert_principal = talloc_strndup(entry,
								  (char *)
								  upn.data,
								  upn.len);
		}
	}
}

static void
cm_certext_read_san(struct cm_store_entry *entry, PLArenaPool *arena,
		    CERTCertExtension *san_ext)
{
	CERTGeneralName *name, *san;
	unsigned int i;
	char *s;
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
			s = talloc_strndup(entry, (char *) san->name.other.data,
					   san->name.other.len);
			entry->cm_cert_hostname = s;
			break;
		case certIPAddress:
			/* binary data - see rfc5280 */
			break;
		case certRFC822Name:
			s = talloc_strndup(entry, (char *) san->name.other.data,
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
		       "key usage extension.\n");
		return;
	}
	eku_oid = SECOID_FindOIDByTag(SEC_OID_X509_EXT_KEY_USAGE);
	if (eku_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "extended key usage extension.\n");
		return;
	}
	san_oid = SECOID_FindOIDByTag(SEC_OID_X509_SUBJECT_ALT_NAME);
	if (san_oid == NULL) {
		cm_log(1, "Internal library error: unable to look up OID for "
		       "subject alternative name extension.\n");
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
