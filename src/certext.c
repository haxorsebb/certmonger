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

#include "certext.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

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

static void
cm_certext_read_san(struct cm_store_entry *entry, PLArenaPool *arena,
		    CERTCertExtension *san_ext)
{
	CERTGeneralName *name, *san;
	unsigned int i;
	name = CERT_DecodeAltNameExtension(arena, &san_ext->value);
	if (name != NULL) {
		cm_log(3, "Got name(s).\n");
	}
	san = name;
	i = 0;
	while (san != NULL) {
		cm_log(3, "SAN value %d.\n", i);
		switch (san->type) {
		case certDNSName:
			cm_log(3, "dnsName\n", i);
			break;
		case certRFC822Name:
			cm_log(3, "email\n", i);
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
			cm_log(1, "Extension %d: key usage.\n", i);
			cm_certext_read_ku(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&eku_oid->oid, &extensions[i]->id)) {
			cm_log(1, "Extension %d: extended key usage.\n", i);
			cm_certext_read_eku(entry, arena, extensions[i]);
		}
		if (SECITEM_ItemsAreEqual(&san_oid->oid, &extensions[i]->id)) {
			cm_log(1, "Extension %d: subjectaltname.\n", i);
			cm_certext_read_san(entry, arena, extensions[i]);
		}
	}
	if (arena == local_arena) {
		PORT_FreeArena(local_arena, PR_TRUE);
	}
}
