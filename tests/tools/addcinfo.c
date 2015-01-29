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

#include "../../src/config.h"

#include <sys/types.h>
#include <sys/unistd.h>
#include <stdio.h>
#include <string.h>

#include <prerror.h>
#include <secasn1.h>
#include <secitem.h>
#include <secoid.h>

#include "../../src/log.h"

struct content_info {
	SECItem content_type, content;
};

static const SEC_ASN1Template
content_info_template[] = {
	{
		.kind = SEC_ASN1_SEQUENCE,
		.offset = 0,
		.sub = NULL,
		.size = sizeof(struct content_info),
	},
	{
		.kind = SEC_ASN1_OBJECT_ID,
		.offset = offsetof(struct content_info, content_type),
		.sub = &SEC_ObjectIDTemplate,
		.size = sizeof(SECItem),
	},
	{
		.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
			SEC_ASN1_CONSTRUCTED |
			SEC_ASN1_EXPLICIT,
		.offset = offsetof(struct content_info, content),
		.sub = &SEC_AnyTemplate,
		.size = sizeof(SECItem),
	},
	{ 0, 0, NULL, 0 },
};


int
main(int argc, char **argv)
{
	unsigned char *buffer = NULL, buf[BUFSIZ];
	int i, n = 0;
	unsigned int j;
	SECItem encoded;
	SECOidData *enveloped;
	struct content_info ci;

	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	while ((i = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		buffer = realloc(buffer, n + i);
		if (buffer == NULL) {
			cm_log(0, "Out of memory.\n");
			return 1;
		}
		memcpy(buffer + n, buf, i);
		n += i;
	}
	memset(&ci, 0, sizeof(ci));
	enveloped = SECOID_FindOIDByTag(SEC_OID_PKCS7_ENVELOPED_DATA);
	if (enveloped == NULL) {
		cm_log(0, "Internal error: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		return 1;
	}
	ci.content_type = enveloped->oid;
	ci.content.data = buffer;
	ci.content.len = n;
	memset(&encoded, 0, sizeof(encoded));
	if (SEC_ASN1EncodeItem(NULL, &encoded, &ci,
			       content_info_template) != &encoded) {
		cm_log(0, "Encoding error: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		return 1;
	}
	n = encoded.len;
	j = 0;
	while ((i = write(STDOUT_FILENO, encoded.data + j, encoded.len - j)) > 0) {
		j += i;
		if (j >= encoded.len) {
			break;
		}
	}
	return 0;
}
