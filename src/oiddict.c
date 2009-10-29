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

#include <stdlib.h>
#include <string.h>

#include <talloc.h>

static const struct {
	const char *name;
	const char *oidish;
} cm_named_oids[] = {
	{"id-pkix", "1.3.6.1.5.5.7"},
	{"id-pe", "id-pkix.1"},
	{"id-kp", "id-pkix.3"},
	{"id-kp-serverAuth", "id-kp.1"},
	{"id-kp-clientAuth", "id-kp.2"},
	{"id-kp-codeSigning", "id-kp.3"},
	{"id-kp-emailProtection", "id-kp.4"},
	{"id-kp-timeStamping", "id-kp.8"},
	{"id-kp-OCSPSigning", "id-kp.9"},
	{"id-pkinit", "1.3.6.1.5.2.3"},
	{"id-pkinit-KPClientAuth", "id-pkinit.4"},
	{"id-pkinit-KPKdc", "id-pkinit.5"},
};

static int
cm_is_a_prefix(const char *possible_prefix, const char *value)
{
	unsigned int len;
	len = strlen(possible_prefix);
	if (strlen(value) < len) {
		return 0;
	}
	if (strncasecmp(possible_prefix, value, len) != 0) {
		return 0;
	}
	return ((value[len] == '.') || (value[len] == 0));
}

char *
cm_oid_to_name(void *ctx, const char *oid)
{
	char *p, *q;
	unsigned int i, len;
	p = talloc_strdup(ctx, oid);
	for (i = 0;
	     i < sizeof(cm_named_oids) / sizeof(cm_named_oids[0]);
	     i++) {
		if (cm_is_a_prefix(cm_named_oids[i].oidish, p)) {
			len = strlen(cm_named_oids[i].oidish);
			q = talloc_asprintf(ctx, "%s%s",
					    cm_named_oids[i].name,
					    p + len);
			talloc_free(p);
			p = q;
		}
	}
	return p;
}

char *
cm_oid_from_name(void *ctx, const char *name)
{
	char *p, *q;
	int i, len;
	p = talloc_strdup(ctx, name);
	for (i = sizeof(cm_named_oids) / sizeof(cm_named_oids[0]) - 1;
	     i >= 0;
	     i--) {
		if (cm_is_a_prefix(cm_named_oids[i].name, p)) {
			len = strlen(cm_named_oids[i].name);
			q = talloc_asprintf("%s%s",
					    cm_named_oids[i].oidish,
					    p + len);
			talloc_free(p);
			p = q;
		}
	}
	if (strspn(p, "0123456789.") != strlen(p)) {
		talloc_free(p);
		p = NULL;
	}
	return p;
}
