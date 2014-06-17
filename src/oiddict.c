/*
 * Copyright (C) 2009,2014 Red Hat, Inc.
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
	{"iso.org.dod.internet.security", "1.3.6.1.5"},
	{"iso.org.dod.internet.security.kerberosV5", "iso.org.dod.internet.security.2"},
	{"iso.org.dod.internet.security.mechanisms", "iso.org.dod.internet.security.5"},
	{"id-pkix", "iso.org.dod.internet.security.mechanisms.7"},
	{"id-mod", "id-pkix.0"},
	{"id-pe", "id-pkix.1"},
	{"id-pe-authorityInfoAccess", "id-pe.1"},
	{"id-pe-nsa", "id-pe.23"},
	{"id-qt", "id-pkix.2"},
	{"id-qt-cps", "id-qt.1"},
	{"id-qt-unotice", "id-qt.2"},
	{"id-kp", "id-pkix.3"},
	{"id-kp-serverAuth", "id-kp.1"},
	{"id-kp-clientAuth", "id-kp.2"},
	{"id-kp-codeSigning", "id-kp.3"},
	{"id-kp-emailProtection", "id-kp.4"},
	{"id-kp-timeStamping", "id-kp.8"},
	{"id-kp-OCSPSigning", "id-kp.9"},
	{"id-on", "id-pkix.8"},
	{"id-on-dnsSRV", "id-on.7"},
	{"id-ad", "id-pkix.48"},
	{"id-ad-ca-ocsp", "id-ad.1"},
	{"id-pkix-ocsp-nocheck", "id-ad-ca-ocsp.5"},
	{"id-ad-ca-Issuers", "id-ad.2"},
	{"id-pkinit", "iso.org.dod.internet.security.kerberosV5.3"},
	{"id-pkinit-KPClientAuth", "id-pkinit.4"},
	{"id-pkinit-KPKdc", "id-pkinit.5"},
	{"id-ms-kp-sc-logon", "1.3.6.1.4.1.311.20.2.2"},
	{"id-ce", "2.5.29"},
	{"id-ce-authorityKeyIdentifier", "id-ce.35"},
	{"id-ce-subjectKeyIdentifier", "id-ce.14"},
	{"id-ce-keyUsage", "id-ce.15"},
	{"id-ce-subjectAltName", "id-ce.17"},
	{"id-ce-issuerAltName", "id-ce.18"},
	{"id-ce-basicConstraints", "id-ce.19"},
	{"id-ce-cRLNumber", "id-ce.20"},
	{"id-ce-cRLDistributionPoints", "id-ce.31"},
	{"id-ce-extKeyUsage", "id-ce.37"},
	{"id-ce-freshestCRL", "id-ce.46"},
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
			q = talloc_asprintf(ctx, "%s%s",
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
