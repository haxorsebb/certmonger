/*
 * Copyright (C) 2012,2015 Red Hat, Inc.
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
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include <pk11pub.h>
#include <secmod.h>

#include "log.h"
#include "util-n.h"

#define NODE "/proc/sys/crypto/fips_enabled"

static PRBool force_fips = PR_FALSE;

void
util_n_set_fips(enum force_fips_mode force)
{
	if (force == do_not_force_fips) {
		force_fips = PR_FALSE;
	} else {
		force_fips = PR_TRUE;
	}
}

const char *
util_n_fips_hook(void)
{
	SECMODModule *module;
	PRBool fips_detected;
	const char *name;
	FILE *fp;
	char buf[LINE_MAX];

	if (!force_fips) {
		fips_detected = PR_FALSE;
		fp = fopen(NODE, "r");
		if (fp != NULL) {
			if (fgets(buf, sizeof(buf), fp) != NULL) {
				buf[strcspn(buf, "\r\n")] = '\0';
				cm_log(4, "Read value \"%s\" from \"%s\".\n",
				       buf, NODE);
				if (strlen(buf) > 0) {
					if (atoi(buf) == 1) {
						fips_detected = PR_TRUE;
					}
				}
			}
			fclose(fp);
		} else {
			cm_log(4, "Error opening \"%s\": %s, assuming 0.\n",
			       NODE, strerror(errno));
		}
		if (!fips_detected) {
			cm_log(4, "Not attempting to set NSS FIPS mode.\n");
			return NULL;
		}
	}

	if (!PK11_IsFIPS()) {
		cm_log(4, "Attempting to set NSS FIPS mode.\n");
		module = SECMOD_GetInternalModule();
		if (module == NULL) {
			return "error obtaining handle to internal "
			       "cryptographic token's module";
		}
		name = module->commonName;
		if (SECMOD_DeleteInternalModule(name) != SECSuccess) {
			return "error unloading (reloading) NSS's internal "
			       "cryptographic module";
		}
		if (!PK11_IsFIPS()) {
			return "unloading (reloading) the internal "
			       "cryptographic module wasn't sufficient to "
			       "enable FIPS mode";
		}
		cm_log(4, "Successfully set NSS FIPS mode.\n");
	}

	return NULL;
}

char *
util_build_next_nickname(const char *prefix, const char *marker)
{
	size_t len;
	char *ret;

	len = strlen(prefix) + strlen(marker) + sizeof("%s (candidate %s)");
	ret = malloc(len + 1);
	if (ret != NULL) {
		snprintf(ret, len, "%s (candidate %s)", prefix, marker);
	}
	return ret;
}

char *
util_build_old_nickname(const char *prefix, const char *serial)
{
	size_t len;
	char *ret;

	len = strlen(prefix) + strlen(serial) + sizeof("%s (serial %s)");
	ret = malloc(len + 1);
	if (ret != NULL) {
		snprintf(ret, len, "%s (serial %s)", prefix, serial);
	}
	return ret;
}
