/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014 Red Hat, Inc.
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
#include <time.h>
#include "prefs.h"
#include "util.h"

#include "dogtag-ipa.h"

#define IPACONFIG "/etc/ipa/default.conf"
#define IPASECTION "dogtag"

void
cm_dogtag_ipa_hostver(const char **host, const char **dogtag_version)
{
	static char *ipaconfig;

	if (ipaconfig == NULL) {
		ipaconfig = read_config_file(IPACONFIG);
	}
	if (ipaconfig != NULL) {
		*host = get_config_entry(ipaconfig,
					 "global",
					 "host");
		if (*dogtag_version == NULL) {
			*dogtag_version = get_config_entry(ipaconfig,
							   "global",
							   "dogtag_version");
		}
	} else {
		*host = NULL;
		*dogtag_version = NULL;
	}
}
