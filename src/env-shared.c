/*
 * Copyright (C) 2011 Red Hat, Inc.
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

#include <dbus/dbus.h>

#include "env.h"

char *
cm_env_config(const char *subdir, const char *subfile)
{
	const char *config;
	char *ret;
	int len;
	if ((subdir == NULL) && (subfile == NULL)) {
		return NULL;
	}
	config = cm_env_config_dir();
	if (config != NULL) {
		len = strlen(config);
		if (subdir != NULL) {
			len += (strlen(subdir) + 1);
		}
		if (subfile != NULL) {
			len += (strlen(subfile) + 1);
		}
		ret = malloc(len + 1);
		if (ret != NULL) {
			strcpy(ret, config);
			if (subdir != NULL) {
				strcat(ret, "/");
				strcat(ret, subdir);
			}
			if (subfile != NULL) {
				strcat(ret, "/");
				strcat(ret, subfile);
			}
		}
	} else {
		ret = NULL;
	}
	return ret;
}
