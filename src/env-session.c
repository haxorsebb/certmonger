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

#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>
#include <tevent.h>

#include <dbus/dbus.h>

#include "env.h"
#include "tdbus.h"

static char *
cm_env_homedir(const char *subdir)
{
	struct passwd *pwd;
	const char *home;
	char *ret;
	home = getenv("HOME");
	if (home == NULL) {
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			home = pwd->pw_name;
		}
	}
	if (home != NULL) {
		ret = malloc(strlen(home) + 1 + strlen(subdir) + 1);
		if (ret != NULL) {
			sprintf(ret, "%s/%s", home, subdir);
		}
	} else {
		ret = NULL;
	}
	return ret;
}

char *
cm_env_config_dir(void)
{
	static char *ret = NULL;
	if (ret == NULL) {
		ret = getenv(CM_STORE_CONFIG_DIRECTORY_ENV);
		if (ret == NULL) {
			ret = cm_env_homedir(CM_STORE_SESSION_CONFIG_DIRECTORY);
		}
	}
	return ret;
}

char *
cm_env_request_dir(void)
{
	static char *ret = NULL;
	if (ret == NULL) {
		ret = getenv(CM_STORE_REQUESTS_DIRECTORY_ENV);
		if (ret == NULL) {
			ret = cm_env_homedir(CM_STORE_SESSION_REQUESTS_DIRECTORY);
		}
	}
	return ret;
}

char *
cm_env_ca_dir(void)
{
	static char *ret = NULL;
	if (ret == NULL) {
		ret = getenv(CM_STORE_CAS_DIRECTORY_ENV);
		if (ret == NULL) {
			ret = cm_env_homedir(CM_STORE_SESSION_CAS_DIRECTORY);
		}
	}
	return ret;
}

char *
cm_env_whoami(void)
{
	return "certmonger-session";
}

enum cm_tdbus_type
cm_env_default_bus(void)
{
	return cm_tdbus_session;
}

dbus_bool_t
cm_env_default_fork(void)
{
	return FALSE;
}
