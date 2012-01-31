/*
 * Copyright (C) 2011,2012 Red Hat, Inc.
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
#include <sys/stat.h>
#include <errno.h>
#include <paths.h>
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
cm_env_homedir(const char *subdir, const char *subfile)
{
	struct passwd *pwd;
	const char *home;
	char *ret;
	int len;
	if ((subdir == NULL) && (subfile == NULL)) {
		return NULL;
	}
	home = getenv("HOME");
	if (home == NULL) {
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			home = pwd->pw_name;
		}
	}
	if (home != NULL) {
		len = strlen(home);
		if (subdir != NULL) {
			len += (strlen(subdir) + 1);
		}
		if (subfile != NULL) {
			len += (strlen(subfile) + 1);
		}
		ret = malloc(len + 1);
		if (ret != NULL) {
			strcpy(ret, home);
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

static void
cm_env_ensure_dir(char *path)
{
	char *p, *q, *tmp;
	struct stat st;

	if (path != NULL) {
		tmp = strdup(path);
		if (tmp != NULL) {
			p = tmp + strlen(tmp);
			for (q = tmp + 1; q < p; q++) {
				if (*q == '/') {
					*q = '\0';
					if ((stat(tmp, &st) == -1) &&
					    (errno == ENOENT)) {
						mkdir(tmp, S_IRWXU);
					}
					*q = '/';
				}
			}
			free(tmp);
		}
	}
}

char *
cm_env_config_dir(void)
{
	static char *ret = NULL;

	if (ret == NULL) {
		ret = getenv(CM_STORE_CONFIG_DIRECTORY_ENV);
		if (ret == NULL) {
			ret = cm_env_homedir(CM_STORE_SESSION_CONFIG_DIRECTORY,
					     NULL);
		}
		if (ret != NULL) {
			cm_env_ensure_dir(ret);
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
			ret = cm_env_homedir(CM_STORE_SESSION_REQUESTS_DIRECTORY,
					     NULL);
		}
		if (ret != NULL) {
			cm_env_ensure_dir(ret);
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
			ret = cm_env_homedir(CM_STORE_SESSION_CAS_DIRECTORY,
					     NULL);
		}
		if (ret != NULL) {
			cm_env_ensure_dir(ret);
		}
	}
	return ret;
}

char *
cm_env_tmp_dir(void)
{
	char *ret;
	ret = getenv(CM_TMPDIR_ENV);
	if ((ret == NULL) || (strlen(ret) == 0)) {
		ret = getenv("TMPDIR");
		if ((ret == NULL) || (strlen(ret) == 0)) {
			ret = _PATH_VARTMP;
		}
		cm_env_ensure_dir(ret);
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

int
cm_env_default_bus_timeout(void)
{
	return CM_DEFAULT_IDLE_TIMEOUT;
}
