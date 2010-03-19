/*
 * Copyright (C) 2010 Red Hat, Inc.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "prefs.h"
#include "store-int.h"
#include "util.h"

static char *
cm_prefs_read(void)
{
	const char *dir, *base = "/" PACKAGE_NAME ".conf";
	char *path, *ret;
	ret = NULL;
	if (getenv(CM_STORE_CONFIG_DIRECTORY_ENV) != NULL) {
		dir = getenv(CM_STORE_CONFIG_DIRECTORY_ENV);
	} else {
		dir = CM_STORE_CONFIG_DIRECTORY;
	}
	path = malloc(strlen(dir) + strlen(base) + 1);
	if (path != NULL) {
		sprintf(path, "%s%s", dir, base);
		ret = read_config_file(path);
		free(path);
	}
	return ret;
}

static void cm_prefs_free(void);

static char *
cm_prefs_config(const char *key)
{
	static char *cm_configuration = NULL;
	if (key == NULL) {
		return cm_configuration;
	}
	if (cm_configuration == NULL) {
		cm_configuration = cm_prefs_read();
		if (cm_configuration != NULL) {
			atexit(cm_prefs_free);
		}
	}
	if (cm_configuration != NULL) {
		return get_config_entry(cm_configuration, "defaults", key);
	}
	return NULL;
}

static void
cm_prefs_free(void)
{
	char *prefs;
	prefs = cm_prefs_config(NULL);
	if (prefs != NULL) {
		free(prefs);
	}
}

static int
cm_prefs_compare_ttl_values(const void *a, const void *b)
{
	return *(time_t *)a - *(time_t *) b;
}

enum cm_prefs_cipher
cm_prefs_preferred_cipher(void)
{
	char *cipher;
	cipher = cm_prefs_config("symmetric_cipher");
	if (cipher != NULL) {
		if (strcasecmp(cipher, "aes") == 0) {
			free(cipher);
			return cm_prefs_aes128;
		}
		if (strcasecmp(cipher, "aes128") == 0) {
			free(cipher);
			return cm_prefs_aes128;
		}
		if (strcasecmp(cipher, "aes256") == 0) {
			free(cipher);
			return cm_prefs_aes256;
		}
		free(cipher);
	}
	return cm_prefs_aes128;
}

enum cm_prefs_digest
cm_prefs_preferred_digest(void)
{
	char *digest;
	digest = cm_prefs_config("digest");
	if (digest != NULL) {
		if (strcasecmp(digest, "sha1") == 0) {
			free(digest);
			return cm_prefs_sha1;
		}
		if (strcasecmp(digest, "sha256") == 0) {
			free(digest);
			return cm_prefs_sha256;
		}
		if (strcasecmp(digest, "sha384") == 0) {
			free(digest);
			return cm_prefs_sha384;
		}
		if (strcasecmp(digest, "sha512") == 0) {
			free(digest);
			return cm_prefs_sha512;
		}
		free(digest);
	}
	return cm_prefs_sha256;
}

int
cm_prefs_ttls(time_t **ttls, unsigned int *n_ttls)
{
	time_t default_ttls[] = {CM_DEFAULT_TTL_LIST};
	char *confttls;
	confttls = cm_prefs_config("ttls");
	if (confttls == NULL) {
		*ttls = default_ttls;
		*n_ttls = sizeof(default_ttls) / sizeof(default_ttls[0]);
	}
	return 0;
}

enum cm_notification_method
cm_prefs_notification_method(void)
{
	char *method;
	enum cm_notification_method ret;
	ret = cm_notification_syslog;
	method = cm_prefs_config("notification_method");
	if (method != NULL) {
		if (strcasecmp(method, "syslog") == 0) {
			ret = cm_notification_syslog;
		}
		if (strcasecmp(method, "email") == 0) {
			ret = cm_notification_email;
		}
		free(method);
	}
	return ret;
}

const char *
cm_prefs_notification_destination(void)
{
	static const char *destination;
	if (destination == NULL) {
		destination = cm_prefs_config("notification_destination");
		if (destination == NULL) {
			destination = "NOTICE";
		}
	}
	return destination;
}
