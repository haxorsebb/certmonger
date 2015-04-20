/*
 * Copyright (C) 2010,2015 Red Hat, Inc.
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
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>

#include "cm.h"
#include "log.h"
#include "store-int.h"
#include "util-o.h"

void
util_o_init(void)
{
#if defined(HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS) && HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS
	OpenSSL_add_all_algorithms();
#elif defined(HAVE_DECL_OPENSSL_ADD_SSL_ALGORITHMS) && HAVE_DECL_OPENSSL_ADD_SSL_ALGORITHMS
	OpenSSL_add_ssl_algorithms();
#else
	SSL_library_init();
#endif
}

char *
util_build_next_filename(const char *prefix, const char *marker)
{
	size_t len;
	char *ret;

	len = strlen(prefix) + strlen(marker) + sizeof("%s.%s.key");
	ret = malloc(len + 1);
	if (ret != NULL) {
		snprintf(ret, len, "%s.%s.key", prefix, marker);
	}
	return ret;
}

char *
util_build_old_filename(const char *prefix, const char *serial)
{
	size_t len;
	char *ret;

	len = strlen(prefix) + strlen(serial) + sizeof("%s.%s.key");
	ret = malloc(len + 1);
	if (ret != NULL) {
		snprintf(ret, len, "%s.%s.key", prefix, serial);
	}
	return ret;
}

void
util_set_fd_owner_perms(int fd, const char *filename,
			const char *owner, mode_t perms)
{
	char *user, *group;
	struct passwd *pwd;
	struct group *grp;
	uid_t uid;
	gid_t gid;

	if (filename == NULL) {
		return;
	}
	if (owner != NULL) {
		user = strdup(owner);
		group = strchr(user, ':');
		if (group != NULL) {
			*group++ = '\0';
			if (strlen(group) == 0) {
				group = NULL;
			}
		}
		pwd = getpwnam(user);
		if (pwd == NULL) {
			cm_log(1, "Error looking up user \"%s\", "
			       "not setting ownership of \"%s\".\n",
			       user, filename);
		} else {
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			if (group != NULL) {
				grp = getgrnam(group);
				if (grp != NULL) {
					gid = grp->gr_gid;
				} else {
					cm_log(1, "Error looking up group "
					       "\"%s\", setting group of \"%s\""
					       " to primary group of \"%s\".\n",
					       group, filename, user);
				}
			}
			if (fchown(fd, uid, gid) == -1) {
				cm_log(1, "Error setting ownership on "
				       "file \"%s\": %s.  Continuing\n",
				       filename, strerror(errno));
			}
		}
		free(user);
	}
	if (perms != 0) {
		if (fchmod(fd, perms) == -1) {
			cm_log(1, "Error setting permissions on "
			       "file \"%s\": %s.  Continuing\n",
			       filename, strerror(errno));
		}
	}
}

void
util_set_fd_entry_key_owner(int keyfd, const char *filename,
			    struct cm_store_entry *entry)
{
	util_set_fd_owner_perms(keyfd, filename, entry->cm_key_owner,
				entry->cm_key_perms);
}

void
util_set_fd_entry_cert_owner(int certfd, const char *filename,
			     struct cm_store_entry *entry)
{
	util_set_fd_owner_perms(certfd, filename, entry->cm_cert_owner,
				entry->cm_cert_perms);
}
