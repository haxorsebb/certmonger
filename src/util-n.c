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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>

#include <pk11pub.h>
#include <secmod.h>

#include "log.h"
#include "store-int.h"
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

static void
util_set_db_owner_perms(const char *dbdir, const char *filename,
			const char *owner, mode_t perms)
{
	char *user, *group, *pathname = NULL;
	struct passwd *pwd;
	struct group *grp;
	uid_t uid;
	gid_t gid;
	struct stat st, before;
	int fd;

	if (filename == NULL) {
		return;
	}
	pathname = malloc(strlen(dbdir) + strlen(filename) + 2);
	if (pathname == NULL) {
		return;
	}
	sprintf(pathname, "%s/%s", dbdir, filename);
	fd = open(pathname, O_RDWR);
	if (fd == -1) {
		free(pathname);
		return;
	}
	if ((lstat(pathname, &before) == -1) || !S_ISREG(before.st_mode)) {
		close(fd);
		free(pathname);
		return;
	}
	if ((fstat(fd, &st) == -1) || !S_ISREG(st.st_mode)) {
		close(fd);
		free(pathname);
		return;
	}
	if ((st.st_dev != before.st_dev) ||
	    (st.st_ino != before.st_ino)) {
		close(fd);
		free(pathname);
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
			       user, pathname);
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
					       group, pathname, user);
				}
			}
			if (fchown(fd, uid, gid) == -1) {
				cm_log(1, "Error setting ownership on "
				       "file \"%s\": %s.  Continuing\n",
				       pathname, strerror(errno));
			}
		}
		free(user);
	}
	if (perms != 0) {
		if (fchmod(fd, perms) == -1) {
			cm_log(1, "Error setting permissions on "
			       "file \"%s\": %s.  Continuing\n",
			       pathname, strerror(errno));
		}
	}
	close(fd);
	free(pathname);
}

void
util_set_db_entry_key_owner(const char *dbdir, struct cm_store_entry *entry)
{
	const char *keydb = NULL;

	if (dbdir == NULL) {
		return;
	}
	if (strncmp(dbdir, "sql:", 4) == 0) {
		keydb = "key4.db";
		dbdir += 4;
	} else
	if (strncmp(dbdir, "dbm:", 4) == 0) {
		keydb = "key3.db";
		dbdir += 4;
	} else
	if (strncmp(dbdir, "rdb:", 4) == 0) {
		keydb = "key3.db";
		dbdir += 4;
	} else
	if (strncmp(dbdir, "extern:", 7) == 0) {
		keydb = "key4.db";
		dbdir += 7;
	} else {
		keydb = "key3.db";
	}
	util_set_db_owner_perms(dbdir, keydb, entry->cm_key_owner,
				entry->cm_key_perms);
}

void
util_set_db_entry_cert_owner(const char *dbdir, struct cm_store_entry *entry)
{
	const char *certdb = NULL, *secmoddb = NULL;

	if (dbdir == NULL) {
		return;
	}
	if (strncmp(dbdir, "sql:", 4) == 0) {
		certdb = "cert9.db";
		secmoddb = "pkcs11.txt";
		dbdir += 4;
	} else
	if (strncmp(dbdir, "dbm:", 4) == 0) {
		certdb = "cert8.db";
		secmoddb = "secmod.db";
		dbdir += 4;
	} else
	if (strncmp(dbdir, "rdb:", 4) == 0) {
		certdb = "cert8.db";
		secmoddb = "secmod.db";
		dbdir += 4;
	} else
	if (strncmp(dbdir, "extern:", 7) == 0) {
		certdb = "cert9.db";
		secmoddb = "pkcs11.txt";
		dbdir += 7;
	} else {
		certdb = "cert8.db";
		secmoddb = "secmod.db";
	}
	util_set_db_owner_perms(dbdir, certdb, entry->cm_cert_owner,
				entry->cm_cert_perms);
	util_set_db_owner_perms(dbdir, secmoddb, entry->cm_cert_owner,
				entry->cm_cert_perms);
}
