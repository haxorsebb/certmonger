/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include "../../src/config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

#include "../../src/log.h"

const char *
uidname(uid_t uid)
{
	static struct passwd *pwd;
	static char name[LINE_MAX];

	if ((pwd != NULL) && (pwd->pw_uid == uid)) {
		return pwd->pw_name;
	}
	pwd = getpwuid(uid);
	if ((pwd != NULL) && (pwd->pw_uid == uid)) {
		return pwd->pw_name;
	}
	snprintf(name, sizeof(name), "%lu", (unsigned long) uid);
	return name;
}

const char *
gidname(gid_t gid)
{
	static struct group *grp;
	static char name[LINE_MAX];

	if ((grp != NULL) && (grp->gr_gid == gid)) {
		return grp->gr_name;
	}
	grp = getgrgid(gid);
	if ((grp != NULL) && (grp->gr_gid == gid)) {
		return grp->gr_name;
	}
	snprintf(name, sizeof(name), "%lu", (unsigned long) gid);
	return name;
}

int
main(int argc, char **argv)
{
	struct stat st;
	int i;

	for (i = 1; i < argc; i++) {
		if (stat(argv[i], &st) == -1) {
			fprintf(stderr, "stat(%s): %s\n", argv[i],
				strerror(errno));
		} else {
			printf("%s:%s|%04o|%s\n",
			       uidname(st.st_uid), gidname(st.st_gid),
			       st.st_mode & 07777, argv[i]);
		}
	}
	return 0;
}
