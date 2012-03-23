/*
 * Copyright (C) 2009,2011,2012 Red Hat, Inc.
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
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <talloc.h>

#include "log.h"
#include "postsave.h"
#include "prefs.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "tm.h"

struct cm_postsave_state {
	struct cm_subproc_state *subproc;
	uid_t uid;
};

/* Fire off a subprocess. */
static int
cm_postsave_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	char **argv;
	const char *error;
	struct passwd *pwd;
	struct cm_postsave_state *state = userdata;
	int i;

	argv = cm_subproc_parse_args(entry, entry->cm_post_certsave_command,
				     &error);
	if (error != NULL) {
		cm_log(-2, "Error parsing \"%s\": %s; not running it.\n",
		       entry->cm_post_certsave_command, error);
		return -1;
	}
	pwd = getpwuid(state->uid);
	if (pwd == NULL) {
		cm_log(-2, "Error on getpwuid(%lu): %s, not running \"%s\".\n",
		       (unsigned long) state->uid,
		       strerror(errno),
		       entry->cm_post_certsave_command);
		return -1;
	}
	if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) {
		if (getuid() != 0) {
			cm_log(0, "Error on initgroups(%s,%lu): %s.\n",
			       pwd->pw_name,
			       (unsigned long) state->uid,
			       strerror(errno));
		} else {
			cm_log(-2, "Error on initgroups(%s,%lu): %s, "
			       "not running \"%s\".\n",
			       pwd->pw_name,
			       (unsigned long) state->uid,
			       strerror(errno),
			       entry->cm_post_certsave_command);
			return -1;
		}
	}
	if (setregid(pwd->pw_gid, pwd->pw_gid) == -1) {
		cm_log(-2, "Error on setregid(%lu,%lu,%lu): %s, "
		       "not running \"%s\".\n",
		       (unsigned long) pwd->pw_gid,
		       (unsigned long) pwd->pw_gid,
		       (unsigned long) pwd->pw_gid,
		       strerror(errno),
		       entry->cm_post_certsave_command);
		return -1;
	}
	if (setreuid(pwd->pw_uid, pwd->pw_uid) == -1) {
		cm_log(0, "Error on setreuid(%lu,%lu,%lu): %s, "
		       "not running \"%s\".\n",
		       (unsigned long) pwd->pw_uid,
		       (unsigned long) pwd->pw_uid,
		       (unsigned long) pwd->pw_uid,
		       strerror(errno),
		       entry->cm_post_certsave_command);
		return -1;
	}
	i = open("/dev/null", O_RDONLY);
	if (i != -1) {
		if (i != STDIN_FILENO) {
			dup2(i, STDIN_FILENO);
			close(i);
		}
	} else {
		close(STDIN_FILENO);
	}
	if (execvp(argv[0], argv) == -1) {
		cm_log(0, "Error execvp()ing command \"%s\" (\"%s\"): %s.\n",
		       argv[0], entry->cm_post_certsave_command,
		       strerror(errno));
		return -1;
	}
	return -1;
}

/* Start the postsave command. */
struct cm_postsave_state *
cm_postsave_start(struct cm_store_entry *entry)
{
	struct cm_postsave_state *state;
	long l;
	char *p;

	if (entry->cm_post_certsave_uid == NULL) {
		cm_log(1, "No UID set for post-save command.\n");
		return NULL;
	}
	p = NULL;
	l = strtol(entry->cm_post_certsave_uid, &p, 10);
	if ((p == NULL) || (*p != '\0')) {
		cm_log(1, "Error parsing \"%s\" as a numeric UID.\n",
		       entry->cm_post_certsave_uid);
		return NULL;
	}

	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		state->uid = l;
		state->subproc = cm_subproc_start(cm_postsave_main,
						  NULL, entry, state);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_postsave_get_fd(struct cm_store_entry *entry, struct cm_postsave_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Check if our child process has exited. */
int
cm_postsave_ready(struct cm_store_entry *entry, struct cm_postsave_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Clean up after... well, we don't really know. */
void
cm_postsave_done(struct cm_store_entry *entry, struct cm_postsave_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}
