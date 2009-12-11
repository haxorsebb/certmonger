/*
 * Copyright (C) 2009 Red Hat, Inc.
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
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>
#include <tevent.h>

#include <dbus/dbus.h>

#include "cm.h"
#include "log.h"
#include "tdbus.h"

int
main(int argc, char **argv)
{
	struct tevent_context *ec;
	struct cm_context *ctx;
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	int i, c, dlevel = 0, pfd;
	pid_t pid;
	FILE *pfp;
	const char *pidfile = NULL;
	dbus_bool_t dofork = TRUE;

	while ((c = getopt(argc, argv, "sSp:d:n")) != -1) {
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'd':
			dlevel = atoi(optarg);
			/* fall through */
		case 'n':
			dofork = FALSE;
			break;
		default:
			printf("Usage: certmonger [-s|-S] [-n] [-d LEVEL] "
			       "[-p FILE]\n"
			       "\t-s         use session bus\n"
			       "\t-S         use system bus\n"
			       "\t-n         don't become a daemon\n"
			       "\t-d LEVEL   set debugging level (implies -n)\n"
			       "\t-p FILE    write service PID to file\n");
			exit(1);
			break;
		}
	}

	cm_log_set_level(dlevel);
	cm_log_set_method(dofork ? cm_log_syslog : cm_log_stderr);
	cm_log(3, "Starting up.\n");

	ec = tevent_context_init(NULL);
	if (ec == NULL) {
		fprintf(stderr, "Error initializing tevent.\n");
		exit(1);
	}
	if (dlevel > 0) {
		tevent_set_debug_stderr(ec);
	}

	if (pidfile != NULL) {
		pfd = open(pidfile, O_RDWR | O_CREAT | O_TRUNC,
			   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (pfd == -1) {
			fprintf(stderr, "Error opening pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			exit(1);
		}
		if (flock(pfd, LOCK_EX | LOCK_NB) != 0) {
			fprintf(stderr, "Error locking pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			exit(1);
		}
		pfp = fdopen(pfd, "w");
		if (pfp == NULL) {
			fprintf(stderr, "Error opening pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			exit(1);
		}
	} else {
		pfp = NULL;
	}

	umask(S_IRWXG | S_IRWXO);

	ctx = NULL;
	i = cm_init(ec, &ctx);
	if (i != 0) {
		fprintf(stderr, "Error: %s\n", strerror(i));
		talloc_free(ec);
		exit(1);
	}

	if (cm_tdbus_setup(ec, bus, ctx) != 0) {
		fprintf(stderr, "Error connecting to D-Bus.\n");
		talloc_free(ec);
		if (pidfile != NULL) {
			remove(pidfile);
		}
		exit(1);
	}

	if (dofork) {
		pid = fork();
		switch (pid) {
		case -1:
			/* failure */
			fprintf(stderr, "fork() error: %s\n", strerror(errno));
			if (pfp != NULL) {
				remove(pidfile);
			}
			exit(1);
			break;
		case 0:
			/* child; keep going */
			if (daemon(0, 0) != 0) {
				fprintf(stderr, "daemon() error: %s\n",
					strerror(errno));
				exit(1);
			}
			if (pfp != NULL) {
				fprintf(pfp, "%ld\n", (long) getpid());
				fflush(pfp);
			}
			break;
		default:
			/* parent; exit cleanly */
			exit(0);
			break;
		}
	} else {
		if (pfp != NULL) {
			fprintf(pfp, "%ld\n", (long) getpid());
			fflush(pfp);
		}
	}
	if (pfp != NULL) {
		fclose(pfp);
	}
	cm_start_all(ctx);
	do {
		i = tevent_loop_once(ec);
		if (i != 0) {
			cm_log(3, "Event loop exits with status %d.\n", i);
			break;
		}
	} while (cm_keep_going(ctx) == 0);
	cm_log(3, "Shutting down.\n");
	cm_stop_all(ctx);
	talloc_free(ctx);
	talloc_free(ec);
	if ((pidfile != NULL) && (pfp != NULL)) {
		remove(pidfile);
	}
	return 0;
}
