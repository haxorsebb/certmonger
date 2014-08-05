/*
 * Copyright (C) 2009,2011,2012,2013,2014 Red Hat, Inc.
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
#include "env.h"
#include "log.h"
#include "tdbus.h"
#include "tdbusm.h"
#include "util-n.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

int
main(int argc, char **argv)
{
	struct tevent_context *ec;
	struct cm_context *ctx;
	enum cm_tdbus_type bus;
	int i, c, dlevel = 0, pfd = -1, lfd = -1;
	long l;
	pid_t pid;
	FILE *pfp;
	const char *pidfile = NULL, *tmpdir, *gate_command = NULL;
	char *env_tmpdir, *hint;
	dbus_bool_t dofork;
	enum force_fips_mode forcefips;
	int bustime;
	DBusError error;

	bus = cm_env_default_bus();
	dofork = cm_env_default_fork();
	bustime = cm_env_default_bus_timeout();
	forcefips = do_not_force_fips;

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif

	if (cm_env_whoami() == NULL) {
		printf("internal error\n");
		exit(1);
	}
	if ((cm_env_config_dir() == NULL) ||
	    (cm_env_request_dir() == NULL) ||
	    (cm_env_ca_dir() == NULL) ||
	    (cm_env_tmp_dir() == NULL)) {
		printf("%s: unable to determine storage locations\n",
		       cm_env_whoami());
		exit(1);
	};

	while ((c = getopt(argc, argv, "sSp:fb:Bd:nFc:")) != -1) {
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'c':
			bustime = 0;
			gate_command = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'f':
			dofork = TRUE;
			break;
		case 'b':
			gate_command = NULL;
			bustime = atoi(optarg);
			break;
		case 'B':
			bustime = 0;
			break;
		case 'd':
			dlevel = atoi(optarg);
			/* fall through */
		case 'n':
			dofork = FALSE;
			break;
		case 'F':
			forcefips = do_force_fips;
			break;
		default:
			printf(_("Usage: %s [-s|-S] [-n|-f] [-d LEVEL] "
				 "[-p FILE] [-F]\n"),
			       cm_env_whoami());
			printf("%s%s%s%s%s%s%s%s%s%s",
			       _("\t-s         use session bus\n"),
			       _("\t-S         use system bus\n"),
			       _("\t-n         don't become a daemon\n"),
			       _("\t-f         do become a daemon\n"),
			       _("\t-b TIMEOUT bus-activated, idle timeout\n"),
			       _("\t-B         don't use an idle timeout\n"),
			       _("\t-d LEVEL   set debugging level (implies -n)\n"),
			       _("\t-c COMMAND run COMMAND and exit when it does\n"),
			       _("\t-p FILE    write service PID to file\n"),
			       _("\t-F         force NSS into FIPS mode\n"));
			exit(1);
			break;
		}
	}

	cm_log_set_level(dlevel);
	cm_log_set_method(dofork ? cm_log_syslog : cm_log_stderr);
	util_n_set_fips(forcefips);
	cm_log(3, "Starting up.\n");

	tmpdir = cm_env_tmp_dir();
	if (tmpdir != NULL) {
		env_tmpdir = malloc(8 + strlen(tmpdir));
		if (env_tmpdir == NULL) {
			fprintf(stderr, "Out of memory.\n");
			exit(1);
		}
		snprintf(env_tmpdir, 8 + strlen(tmpdir), "TMPDIR=%s", tmpdir);
		if (putenv(env_tmpdir) != 0) {
			printf("internal error: %s\n", strerror(errno));
			exit(1);
		}
	}

	ec = tevent_context_init(NULL);
	if (ec == NULL) {
		fprintf(stderr, "Error initializing tevent.\n");
		exit(1);
	}
	if (dlevel > 0) {
		tevent_set_debug_stderr(ec);
	}

	umask(S_IRWXG | S_IRWXO);

	switch (bus) {
	case cm_tdbus_system:
		if (chdir("/") != 0) {
			cm_log(0, "Error in chdir(\"/\"): %s.\n",
			       strerror(errno));
		}
		break;
	case cm_tdbus_session:
		cm_log(2, "Changing to config directory.\n");
		if (chdir(cm_env_config_dir()) != 0) {
			cm_log(2, "Error in chdir(\"%s\"): %s.\n",
			       cm_env_config_dir(), strerror(errno));
		}
		cm_log(2, "Obtaining session lock.\n");
		lfd = open(cm_env_lock_file(), O_RDWR | O_CREAT,
			   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (lfd == -1) {
			fprintf(stderr, "Error opening lockfile \"%s\": %s\n",
				cm_env_lock_file(), strerror(errno));
			exit(1);
		}
		if (lockf(lfd, F_LOCK, 0) != 0) {
			fprintf(stderr, "Error locking lockfile \"%s\": %s\n",
				cm_env_lock_file(), strerror(errno));
			close(lfd);
			exit(1);
		}
		l = fcntl(lfd, F_GETFD);
		if (l != -1) {
			l = fcntl(lfd, F_SETFD, l | FD_CLOEXEC);
			if (l == -1) {
				fprintf(stderr,
					"Error setting close-on-exec flag on "
					"\"%s\": %s\n",
					cm_env_lock_file(), strerror(errno));
				close(lfd);
				exit(1);
			}
		}
		break;
	}

	ctx = NULL;
	i = cm_init(ec, &ctx, bustime, gate_command);
	if (i != 0) {
		fprintf(stderr, "Error: %s\n", strerror(i));
		talloc_free(ec);
		exit(1);
	}

	if (cm_tdbus_setup(ec, bus, ctx, &error) != 0) {
		fprintf(stderr, "Error connecting to D-Bus.\n");
		hint = cm_tdbusm_hint(ec, error.name, error.message);
		if (hint != NULL) {
			fprintf(stderr, "%s", hint);
		}
		talloc_free(ec);
		exit(1);
	}

	if (pidfile != NULL) {
		pfd = open(pidfile, O_RDWR | O_CREAT,
			   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (pfd == -1) {
			fprintf(stderr, "Error opening pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			exit(1);
		}
		if (lockf(pfd, F_TLOCK, 0) != 0) {
			fprintf(stderr, "Error locking pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			close(pfd);
			exit(1);
		}
		if (ftruncate(pfd, 0) != 0) {
			fprintf(stderr, "Error truncating pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			close(pfd);
			exit(1);
		}
		l = fcntl(pfd, F_GETFD);
		if (l != -1) {
			fcntl(pfd, F_SETFD, l | FD_CLOEXEC);
		}
		pfp = fdopen(pfd, "w");
		if (pfp == NULL) {
			fprintf(stderr, "Error opening pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			close(pfd);
			exit(1);
		}
	} else {
		pfp = NULL;
	}

	if (dofork) {
		pid = fork();
		switch (pid) {
		case -1:
			/* failure */
			fprintf(stderr, "fork() error: %s\n", strerror(errno));
			if ((pidfile != NULL) && (pfp != NULL)) {
				fclose(pfp);
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
			/* lock the pid file now that our parent is exiting and
			 * thus losing its lock; it should be safe to block
			 * here, even if the parent gives up the lock before we
			 * get here, because we've already ensured that only we
			 * and our parent have the named connection to the bus,
			 * and wouldn't have gotten here otherwise */
			if ((pidfile != NULL) && (pfp != NULL)) {
				if (lockf(pfd, F_LOCK, 0) != 0) {
					cm_log(0,
					       "Error locking pidfile \"%s\": "
					       "%s\n",
					       pidfile, strerror(errno));
					exit(1);
				}
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
		if ((pidfile != NULL) && (pfp != NULL)) {
			fprintf(pfp, "%ld\n", (long) getpid());
			fflush(pfp);
		}
	}
	if (cm_start_all(ctx) == 0) {
		do {
			i = tevent_loop_once(ec);
			if (i != 0) {
				cm_log(3, "Event loop exits with status %d.\n",
				       i);
				break;
			}
		} while (cm_keep_going(ctx) == 0);
		cm_log(3, "Shutting down.\n");
		cm_stop_all(ctx);
	}
	talloc_free(ctx);
	talloc_free(ec);
	if ((pidfile != NULL) && (pfp != NULL)) {
		remove(pidfile);
		fclose(pfp);
	}
	return 0;
}
