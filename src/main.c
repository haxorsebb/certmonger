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
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>
#include <tevent.h>

#include "cm.h"
#include "log.h"
#include "tdbus.h"

int
main(int argc, char **argv)
{
	struct tevent_context *ec;
	struct cm_context *ctx;
	int i;

	cm_log_set_level(3);
	cm_log_set_method(cm_log_stderr);
	cm_log(3, "Starting up.\n");

	ec = tevent_context_init(NULL);
	if (ec == NULL) {
		fprintf(stderr, "Error initializing tevent.\n");
		return 1;
	}

	ctx = NULL;
	i = cm_init(ec, &ctx);
	if (i != 0) {
		fprintf(stderr, "Error: %s\n", strerror(i));
		talloc_free(ec);
		return 1;
	}
	if (cm_tdbus_setup(ec, CM_DBUS_DEFAULT_BUS, ctx) != 0) {
		fprintf(stderr, "Error connecting to D-Bus.\n");
		talloc_free(ec);
		return 1;
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
	cm_done(ctx);
	talloc_free(ec);
	return 0;
}
