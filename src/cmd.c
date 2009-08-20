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
