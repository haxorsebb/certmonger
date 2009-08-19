#include "config.h"

#include <sys/types.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>

#include "cm.h"
#include "log.h"

#define MAX_TIMEOUT 3600000
static int cm_quit = 0;

static void
sig_handler(int signum, siginfo_t *info, void *context)
{
	cm_quit++;
}

int
main(int argc, char **argv)
{
	struct cm_context *ctx;
	struct pollfd *pfds;
	struct sigaction action;
	int i, *fds, nfds, timeout;

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = &sig_handler;
	action.sa_flags = SA_SIGINFO;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);

	cm_log_set_level(3);
	cm_log_set_method(cm_log_stderr);
	cm_log(3, "Starting up.\n");

	ctx = NULL;
	i = cm_init(NULL, &ctx);
	if (i != 0) {
		fprintf(stderr, "Error: %s\n", strerror(i));
		return 1;
	}

	fds = NULL;
	nfds = 0;
	while (!cm_quit) {
		timeout = -1;
		i = cm_next(ctx, &fds, &nfds, &timeout);
		if (i != 0) {
			cm_quit++;
		} else {
			if ((timeout < 0) || (timeout > MAX_TIMEOUT)) {
				timeout = MAX_TIMEOUT;
			}
			if (nfds > 0) {
				pfds = talloc_array_ptrtype(ctx, pfds, nfds);
				if (pfds != NULL) {
					for (i = 0; i < nfds; i++) {
						memset(&pfds[i], 0,
						       sizeof(pfds[i]));
						pfds[i].fd = fds[i];
						pfds[i].events = POLLIN;
					}
					poll(pfds, nfds, timeout);
					talloc_free(pfds);
				}
			} else {
				poll(NULL, 0, timeout);
			}
		}
	}
	cm_log(3, "Shutting down.\n");
	cm_done(ctx, &fds);
	return 0;
}
