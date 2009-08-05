#include "config.h"

#include <sys/types.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cm.h"

#define MAX_TIMEOUT 3600
static int cm_quit;

int
main(int argc, char **argv)
{
	struct cm_context *ctx;
	struct pollfd *pfds;
	int i, *fds, nfds, timeout;

	ctx = NULL;
	i = cm_init(&ctx);
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
				pfds = malloc(sizeof(pfds[0]) * nfds);
				if (pfds != NULL) {
					memset(pfds, 0, sizeof(pfds[0]) * nfds);
					for (i = 0; i < nfds; i++) {
						pfds[i].fd = fds[i];
						pfds[i].events = POLLIN;
					}
					poll(pfds, nfds, timeout);
				}
			} else {
				poll(NULL, 0, timeout);
			}
		}
	}
	cm_done(ctx);
	return 0;
}
