#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "notify.h"
#include "store.h"
#include "store-int.h"

struct cm_notify_state {
	pid_t pid;
	int fd, status;
};

/* Fire off the proper notification. */
static void
cm_notify_main(int fd, struct cm_store_entry *entry)
{
}

/* Start notifying the user that the certificate will expire soon. */
struct cm_notify_state *
cm_notify_start(struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_notify_state *state;
	state = malloc(sizeof(*state));
	if (state != NULL) {
		state->fd = -1;
		if (pipe(fds) != -1) {
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(fds[0]);
				close(fds[1]);
				free(state);
				state = NULL;
				break;
			case 0:
				close(fds[0]);
				cm_notify_main(fds[1], entry);
				_exit(0);
				break;
			default:
				state->fd = fds[0];
				close(fds[1]);
				break;
			}
		}
	}
	return state;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_notify_get_fd(struct cm_store_entry *entry, struct cm_notify_state *state)
{
	return state->fd;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_notify_ready(struct cm_store_entry *entry, struct cm_notify_state *state)
{
	if (state->pid != -1) {
		close(state->fd);
		state->fd = -1;
		waitpid(state->pid, &state->status, 0);
		state->pid = -1;
	}
	return 0;
}

/* Clean up after notification. */
void
cm_notify_done(struct cm_store_entry *entry, struct cm_notify_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}
