/*
 * Copyright (C) 2009,2011 Red Hat, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include "log.h"
#include "subproc.h"

#define GROW_SIZE 0x2000

struct cm_subproc_state {
	pid_t pid;
	char *msg;
	int fd, count, bufsize, status;
};

struct cm_subproc_state *
cm_subproc_start(int (*cb)(int fd,
			   struct cm_store_ca *ca,
			   struct cm_store_entry *entry,
			   void *data),
		 struct cm_store_ca *ca,
		 struct cm_store_entry *entry,
		 void *data)
{
	struct cm_subproc_state *state;
	int fds[2];
	long flags;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->fd = -1;
		state->msg = NULL;
		state->status = -1;
		if (pipe(fds) != -1) {
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(fds[0]);
				close(fds[1]);
				talloc_free(state);
				state = NULL;
				break;
			case 0:
				state->fd = fds[1];
				close(fds[0]);
				exit((*cb)(fds[1], ca, entry, data));
				break;
			default:
				state->fd = fds[0];
				flags = fcntl(state->fd, F_GETFL);
				fcntl(state->fd, F_SETFL, flags | O_NONBLOCK);
				close(fds[1]);
				break;
			}
		}
	}
	return state;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_subproc_get_fd(struct cm_store_entry *entry, struct cm_subproc_state *state)
{
	return state->fd;
}

/* Get the output to-date. */
const char *
cm_subproc_get_msg(struct cm_store_entry *entry, struct cm_subproc_state *state,
		   int *length)
{
	if (length != NULL) {
		*length = state->count;
	}
	return state->msg ? state->msg : "";
}

/* Get the exit status. */
int
cm_subproc_get_exitstatus(struct cm_store_entry *entry,
			  struct cm_subproc_state *state)
{
	return state->status;
}

/* Clean up when we're done. */
void
cm_subproc_done(struct cm_store_entry *entry, struct cm_subproc_state *state)
{
	pid_t pid;
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
		do {
			pid = waitpid(state->pid, &state->status, 0);
		} while ((pid == -1) && (errno == EINTR));
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Check if we're done (return 0), or need to be called again (-1). */
int
cm_subproc_ready(struct cm_store_entry *entry,
		 struct cm_subproc_state *state)
{
	ssize_t i, remainder;
	char *tmp;
	int status;
	if (state->pid == -1) {
		return state->status;
	}
	do {
		remainder = state->bufsize - state->count;
		if (remainder <= 0) {
			tmp = talloc_realloc_size(state, state->msg,
						  state->bufsize + GROW_SIZE + 1);
			if (tmp != NULL) {
				state->msg = tmp;
				state->bufsize += GROW_SIZE;
				state->msg[state->bufsize] = '\0';
				remainder = state->bufsize - state->count;
			} else {
				errno = EINTR;
				i = -1;
				break;
			}
		}
		i = read(state->fd, state->msg + state->count, remainder);
		switch (i) {
		case -1:
		case 0:
			break;
		default:
			state->count += i;
			break;
		}
	} while (i > 0);
	if ((i == -1) && ((errno == EAGAIN) || (errno == EINTR))) {
		status = -1;
	} else {
		state->msg[state->count] = '\0';
		close(state->fd);
		state->fd = -1;
		waitpid(state->pid, &state->status, 0);
		state->pid = -1;
		status = 0;
	}
	return status;
}

/* Adapted from oddjob's parse_args(). */
char **
cm_subproc_parse_args(void *parent, const char *cmdline, const char **error)
{
	const char *p;
	char *q, *bigbuf;
	char **argv;
	int sqlevel, dqlevel, escape;
	size_t buffersize, words;

	buffersize = strlen(cmdline) * 3;
	bigbuf = talloc_zero_size(parent, buffersize);

	sqlevel = dqlevel = escape = 0;
	p = cmdline;
	q = bigbuf;
	while (*p != '\0') {
		switch (*p) {
		case '\\':
			if ((dqlevel != 0) || (sqlevel != 0) || escape) {
				*q++ = *p++;
				escape = 0;
			} else {
				escape = 1;
				p++;
			}
			break;
		case '\'':
			switch (sqlevel) {
			case 0:
				if (escape || (dqlevel > 0)) {
					*q++ = *p++;
					escape = 0;
				} else {
					sqlevel = 1;
					p++;
				}
				break;
			case 1:
				sqlevel = 0;
				p++;
				break;
			}
			break;
		case '"':
			switch (dqlevel) {
			case 0:
				if (escape || (sqlevel > 0)) {
					*q++ = *p++;
					escape = 0;
				} else {
					dqlevel = 1;
					p++;
				}
				break;
			case 1:
				dqlevel = 0;
				p++;
				break;
			}
			break;
		case '\r':
		case '\n':
		case '\t':
		case ' ':
			if (escape || (dqlevel > 0) || (sqlevel > 0)) {
				*q++ = *p;
			} else {
				*q++ = '\0';
			}
			p++;
			break;
		default:
			*q++ = *p++;
			break;
		}
	}
	if (error) {
		*error = NULL;
	}
	if (dqlevel > 0) {
		if (error) {
			*error = "Unmatched \"";
		}
		talloc_free(bigbuf);
		return NULL;
	}
	if (sqlevel > 0) {
		if (error) {
			*error = "Unmatched '";
		}
		talloc_free(bigbuf);
		return NULL;
	}
	if (escape) {
		if (error) {
			*error = "Attempt to escape end-of-command";
		}
		talloc_free(bigbuf);
		return NULL;
	}
	p = NULL;
	words = 0;
	for (q = bigbuf; q < bigbuf + buffersize; q++) {
		if (*q != '\0') {
			if (p == NULL) {
				p = q;
			}
		} else {
			if (p != NULL) {
				words++;
				p = NULL;
			}
		}
	}
	argv = talloc_zero_size(parent, sizeof(char*) * (words + 1));
	p = NULL;
	words = 0;
	for (q = bigbuf; q < bigbuf + buffersize; q++) {
		if (*q != '\0') {
			if (p == NULL) {
				p = q;
			}
		} else {
			if (p != NULL) {
				argv[words++] = talloc_strdup(argv, p);
				p = NULL;
			}
		}
	}
	talloc_free(bigbuf);
	return argv;
}

/* Check if we're done (return 0), or need to be called again (-1). */
void
cm_subproc_mark_most_cloexec(struct cm_store_entry *entry, int fd)
{
	int i;
	long l;
	if (fd != STDIN_FILENO) {
		i = open("/dev/null", O_RDONLY);
		if (i != -1) {
			if (i != STDIN_FILENO) {
				dup2(i, STDIN_FILENO);
				close(i);
			}
		} else {
			close(STDIN_FILENO);
		}
	}
	if (fd != STDOUT_FILENO) {
		i = open("/dev/null", O_WRONLY);
		if (i != -1) {
			if (i != STDOUT_FILENO) {
				dup2(i, STDOUT_FILENO);
				close(i);
			}
		} else {
			close(STDOUT_FILENO);
		}
	}
	if (fd != STDERR_FILENO) {
		i = open("/dev/null", O_WRONLY);
		if (i != -1) {
			if (i != STDERR_FILENO) {
				dup2(i, STDERR_FILENO);
				close(i);
			}
		} else {
			close(STDERR_FILENO);
		}
	}
	for (i = getdtablesize() - 1; i >= 3; i--) {
		if (i == fd) {
			continue;
		}
		l = fcntl(i, F_GETFD);
		if (l != -1) {
			fcntl(i, F_SETFD, l | FD_CLOEXEC);
		}
	}
}
