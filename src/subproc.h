/*
 * Copyright (C) 2009,2014 Red Hat, Inc.
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

#ifndef cmsubproc_h
#define cmsubproc_h

struct cm_store_ca;
struct cm_store_entry;
struct cm_subproc_state;

/* Start calling the callback in a subprocess. */
struct cm_subproc_state *cm_subproc_start(int (*cb)(int fd,
						    struct cm_store_ca *ca,
						    struct cm_store_entry *e,
						    void *data),
					  void *parent,
					  struct cm_store_ca *ca,
					  struct cm_store_entry *entry,
					  void *data);
/* Get a selectable-for-read descriptor we can wait on for status changes.  If
 * we return -1, the caller must poll.  */
int cm_subproc_get_fd(struct cm_subproc_state *state);
/* Return 0 if the process has finished its run. */
int cm_subproc_ready(struct cm_subproc_state *state);
/* Return the subprocess's output. */
const char *cm_subproc_get_msg(struct cm_subproc_state *state,
			       int *length);
/* Return the subprocess's exit status. */
int cm_subproc_get_exitstatus(struct cm_subproc_state *state);
/* Clean up. */
void cm_subproc_done(struct cm_subproc_state *state);

/* Parse args. */
char **cm_subproc_parse_args(void *parent, const char *cmdline,
			     const char **error);

/* Reset stdio to /dev/null and mark all but the passed-in descriptor as
 * close-on-exec. */
void cm_subproc_mark_most_cloexec(int fd);

#endif
