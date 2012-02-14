/*
 * Copyright (C) 2012 Red Hat, Inc.
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

#ifndef cmpostsave_h
#define cmpostsave_h

struct cm_postsave_state;
struct cm_store_entry;

/* Start doing whatever we need to after saving the certificate to the
 * configured location. */
struct cm_postsave_state *cm_postsave_start(struct cm_store_entry *entry);

/* Check if something changed, for example we finished doing whatever it is
 * that we're doing. */
int cm_postsave_ready(struct cm_store_entry *entry,
		      struct cm_postsave_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_postsave_get_fd(struct cm_store_entry *entry,
		       struct cm_postsave_state *state);

/* Clean up after ourselves. */
void cm_postsave_done(struct cm_store_entry *entry,
		      struct cm_postsave_state *state);

#endif
