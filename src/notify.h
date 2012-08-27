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

#ifndef cmnotify_h
#define cmnotify_h

struct cm_store_entry;
struct cm_notify_state;

enum cm_notify_event {
	cm_notify_event_unknown = 0,
	cm_notify_event_validity_ending,
	cm_notify_event_rejected,
	cm_notify_event_issued_not_saved,
	cm_notify_event_issued_and_saved
};

/* Start to notify the administrator or user that expiration is imminent. */
struct cm_notify_state *cm_notify_start(struct cm_store_entry *entry,
					enum cm_notify_event event);
/* Get a selectable-for-read descriptor we can poll for status changes when
 * we're finished sending the notification. */
int cm_notify_get_fd(struct cm_store_entry *entry,
		     struct cm_notify_state *state);
/* Check if we're ready to call notification done. */
int cm_notify_ready(struct cm_store_entry *entry,
		    struct cm_notify_state *state);
/* Clean up after notification. */
void cm_notify_done(struct cm_store_entry *entry,
		    struct cm_notify_state *state);

#endif
