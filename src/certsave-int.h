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

#ifndef cmcertsaveint_h
#define cmcertsaveint_h

enum cm_certsave_status {
	CM_STATUS_SAVED = 0,
	CM_STATUS_SUBJECT_CONFLICT = 1,
	CM_STATUS_NICKNAME_CONFLICT = 2,
	CM_STATUS_INTERNAL = 3,
};

struct cm_certsave_state_pvt {
	/* Check if something changed, for example we finished saving the cert.
	 */
	int (*ready)(struct cm_store_entry *entry,
		     struct cm_certsave_state *state);
	/* Get a selectable-for-read descriptor that we can poll for status
	 * changes.  */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_certsave_state *state);
	/* Check if we saved the certificate. */
	int (*saved)(struct cm_store_entry *entry,
		     struct cm_certsave_state *state);
	/* Check if we failed because the subject was already being used. */
	int (*conflict_subject)(struct cm_store_entry *entry,
				struct cm_certsave_state *state);
	/* Check if we failed because the nickname was already being used. */
	int (*conflict_nickname)(struct cm_store_entry *entry,
				 struct cm_certsave_state *state);
	/* Clean up after saving the certificate. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_certsave_state *state);
};

#endif
