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

#ifndef iterate_h
#define iterate_h

struct cm_store_entry;
struct cm_store_ca;
struct cm_context;
enum cm_ca_phase;

/* Start tracking a working state for this entry. */
int cm_iterate_entry_init(struct cm_store_entry *entry,
			  void **cm_iterate_state);

/* Start tracking a working state for a CA's maintenance tasks. */
int cm_iterate_ca_init(struct cm_store_ca *ca, enum cm_ca_phase phase,
		       void **cm_iterate_state);

/* Figure out what to do next about this specific entry or CA. */
enum cm_time {
	cm_time_now,	/* Poke again without delay. */
	cm_time_soon,	/* Soon - small delays ok. */
	cm_time_soonish,/* Small delay. */
	cm_time_delay,	/* At specified delay. */
	cm_time_no_time	/* Wait for data on specified descriptor. */
};
int cm_iterate_entry(struct cm_store_entry *entry,
		     struct cm_store_ca *ca,
		     struct cm_context *context,
		     struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
		     int (*get_n_cas)(struct cm_context *),
		     struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
		     int (*get_n_entries)(struct cm_context *),
		     void (*emit_entry_saved_cert)(struct cm_context *,
						   struct cm_store_entry *),
		     void (*emit_entry_changes)(struct cm_context *,
						struct cm_store_entry *,
						struct cm_store_entry *),
		     void *cm_iterate_state,
		     enum cm_time *when,
		     int *delay,
		     int *readfd);
int cm_iterate_ca(struct cm_store_ca *ca,
		  struct cm_context *context,
		  struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
		  int (*get_n_cas)(struct cm_context *),
		  struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
		  int (*get_n_entries)(struct cm_context *),
		  void (*emit_ca_changes)(struct cm_context *,
					  struct cm_store_ca *,
					  struct cm_store_ca *),
		  void *cm_iterate_state,
		  enum cm_time *when,
		  int *delay,
		  int *readfd);

/* We're shutting down. */
int cm_iterate_entry_done(struct cm_store_entry *entry, void *cm_iterate_state);
int cm_iterate_ca_done(struct cm_store_ca *ca, void *cm_iterate_state);

/* Wait for the descriptor to become readable. */
void cm_waitfor_readable_fd(int fd, int delay);

#endif
