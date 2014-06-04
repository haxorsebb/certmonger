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

#ifndef cmsubmit_h
#define cmsubmit_h

struct cm_submit_state;
struct cm_store_entry;
struct cm_store_ca;

/* Start CSR submission using parameters stored in the entry.  If we have a
 * cookie in the entry, poll for its status. */
struct cm_submit_state *cm_submit_start(struct cm_store_ca *ca,
					struct cm_store_entry *entry);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_submit_get_fd(struct cm_submit_state *state);

/* Check if either the CSR was submitted to the CA yet, or we figured out that
 * we weren't going to be able to send it. */
int cm_submit_ready(struct cm_submit_state *state);

/* Save CA-specific identifier for our submitted request. */
int cm_submit_save_ca_cookie(struct cm_submit_state *state);

/* Clear CA-specific identifier for our submitted request. */
int cm_submit_clear_ca_cookie(struct cm_submit_state *state);

/* If we need to poll again, any non-negative value is the polling interval. */
int cm_submit_specified_delay(struct cm_submit_state *state);

/* Check if the certificate was issued. */
int cm_submit_issued(struct cm_submit_state *state);

/* Check if the certificate request was rejected. */
int cm_submit_rejected(struct cm_submit_state *state);

/* Check if the CA was unreachable. */
int cm_submit_unreachable(struct cm_submit_state *state);

/* Check if we're missing some configuration. */
int cm_submit_unconfigured(struct cm_submit_state *state);

/* Done talking to the CA. */
void cm_submit_done(struct cm_submit_state *state);

#endif
