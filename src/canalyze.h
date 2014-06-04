/*
 * Copyright (C) 2014 Red Hat, Inc.
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

#ifndef cmcanalyze_h
#define cmcanalyze_h

struct cm_store_ca;
struct cm_ca_analyze_state;

/* Start computing information about the CA. */
struct cm_ca_analyze_state *cm_ca_analyze_start_certs(struct cm_store_ca *ca);

/* Check if the data has been retrieved. */
int cm_ca_analyze_ready(struct cm_ca_analyze_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_ca_analyze_get_fd(struct cm_ca_analyze_state *state);

/* Clean up after retrieving data. */
void cm_ca_analyze_done(struct cm_ca_analyze_state *state);

/* Get the refresh delay. */
long cm_ca_analyze_get_delay(struct cm_ca_analyze_state *state);

#endif
