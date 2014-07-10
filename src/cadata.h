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

#ifndef cmcadata_h
#define cmcadata_h

struct cm_cadata_state;
struct cm_store_ca;

/* Start fetching information from the CA. */
struct cm_cadata_state *cm_cadata_start_identify(struct cm_store_ca *ca);
struct cm_cadata_state *cm_cadata_start_certs(struct cm_store_ca *ca);
struct cm_cadata_state *cm_cadata_start_profiles(struct cm_store_ca *ca);
struct cm_cadata_state *cm_cadata_start_default_profile(struct cm_store_ca *ca);
struct cm_cadata_state *cm_cadata_start_enroll_reqs(struct cm_store_ca *ca);
struct cm_cadata_state *cm_cadata_start_renew_reqs(struct cm_store_ca *ca);

/* Check if the data has been retrieved. */
int cm_cadata_ready(struct cm_cadata_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_cadata_get_fd(struct cm_cadata_state *state);

/* Check if the CA data was modified. */
int cm_cadata_modified(struct cm_cadata_state *state);

/* Check if we need to retry. */
int cm_cadata_needs_retry(struct cm_cadata_state *state);

/* Check when we need to retry. */
int cm_cadata_specified_delay(struct cm_cadata_state *state);

/* Check if the CA was unreachable. */
int cm_cadata_unreachable(struct cm_cadata_state *state);

/* Check if we're missing some configuration. */
int cm_cadata_unconfigured(struct cm_cadata_state *state);

/* Check if the helper didn't support that. */
int cm_cadata_unsupported(struct cm_cadata_state *state);

/* Clean up after retrieving data. */
void cm_cadata_done(struct cm_cadata_state *state);

#endif
