/*
 * Copyright (C) 2009,2013 Red Hat, Inc.
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
#include "certsave.h"
#include "certsave-int.h"
#include "store-int.h"

/* Start writing the certificate from the entry to the configured location. */
struct cm_certsave_state *
cm_certsave_start(struct cm_store_entry *entry)
{
	switch (entry->cm_cert_storage_type) {
#ifdef HAVE_OPENSSL
	case cm_cert_storage_file:
		return cm_certsave_o_start(entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_cert_storage_nssdb:
		return cm_certsave_n_start(entry);
		break;
#endif
	}
	return NULL;
}

/* Check if something changed, for example we finished saving the cert. */
int
cm_certsave_ready(struct cm_certsave_state *state)
{
	struct cm_certsave_state_pvt *pvt;

	pvt = (struct cm_certsave_state_pvt *) state;
	return pvt->ready(state);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_certsave_get_fd(struct cm_certsave_state *state)
{
	struct cm_certsave_state_pvt *pvt;

	pvt = (struct cm_certsave_state_pvt *) state;
	return pvt->get_fd(state);
}

/* Check if we saved the certificate. */
int
cm_certsave_saved(struct cm_certsave_state *state)
{
	struct cm_certsave_state_pvt *pvt;

	pvt = (struct cm_certsave_state_pvt *) state;
	return pvt->saved(state);
}

/* Check if we failed due to a subject conflict. */
int
cm_certsave_conflict_subject(struct cm_certsave_state *state)
{
	struct cm_certsave_state_pvt *pvt;

	pvt = (struct cm_certsave_state_pvt *) state;
	return pvt->conflict_subject(state);
}

/* Check if we failed due to a nickname conflict. */
int
cm_certsave_conflict_nickname(struct cm_certsave_state *state)
{
	struct cm_certsave_state_pvt *pvt;

	pvt = (struct cm_certsave_state_pvt *) state;
	return pvt->conflict_nickname(state);
}

/* Check if we failed due to a permissions error. */
int
cm_certsave_permissions_error(struct cm_certsave_state *state)
{
	struct cm_certsave_state_pvt *pvt;

	pvt = (struct cm_certsave_state_pvt *) state;
	return pvt->permissions_error(state);
}

/* Clean up after saving the certificate. */
void
cm_certsave_done(struct cm_certsave_state *state)
{
	struct cm_certsave_state_pvt *pvt;

	pvt = (struct cm_certsave_state_pvt *) state;
	pvt->done(state);
}
