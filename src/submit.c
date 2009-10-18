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

#include "config.h"
#include "log.h"
#include "submit.h"
#include "submit-int.h"
#include "store-int.h"

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	switch (ca->cm_ca_type) {
	case cm_ca_internal_self:
		switch (entry->cm_key_storage_type) {
		case cm_key_storage_none:
			cm_log(1, "Can't self-sign \"%s\" without access to "
			       "the private key.\n", entry->cm_id);
			break;
#ifdef HAVE_OPENSSL
		case cm_key_storage_file:
			return cm_submit_so_start(ca, entry);
			break;
#endif
#ifdef HAVE_NSS
		case cm_key_storage_nssdb:
			return cm_submit_sn_start(ca, entry);
			break;
#endif
		}
		break;
	case cm_ca_external:
		return cm_submit_e_start(ca, entry);
	}
	return NULL;
}

/* Pick up after a CSR has been submitted, in case we haven't yet gotten a
 * decision about it. */
struct cm_submit_state *
cm_submit_resume(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	switch (ca->cm_ca_type) {
	case cm_ca_internal_self:
		switch (entry->cm_key_storage_type) {
		case cm_key_storage_none:
			cm_log(1, "Can't self-sign \"%s\" without access to "
			       "the private key.\n", entry->cm_id);
			break;
#ifdef HAVE_OPENSSL
		case cm_key_storage_file:
			return cm_submit_so_resume(ca, entry);
			break;
#endif
#ifdef HAVE_NSS
		case cm_key_storage_nssdb:
			return cm_submit_sn_resume(ca, entry);
			break;
#endif
		}
		break;
	case cm_ca_external:
		return cm_submit_e_resume(ca, entry);
		break;
	}
	return NULL;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_submit_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->get_fd(entry, state);
}

/* Check if the CSR was submitted to the CA yet. */
int
cm_submit_sent(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->sent(entry, state);
}

/* Save CA-specific identifier for our submitted request. */
int
cm_submit_save_ca_cookie(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->save_ca_cookie(entry, state);
}

/* Check if an attempt to get status has succeeded. */
int
cm_submit_status_ready(struct cm_store_entry *entry,
		       struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->status_ready(entry, state);
}

/* Check if the certificate was issued. */
int
cm_submit_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->issued(entry, state);
}

/* Check if we need to make another request to actually retrieve the cert. */
int
cm_submit_needs_retrieval(struct cm_store_entry *entry,
			  struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->needs_retrieval(entry, state);
}

/* Done talking to the CA. */
void
cm_submit_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	pvt->done(entry, state);
}
