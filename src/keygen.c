/*
 * Copyright (C) 2009,2010,2011,2013 Red Hat, Inc.
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
#include "keygen.h"
#include "keygen-int.h"
#include "log.h"
#include "store-int.h"

struct cm_keygen_state *
cm_keygen_start(struct cm_store_entry *entry)
{
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		cm_log(1, "Can't generate key for %s('%s') without knowing "
		       "where to store it.\n",
		       entry->cm_busname, entry->cm_nickname);
		break;
#ifdef HAVE_OPENSSL
	case cm_key_storage_file:
		return cm_keygen_o_start(entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_key_storage_nssdb:
		return cm_keygen_n_start(entry);
		break;
#endif
	}
	return NULL;
}

/* Check if the keypair is ready. */
int
cm_keygen_ready(struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	return pvt->ready(state);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_keygen_get_fd(struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	return pvt->get_fd(state);
}

/* Tell us if the keypair was saved to the location specified in the entry. */
int
cm_keygen_saved_keypair(struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	return pvt->saved_keypair(state);
}

/* Tell us if we need filesystem permissions to write the key. */
int
cm_keygen_need_perms(struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	return pvt->need_perms(state);
}

/* Tell us if we need a PIN (or a new PIN) to access the key store. */
int
cm_keygen_need_pin(struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	return pvt->need_pin(state);
}

/* Tell us if we need a token to be inserted to access the key store. */
int
cm_keygen_need_token(struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;

	return pvt->need_token(state);
}

/* Clean up after key generation. */
void
cm_keygen_done(struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;

	pvt->done(state);
}
