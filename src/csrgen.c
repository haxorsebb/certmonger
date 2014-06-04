/*
 * Copyright (C) 2009,2011,2012,2014 Red Hat, Inc.
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
#include "csrgen.h"
#include "csrgen-int.h"
#include "log.h"
#include "store-int.h"

struct cm_csrgen_state *
cm_csrgen_start(struct cm_store_entry *entry)
{
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		cm_log(1, "Can't generate new CSR for %s('%s') without the "
		       "key, and we don't know where that is or should be.\n",
		       entry->cm_busname, entry->cm_nickname);
		break;
#ifdef HAVE_OPENSSL
	case cm_key_storage_file:
		return cm_csrgen_o_start(entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_key_storage_nssdb:
		return cm_csrgen_n_start(entry);
		break;
#endif
	}
	return NULL;
}

int
cm_csrgen_ready(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->ready(state);
}

int
cm_csrgen_get_fd(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->get_fd(state);
}

int
cm_csrgen_save_csr(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->save_csr(state);
}

int
cm_csrgen_need_pin(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->need_pin(state);
}

int
cm_csrgen_need_token(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->need_token(state);
}

void
cm_csrgen_done(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	pvt->done(state);
}
