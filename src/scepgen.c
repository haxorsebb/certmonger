/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/pkcs7.h>

#include "scepgen.h"
#include "scepgen-int.h"
#include "log.h"
#include "store-int.h"

struct cm_scepgen_state *
cm_scepgen_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		cm_log(1, "Can't generate new SCEP data for %s('%s') without "
		       "the key, and we don't know where that is or should "
		       "be.\n", entry->cm_busname, entry->cm_nickname);
		break;
#ifdef HAVE_OPENSSL
	case cm_key_storage_file:
		return cm_scepgen_o_start(ca, entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_key_storage_nssdb:
		return cm_scepgen_n_start(ca, entry);
		break;
#endif
	}
	return NULL;
}

int
cm_scepgen_ready(struct cm_scepgen_state *state)
{
	struct cm_scepgen_state_pvt *pvt = (struct cm_scepgen_state_pvt *) state;

	return pvt->ready(state);
}

int
cm_scepgen_get_fd(struct cm_scepgen_state *state)
{
	struct cm_scepgen_state_pvt *pvt = (struct cm_scepgen_state_pvt *) state;

	return pvt->get_fd(state);
}

int
cm_scepgen_save_scep(struct cm_scepgen_state *state)
{
	struct cm_scepgen_state_pvt *pvt = (struct cm_scepgen_state_pvt *) state;

	return pvt->save_scep(state);
}

int
cm_scepgen_need_pin(struct cm_scepgen_state *state)
{
	struct cm_scepgen_state_pvt *pvt = (struct cm_scepgen_state_pvt *) state;

	return pvt->need_pin(state);
}

int
cm_scepgen_need_token(struct cm_scepgen_state *state)
{
	struct cm_scepgen_state_pvt *pvt = (struct cm_scepgen_state_pvt *) state;

	return pvt->need_token(state);
}

int
cm_scepgen_need_encryption_certs(struct cm_scepgen_state *state)
{
	struct cm_scepgen_state_pvt *pvt = (struct cm_scepgen_state_pvt *) state;

	return pvt->need_encryption_certs(state);
}

int
cm_scepgen_need_different_key_type(struct cm_scepgen_state *state)
{
	struct cm_scepgen_state_pvt *pvt = (struct cm_scepgen_state_pvt *) state;

	return pvt->need_different_key_type(state);
}

void
cm_scepgen_done(struct cm_scepgen_state *state)
{
	struct cm_scepgen_state_pvt *pvt = (struct cm_scepgen_state_pvt *) state;

	pvt->done(state);
}
