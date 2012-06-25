/*
 * Copyright (C) 2009,2011 Red Hat, Inc.
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
#include <ctype.h>
#include <string.h>

#include <talloc.h>

#include "log.h"
#include "submit.h"
#include "submit-int.h"
#include "store-int.h"

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	if (ca == NULL) {
		if (entry != NULL) {
			if (entry->cm_ca_nickname != NULL) {
				cm_log(1, "No matching CA \"%s\" for "
				       "%s('%s').\n",
				       entry->cm_ca_nickname,
				       entry->cm_busname, entry->cm_nickname);
			} else {
				cm_log(1, "No matching CA for %s('%s').\n",
				       entry->cm_busname, entry->cm_nickname);
			}
		} else {
			cm_log(1, "No matching CA.\n");
		}
		return NULL;
	}
	talloc_free(entry->cm_ca_error);
	entry->cm_ca_error = NULL;
	switch (ca->cm_ca_type) {
	case cm_ca_internal_self:
		switch (entry->cm_key_storage_type) {
		case cm_key_storage_none:
			cm_log(1, "Can't self-sign %s('%s') without access to "
			       "the private key.\n",
			       entry->cm_busname, entry->cm_nickname);
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
		if (ca->cm_ca_external_helper == NULL) {
			cm_log(1, "No helper defined for CA %s('%s').\n",
			       entry->cm_busname, entry->cm_nickname);
			return NULL;
		}
		return cm_submit_e_start(ca, entry);
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

/* Check if the CSR was submitted to the CA yet, or we figured out that it
 * wasn't possible to accomplish it. */
int
cm_submit_ready(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->ready(entry, state);
}

/* Save CA-specific identifier for our submitted request. */
int
cm_submit_save_ca_cookie(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->save_ca_cookie(entry, state);
}

/* Clear CA-specific identifier for our submitted request. */
int
cm_submit_clear_ca_cookie(struct cm_store_entry *entry,
			  struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	talloc_free(entry->cm_ca_cookie);
	entry->cm_ca_cookie = NULL;
	return 0;
}

/* Check if the certificate was issued. */
int
cm_submit_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->issued(entry, state);
}

/* Check if the certificate was rejected. */
int
cm_submit_rejected(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->rejected(entry, state);
}

/* Check if the CA was unreachable. */
int
cm_submit_unconfigured(struct cm_store_entry *entry,
		       struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->unconfigured(entry, state);
}

/* Check if the CA was unreachable. */
int
cm_submit_unreachable(struct cm_store_entry *entry,
		      struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->unreachable(entry, state);
}

/* Done talking to the CA. */
void
cm_submit_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	pvt->done(entry, state);
}

/* How long should we wait before talking to the CA again? */
int
cm_submit_specified_delay(struct cm_store_entry *entry,
			  struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->delay;
}

/* Concatenate some strings. */
char *
cm_submit_maybe_joinv(void *parent, const char *sep, char **s)
{
	int i, l;
	char *ret = NULL;
	for (i = 0, l = 0; (s != NULL) && (s[i] != NULL); i++) {
		l += i ? strlen(sep) + strlen(s[i]) : strlen(s[i]);
	}
	if (l > 0) {
		ret = talloc_zero_size(parent, l + 1);
		if (ret != NULL) {
			for (i = 0; s[i] != NULL; i++) {
				if (i > 0) {
					strcat(ret, sep);
				}
				strcat(ret, s[i]);
			}
		}
	}
	return ret;
}
