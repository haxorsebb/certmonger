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
			if (entry->cm_ca_name != NULL) {
				cm_log(1, "No matching CA \"%s\" for \"%s\".\n",
				       entry->cm_ca_name, entry->cm_id);
			} else {
				cm_log(1, "No matching CA for \"%s\".\n",
				       entry->cm_id);
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
		if (ca->cm_ca_external_helper == NULL) {
			cm_log(1, "No helper defined for CA \"%s\".\n",
			       entry->cm_id);
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

/* Convert a delta string to a time_t. */
int
cm_submit_delta_from_string(const char *deltas, time_t now, time_t *delta)
{
	struct tm now_tm, *pnow;
	time_t start;
	int multiple, i, val, done, digits;
	unsigned char c;
	val = 0;
	digits = 0;
	done = 0;
	if (strlen(deltas) == 0) {
		return -1;
	}
	start = now;
	for (i = 0; !done; i++) {
		c = (unsigned char) deltas[i];
		switch (c) {
		case '\0':
			done++;
			/* fall through */
		case 's':
			multiple = 1;
			now += val * multiple;
			val = 0;
			break;
		case 'm':
			multiple = 60;
			now += val * multiple;
			val = 0;
			break;
		case 'h':
			multiple = 60 * 60;
			now += val * multiple;
			val = 0;
			break;
		case 'd':
			multiple = 60 * 60 * 24;
			now += val * multiple;
			val = 0;
			break;
		case 'w':
			multiple = 60 * 60 * 24 * 7;
			now += val * multiple;
			val = 0;
			break;
		case 'M':
			pnow = localtime_r(&now, &now_tm);
			if (pnow == NULL) {
				multiple = 60 * 60 * 24 * 30;
				now += val * multiple;
			} else {
				now_tm.tm_mon += val;
				now_tm.tm_year += (now_tm.tm_mon / 12);
				now_tm.tm_mon %= 12;
				now = mktime(&now_tm);
			}
			val = 0;
			break;
		case 'y':
			pnow = localtime_r(&now, &now_tm);
			if (pnow == NULL) {
				multiple = 60 * 60 * 24 * 365;
				now += val * multiple;
			} else {
				now_tm.tm_year += val;
				now = mktime(&now_tm);
			}
			val = 0;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			val = (val * 10) + (c - '0');
			digits++;
			break;
		default:
			/* just skip this character */
			break;
		}
	}
	if (digits == 0) {
		return -1;
	}
	*delta = now + val - start;
	return 0;
}
