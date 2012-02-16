/*
 * Copyright (C) 2009,2010 Red Hat, Inc.
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
#include <stdio.h>
#include <string.h>

#include <talloc.h>

#include "keyiread.h"
#include "keyiread-int.h"
#include "log.h"
#include "store-int.h"

/* Start refreshing the key info from the entry from the configured location. */
struct cm_keyiread_state *
cm_keyiread_start(struct cm_store_entry *entry)
{
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		break;
#ifdef HAVE_OPENSSL
	case cm_key_storage_file:
		if (entry->cm_key_storage_location != NULL) {
			return cm_keyiread_o_start(entry);
		} else {
			return NULL;
		}
		break;
#endif
#ifdef HAVE_NSS
	case cm_key_storage_nssdb:
		if ((entry->cm_key_storage_location != NULL) &&
		    (entry->cm_key_nickname != NULL)) {
			return cm_keyiread_n_start(entry);
		} else {
			return NULL;
		}
		break;
#endif
	}
	return NULL;
}

/* Check if something changed, for example we finished reading the key info. */
int
cm_keyiread_ready(struct cm_store_entry *entry, struct cm_keyiread_state *state)
{
	struct cm_keyiread_state_pvt *pvt;
	pvt = (struct cm_keyiread_state_pvt *) state;
	return pvt->ready(entry, state);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_keyiread_get_fd(struct cm_store_entry *entry,
		   struct cm_keyiread_state *state)
{
	struct cm_keyiread_state_pvt *pvt;
	pvt = (struct cm_keyiread_state_pvt *) state;
	return pvt->get_fd(entry, state);
}

/* Check if we finished reading the key information. */
int
cm_keyiread_finished_reading(struct cm_store_entry *entry,
			     struct cm_keyiread_state *state)
{
	struct cm_keyiread_state_pvt *pvt;
	pvt = (struct cm_keyiread_state_pvt *) state;
	return pvt->finished_reading(entry, state);
}

/* Check if we need a PIN (or a new PIN) in order to access the key info. */
int
cm_keyiread_need_pin(struct cm_store_entry *entry,
		     struct cm_keyiread_state *state)
{
	struct cm_keyiread_state_pvt *pvt;
	pvt = (struct cm_keyiread_state_pvt *) state;
	return pvt->need_pin(entry, state);
}

/* Check if we need a token to be present in order to access the key info. */
int
cm_keyiread_need_token(struct cm_store_entry *entry,
		       struct cm_keyiread_state *state)
{
	struct cm_keyiread_state_pvt *pvt;
	pvt = (struct cm_keyiread_state_pvt *) state;
	return pvt->need_token(entry, state);
}

/* Clean up after reading the key info. */
void
cm_keyiread_done(struct cm_store_entry *entry, struct cm_keyiread_state *state)
{
	struct cm_keyiread_state_pvt *pvt;
	pvt = (struct cm_keyiread_state_pvt *) state;
	pvt->done(entry, state);
}

/* Parse what we know about this key from a buffer. */
void
cm_keyiread_read_data_from_buffer(struct cm_store_entry *entry, const char *p)
{
	const char *q;
	int size = 0;
	enum cm_key_algorithm alg;

	/* Break out the algorithm. */
	q = p + strcspn(p, "/\r\n");
	if (((q - p) == strlen("RSA")) &&
	    (strncasecmp(p, "RSA", 3) == 0)) {
		alg = cm_key_rsa;
		p = q + strspn(q, "/\r\n");
		q = p + strcspn(p, "/\r\n");
		if (p != q) {
			size = atoi(p);
			if (size > 0) {
				entry->cm_key_type.cm_key_algorithm = alg;
				entry->cm_key_type.cm_key_size = size;
			}
			p = q + strspn(q, "/\r\n");
			q = p + strcspn(p, "/\r\n");
			if (p != q) {
				talloc_free(entry->cm_key_pubkey);
				entry->cm_key_pubkey = talloc_strndup(entry,
								      p, q - p);
				p = q + strspn(q, "/\r\n");
				q = p + strcspn(p, "/\r\n");
				if (p != q) {
					talloc_free(entry->cm_key_token);
					entry->cm_key_token = talloc_strndup(entry,
									     p, q - p);
				}
			}
		}
	}
}
