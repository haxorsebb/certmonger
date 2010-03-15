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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dbus/dbus.h>
#include <talloc.h>

#include "certread.h"
#include "certsave.h"
#include "cm.h"
#include "csrgen.h"
#include "iterate.h"
#include "keygen.h"
#include "keyiread.h"
#include "log.h"
#include "notify.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"

struct cm_iterate_state {
	struct cm_keygen_state *cm_keygen_state;
	struct cm_keyiread_state *cm_keyiread_state;
	struct cm_csrgen_state *cm_csrgen_state;
	struct cm_submit_state *cm_submit_state;
	struct cm_certsave_state *cm_certsave_state;
	struct cm_certread_state *cm_certread_state;
	struct cm_notify_state *cm_notify_state;
};

/* Helper routine to replace in-progress states with the previous "stable"
 * state. */
static void
cm_entry_reset_state(struct cm_store_entry *entry)
{
	switch (entry->cm_state) {
	case CM_NEED_KEY_PAIR:
		break;
	case CM_GENERATING_KEY_PAIR:
		entry->cm_state = CM_NEED_KEY_PAIR;
		break;
	case CM_NEED_KEY_GEN_PIN:
		entry->cm_state = CM_NEED_KEY_PAIR;
		break;
	case CM_HAVE_KEY_PAIR:
		break;
	case CM_NEED_CSR:
		entry->cm_state = CM_HAVE_KEY_PAIR;
		break;
	case CM_GENERATING_CSR:
		entry->cm_state = CM_HAVE_KEY_PAIR;
		break;
	case CM_NEED_CSR_GEN_PIN:
		entry->cm_state = CM_HAVE_KEY_PAIR;
		break;
	case CM_HAVE_CSR:
		break;
	case CM_NEED_TO_SUBMIT:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_SUBMITTING:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_NEED_TO_SAVE_CERT:
		break;
	case CM_SAVING_CERT:
		entry->cm_state = CM_NEED_TO_SAVE_CERT;
		break;
	case CM_NEED_TO_READ_CERT:
		break;
	case CM_READING_CERT:
		entry->cm_state = CM_NEED_TO_READ_CERT;
		break;
	case CM_SAVED_CERT:
		break;
	case CM_CA_REJECTED:
		break;
	case CM_CA_WORKING:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_CA_UNREACHABLE:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_CA_UNCONFIGURED:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_NEED_CA:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_NEED_GUIDANCE:
		break;
	case CM_MONITORING:
		break;
	case CM_NEED_TO_NOTIFY:
		entry->cm_state = CM_MONITORING;
		break;
	case CM_NOTIFYING:
		entry->cm_state = CM_NEED_TO_NOTIFY;
		break;
	case CM_NEWLY_ADDED:
		break;
	case CM_NEWLY_ADDED_START_READING_KEYI:
		break;
	case CM_NEWLY_ADDED_READING_KEYI:
		entry->cm_state = CM_NEWLY_ADDED_START_READING_KEYI;
		break;
	case CM_NEWLY_ADDED_NEED_KEYI_READ_PIN:
		entry->cm_state = CM_NEWLY_ADDED_START_READING_KEYI;
		break;
	case CM_NEWLY_ADDED_START_READING_CERT:
		break;
	case CM_NEWLY_ADDED_READING_CERT:
		entry->cm_state = CM_NEWLY_ADDED_START_READING_CERT;
		break;
	case CM_NEWLY_ADDED_DECIDING:
		break;
	case CM_INVALID:
		/* not reached */
		abort();
		break;
	}
}

static void
cm_waitfor_readable_fd(int fd, int delay)
{
	fd_set fds;
	struct timeval tv;
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = delay;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	select(fd + 1, &fds, NULL, &fds, (delay >= 0) ? &tv : NULL);
}

/* Set up run-time data associated with the entry. */
int
cm_iterate_init(struct cm_store_entry *entry, void **cm_iterate_state)
{
	struct cm_iterate_state *state;
	int fd;
	state = talloc_ptrtype(entry, state);
	if (state == NULL) {
		return ENOMEM;
	}
	memset(state, 0, sizeof(*state));
	*cm_iterate_state = state;
	cm_entry_reset_state(entry);
	state->cm_keyiread_state = cm_keyiread_start(entry);
	if (state->cm_keyiread_state != NULL) {
		while (cm_keyiread_ready(entry,
					 state->cm_keyiread_state) != 0) {
			fd = cm_keyiread_get_fd(entry,
						state->cm_keyiread_state);
			if (fd != -1) {
				cm_waitfor_readable_fd(fd, -1);
			}
		}
		cm_keyiread_done(entry, state->cm_keyiread_state);
		state->cm_keyiread_state = NULL;
	}
	state->cm_certread_state = cm_certread_start(entry);
	if (state->cm_certread_state != NULL) {
		while (cm_certread_ready(entry,
					 state->cm_certread_state) != 0) {
			fd = cm_certread_get_fd(entry,
						state->cm_certread_state);
			if (fd != -1) {
				cm_waitfor_readable_fd(fd, -1);
			}
		}
		cm_certread_done(entry, state->cm_certread_state);
		state->cm_certread_state = NULL;
	}
	cm_store_entry_save(entry);
	cm_log(3, "'%s' starts in state '%s'\n", entry->cm_id,
	       cm_store_state_as_string(entry->cm_state));
	return 0;
}

/* Check if the entry's expiration has crossed an interesting threshold. */
static int
cm_check_expiration_is_noteworthy(struct cm_store_entry *entry)
{
	unsigned int i, n_ttls;
	time_t *ttls, ttl, previous_ttl, default_ttls[] = {CM_DEFAULT_TTL_LIST};
	time_t now;
	now = time(NULL);
	/* How much time is left? */
	if (entry->cm_cert_expiration < now) {
		ttl = 0;
	} else {
		ttl = entry->cm_cert_expiration - now;
	}
	/* How much time was left, last time we checked? */
	if (entry->cm_cert_expiration < entry->cm_last_expiration_check) {
		previous_ttl = 0;
	} else {
		previous_ttl = entry->cm_cert_expiration -
			       entry->cm_last_expiration_check;
	}
	/* Note that we're checking now. */
	entry->cm_last_expiration_check = now;
	/* Which list of interesting values are we consulting? */
	if (entry->cm_ttls_default) {
		ttls = default_ttls;
		n_ttls = sizeof(default_ttls) / sizeof(default_ttls[0]);
	} else {
		ttls = entry->cm_ttls;
		n_ttls = entry->cm_n_ttls;
	}
	/* Check for crosses. */
	for (i = 0; i < n_ttls; i++) {
		/* We crossed a threshold. */
		if ((ttl < ttls[i]) && (previous_ttl >= ttls[i])) {
			return 0;
		}
		/* We crossed a threshold, and time is running backwards. */
		if ((ttl >= ttls[i]) && (previous_ttl < ttls[i])) {
			return 0;
		}
	}
	/* The certificate has expired. */
	if (ttl == 0) {
		return 0;
	}
	return -1;
}

int
cm_iterate(struct cm_store_entry *entry, struct cm_store_ca *ca,
	   struct cm_context *context,
	   struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
	   int (*get_n_cas)(struct cm_context *),
	   void *cm_iterate_state,
	   enum cm_time *when, int *delay, int *readfd)
{
	int i, j;
	struct cm_iterate_state *state;
	struct cm_store_ca *tmp_ca;
	enum cm_state old_entry_state;
	char *serial;
	state = cm_iterate_state;
	*readfd = -1;
	*when = cm_time_no_time;
	*delay = 0;
	old_entry_state = entry->cm_state;
	switch (entry->cm_state) {
	case CM_NEED_KEY_PAIR:
		/* Start a helper. */
		state->cm_keygen_state = cm_keygen_start(entry);
		if (state->cm_keygen_state != NULL) {
			/* Note that we're generating a key. */
			entry->cm_state = CM_GENERATING_KEY_PAIR;
			/* Wait for status update, or poll. */
			*readfd = cm_keygen_get_fd(entry,
						   state->cm_keygen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start generating a key; try again. */
			*when = cm_time_soonish;
		}
		break;

	case CM_GENERATING_KEY_PAIR:
		if (cm_keygen_ready(entry, state->cm_keygen_state) == 0) {
			if (cm_keygen_saved_keypair(entry,
						    state->cm_keygen_state) == 0) {
				/* Saved key pair; move on. */
				cm_keygen_done(entry, state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_HAVE_KEY_PAIR;
				*when = cm_time_now;
			} else {
				/* Failed to save key pair; take a breather and
				 * try again. */
				cm_keygen_done(entry, state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_NEED_KEY_PAIR;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_keygen_get_fd(entry,
						   state->cm_keygen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_KEY_GEN_PIN:
		*when = cm_time_no_time;
		break;

	case CM_HAVE_KEY_PAIR:
		entry->cm_state = CM_NEED_CSR;
		*when = cm_time_now;
		break;

	case CM_NEED_CSR:
		state->cm_csrgen_state = cm_csrgen_start(entry);
		if (state->cm_csrgen_state != NULL) {
			/* Note that we're generating a CSR. */
			entry->cm_state = CM_GENERATING_CSR;
			/* Wait for status update, or poll. */
			*readfd = cm_csrgen_get_fd(entry,
						   state->cm_csrgen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start generating a CSR; take a breather
			 * and try again. */
			*when = cm_time_soonish;
		}
		break;

	case CM_GENERATING_CSR:
		if (cm_csrgen_ready(entry, state->cm_csrgen_state) == 0) {
			if (cm_csrgen_save_csr(entry,
					       state->cm_csrgen_state) == 0) {
				/* Saved CSR; move on. */
				cm_csrgen_done(entry, state->cm_csrgen_state);
				state->cm_csrgen_state = NULL;
				entry->cm_state = CM_HAVE_CSR;
				*when = cm_time_now;
			} else {
				/* Failed to save CSR; try again. */
				cm_csrgen_done(entry, state->cm_csrgen_state);
				state->cm_csrgen_state = NULL;
				entry->cm_state = CM_NEED_CSR;
				*when = cm_time_soon;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_csrgen_get_fd(entry,
						   state->cm_csrgen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_CSR_GEN_PIN:
		*when = cm_time_no_time;
		break;

	case CM_HAVE_CSR:
		entry->cm_state = CM_NEED_TO_SUBMIT;
		*when = cm_time_now;
		break;

	case CM_NEED_TO_SUBMIT:
		state->cm_submit_state = cm_submit_start(ca, entry);
		if (state->cm_submit_state != NULL) {
			/* Note that we're in the process of submitting the CSR
			 * to a CA. */
			entry->cm_state = CM_SUBMITTING;
			/* Wait for status update, or poll. */
			*readfd = cm_submit_get_fd(entry,
						   state->cm_submit_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
			/* If we're doing internal-CA, mark this serial number
			 * as used. */
			if (ca != NULL) {
				switch (ca->cm_ca_type) {
				case cm_ca_external:
					break;
				case cm_ca_internal_self:
					serial = ca->cm_ca_internal_serial;
					ca->cm_ca_internal_serial =
						cm_store_increment_serial(ca, serial);
					talloc_free(serial);
					cm_store_ca_save(ca);
				}
			}
		} else {
			if (ca == NULL) {
				/* No known CA is associated with this entry. */
				entry->cm_state = CM_NEED_CA;
				*when = cm_time_now;
			} else {
				/* Failed to start submission; take a breather
				 * and try again. */
				*when = cm_time_soonish;
			}
		}
		break;

	case CM_SUBMITTING:
		if (cm_submit_ready(entry, state->cm_submit_state) == 0) {
			entry->cm_submitted = time(NULL);
			if (cm_submit_issued(entry,
					     state->cm_submit_state) == 0) {
				/* We're all done.  Save the certificate to its
				 * real home. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_NEED_TO_SAVE_CERT;
				*when = cm_time_now;
			} else
			if (cm_submit_rejected(entry,
					       state->cm_submit_state) == 0) {
				/* The request was flat-out rejected. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_CA_REJECTED;
				*when = cm_time_delay;
				*delay = CM_DELAY_CA_POLL;
			} else
			if (cm_submit_unreachable(entry,
						  state->cm_submit_state) == 0) {
				/* Let's try again later. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_CA_UNREACHABLE;
				*when = cm_time_delay;
				*delay = CM_DELAY_CA_POLL;
			} else
			if (cm_submit_save_ca_cookie(entry,
						     state->cm_submit_state) == 0) {
				/* Saved CA's identifier for our request; give
				 * it a little time and then ask. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_CA_WORKING;
				*when = cm_time_soonish;
			} else
			if (cm_submit_unconfigured(entry,
						   state->cm_submit_state) == 0) {
				/* Saved CA's identifier for our request; give
				 * it a little time and then ask. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_CA_UNCONFIGURED;
				*when = cm_time_delay;
				*delay = CM_DELAY_CA_POLL;
			} else {
				/* Don't know what's going on. HELP! */
				cm_log(1,
				       "Unable to determine course of action "
				       "for \"%s\".\n", entry->cm_id);
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_NEED_GUIDANCE;
				*when = cm_time_now;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_submit_get_fd(entry,
						   state->cm_submit_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_TO_SAVE_CERT:
		state->cm_certsave_state = cm_certsave_start(entry);
		if (state->cm_certsave_state != NULL) {
			/* Note that we're saving the cert. */
			entry->cm_state = CM_SAVING_CERT;
			/* Wait for status update, or poll. */
			*readfd = cm_certsave_get_fd(entry,
						     state->cm_certsave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start saving the certificate; try again. */
			*when = cm_time_soonish;
		}
		break;

	case CM_SAVING_CERT:
		if (cm_certsave_ready(entry, state->cm_certsave_state) == 0) {
			if (cm_certsave_saved(entry,
					      state->cm_certsave_state) == 0) {
				/* Saved certificate; note that we have to
				 * reload the information that was in it. */
				cm_certsave_done(entry, state->cm_certsave_state);
				state->cm_certsave_state = NULL;
				entry->cm_state = CM_NEED_TO_READ_CERT;
				*when = cm_time_now;
			} else {
				/* Failed to save cert; try again in a bit. */
				cm_certsave_done(entry,
						 state->cm_certsave_state);
				state->cm_certsave_state = NULL;
				entry->cm_state = CM_NEED_TO_SAVE_CERT;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_certsave_get_fd(entry,
						     state->cm_certsave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_TO_READ_CERT:
		state->cm_certread_state = cm_certread_start(entry);
		if (state->cm_certread_state != NULL) {
			/* Note that we're reading the cert. */
			entry->cm_state = CM_READING_CERT;
			/* Wait for status update, or poll. */
			*readfd = cm_certread_get_fd(entry,
						     state->cm_certread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start re-reading the certificate; try
			 * again. */
			*when = cm_time_soonish;
		}
		break;

	case CM_READING_CERT:
		if (cm_certread_ready(entry, state->cm_certread_state) == 0) {
			/* Finished reloading certificate. */
			cm_certread_done(entry, state->cm_certread_state);
			state->cm_certread_state = NULL;
			entry->cm_state = CM_SAVED_CERT;
			*when = cm_time_now;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_certread_get_fd(entry,
						     state->cm_certread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_SAVED_CERT:
		entry->cm_state = CM_MONITORING;
		*when = cm_time_now;
		break;

	case CM_CA_REJECTED:
		*when = cm_time_no_time;
		break;

	case CM_CA_WORKING:
		entry->cm_state = CM_NEED_TO_SUBMIT;
		*when = cm_time_now;
		break;

	case CM_CA_UNREACHABLE:
		entry->cm_state = CM_NEED_TO_SUBMIT;
		*when = cm_time_now;
		break;

	case CM_CA_UNCONFIGURED:
		entry->cm_state = CM_NEED_TO_SUBMIT;
		*when = cm_time_now;
		break;

	case CM_NEED_GUIDANCE:
		*when = cm_time_no_time;
		break;

	case CM_NEED_CA:
		entry->cm_state = CM_NEED_TO_SUBMIT;
		*when = cm_time_soonish;
		break;

	case CM_MONITORING:
		if ((entry->cm_monitor ||
		     entry->cm_monitor_default) && /* XXX */
		    (cm_check_expiration_is_noteworthy(entry) == 0)) {
			/* Kick off a notification. */
			entry->cm_state = CM_NEED_TO_NOTIFY;
			*when = cm_time_now;
		} else {
			/* Nothing to do here. */
			*delay = 24 * 60 * 60; /* XXX */
			*when = cm_time_delay;
		}
		break;

	case CM_NEED_TO_NOTIFY:
		state->cm_notify_state = cm_notify_start(entry);
		if (state->cm_notify_state != NULL) {
			entry->cm_state = CM_NOTIFYING;
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(entry,
						   state->cm_notify_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start notifying; try again. */
			*when = cm_time_soonish;
		}
		break;

	case CM_NOTIFYING:
		if (cm_notify_ready(entry, state->cm_notify_state) == 0) {
			cm_notify_done(entry, state->cm_notify_state);
			state->cm_notify_state = NULL;
		}
		if ((entry->cm_autorenew || entry->cm_autorenew_default)) {
			/* We need to go all the way back to generating the CSR
			 * because the user may have asked us to request with
			 * parameters that have changed since we last generated
			 * a CSR. */
			entry->cm_state = CM_NEED_CSR;
			*when = cm_time_soon;
		} else {
			entry->cm_state = CM_MONITORING;
			*when = cm_time_soon;
		}
		break;

	case CM_NEWLY_ADDED:
		/* We need to do some recon, and then decide what we need to
		 * do to make things the way the user has specified that they
		 * should be. */
		if (entry->cm_key_storage_type != cm_key_storage_none) {
			entry->cm_state = CM_NEWLY_ADDED_START_READING_KEYI;
			*when = cm_time_now;
		} else {
			entry->cm_state = CM_NEWLY_ADDED_START_READING_CERT;
			*when = cm_time_now;
		}
		break;

	case CM_NEWLY_ADDED_START_READING_KEYI:
		/* Try to read information about the key. */
		state->cm_keyiread_state = cm_keyiread_start(entry);
		if (state->cm_keyiread_state != NULL) {
			entry->cm_state = CM_NEWLY_ADDED_READING_KEYI;
			/* Note that we're reading information about
			 * the key. */
			*readfd = cm_keyiread_get_fd(entry,
						     state->cm_keyiread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start reading info about the key;
			 * try again soon. */
			*when = cm_time_soonish;
		}
		break;

	case CM_NEWLY_ADDED_READING_KEYI:
		/* If we finished reading info about the key, move on to try
		 * and read the certificate. */
		if (cm_keyiread_ready(entry, state->cm_keyiread_state) == 0) {
			cm_keyiread_done(entry, state->cm_keyiread_state);
			state->cm_keyiread_state = NULL;
			entry->cm_state = CM_NEWLY_ADDED_START_READING_CERT;
			*when = cm_time_now;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_keyiread_get_fd(entry,
						     state->cm_keyiread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEWLY_ADDED_NEED_KEYI_READ_PIN:
		*when = cm_time_no_time;
		break;

	case CM_NEWLY_ADDED_START_READING_CERT:
		/* Try to read the certificate. */
		state->cm_certread_state = cm_certread_start(entry);
		if (state->cm_certread_state != NULL) {
			entry->cm_state = CM_NEWLY_ADDED_READING_CERT;
			/* Note that we're reading information about
			 * the certificate. */
			*readfd = cm_certread_get_fd(entry,
						     state->cm_certread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start reading info about the certificate;
			 * try again soon. */
			*when = cm_time_soonish;
		}
		break;

	case CM_NEWLY_ADDED_READING_CERT:
		/* If we finished reading info about the cert, move on to try
		 * to figure out what we should do next. */
		if (cm_certread_ready(entry, state->cm_certread_state) == 0) {
			cm_certread_done(entry, state->cm_certread_state);
			state->cm_certread_state = NULL;
			entry->cm_state = CM_NEWLY_ADDED_DECIDING;
			*when = cm_time_now;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_certread_get_fd(entry,
						     state->cm_certread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEWLY_ADDED_DECIDING:
		/* Decide what to do next.  Assign a CA if it doesn't have one
		 * assigned to it already. */
		if ((entry->cm_ca_name == NULL) &&
		    (entry->cm_cert_issuer != NULL)) {
			/* Walk the list of known names of known CAs and try to
			 * match one with the issuer of the certificate we
			 * already have. */
			for (i = 0; i < (*get_n_cas)(context); i++) {
				tmp_ca = (*get_ca_by_index)(context, i);
				for (j = 0;
				     (tmp_ca->cm_ca_known_issuer_names != NULL) &&
				     (tmp_ca->cm_ca_known_issuer_names[j] != NULL);
				     j++) {
					if (strcmp(tmp_ca->cm_ca_known_issuer_names[j],
						   entry->cm_cert_issuer) == 0) {
						entry->cm_ca_name = talloc_strdup(entry, tmp_ca->cm_id);
					}
				}
			}
		}
		/* No match -> assign the default. */
		if (entry->cm_ca_name == NULL) {
			for (i = 0; i < (*get_n_cas)(context); i++) {
				tmp_ca = (*get_ca_by_index)(context, i);
				if (tmp_ca->cm_ca_is_default) {
					entry->cm_ca_name = talloc_strdup(entry, tmp_ca->cm_id);
				}
			}
		}
		/* If we have a certificate, we go straight to monitoring it. */
		if (entry->cm_cert != NULL) {
			cm_log(3, "'%s' has a certificate, monitoring it\n",
			       entry->cm_id);
			entry->cm_state = CM_MONITORING;
			*when = cm_time_now;
		} else
		/* If we don't have a certificate, but we know where the key
		 * should be, we have some options. */
		if (entry->cm_key_storage_type != cm_key_storage_none) {
			/* If we don't have a certificate, but we have a key,
			 * the next step is to generate a CSR. */
			if (entry->cm_key_type.cm_key_size > 0) {
				cm_log(3, "'%s' has no certificate, will "
				       "attempt enrollment using "
				       "already-present key\n", entry->cm_id);
				entry->cm_state = CM_NEED_CSR;
				*when = cm_time_now;
			} else {
				/* No certificate, no key, start with
				 * generating the key. */
				cm_log(3, "'%s' has no key or certificate, "
				       "will generate keys and attempt "
				       "enrollment\n", entry->cm_id);
				entry->cm_state = CM_NEED_KEY_PAIR;
				*when = cm_time_now;
			}
		} else {
			/* And if we don't have a place for the key, we're
			 * screwed.  Hopefully this didn't happen normally. */
			cm_log(3, "'%s' has no key or certificate location, "
			       "don't know what to do about that\n",
			       entry->cm_id);
			entry->cm_state = CM_NEED_GUIDANCE;
			*when = cm_time_now;
		}
		break;

	case CM_INVALID:
		/* not reached */
		abort();
		break;
	}
	if (old_entry_state != entry->cm_state) {
		cm_log(3, "'%s' moved to state '%s'\n", entry->cm_id,
		       cm_store_state_as_string(entry->cm_state));
		cm_store_entry_save(entry);
	}
	return 0;
}

/* Cancel and clean up any in-progress work and then free the working state. */
int
cm_iterate_done(struct cm_store_entry *entry, void *cm_iterate_state)
{
	struct cm_iterate_state *state;
	state = cm_iterate_state;
	if (state != NULL) {
		if (state->cm_submit_state != NULL) {
			cm_submit_done(entry, state->cm_submit_state);
			state->cm_submit_state = NULL;
		}
		if (state->cm_csrgen_state != NULL) {
			cm_csrgen_done(entry, state->cm_csrgen_state);
			state->cm_csrgen_state = NULL;
		}
		if (state->cm_keyiread_state != NULL) {
			cm_keyiread_done(entry, state->cm_keyiread_state);
			state->cm_keyiread_state = NULL;
		}
		if (state->cm_keygen_state != NULL) {
			cm_keygen_done(entry, state->cm_keygen_state);
			state->cm_keygen_state = NULL;
		}
		if (state->cm_notify_state != NULL) {
			cm_notify_done(entry, state->cm_notify_state);
			state->cm_notify_state = NULL;
		}
		talloc_free(state);
	}
	cm_entry_reset_state(entry);
	cm_log(3, "'%s' ends in state '%s'\n", entry->cm_id,
	       cm_store_state_as_string(entry->cm_state));
	return 0;
}
