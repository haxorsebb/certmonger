/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014,2015 Red Hat, Inc.
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

#include "cadata.h"
#include "canalyze.h"
#include "casave.h"
#include "certread.h"
#include "certsave.h"
#include "cm.h"
#include "csrgen.h"
#include "hook.h"
#include "iterate.h"
#include "keygen.h"
#include "keyiread.h"
#include "log.h"
#include "notify.h"
#include "prefs.h"
#include "scepgen.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"
#include "tm.h"

struct cm_entry_state {
	struct cm_keygen_state *cm_keygen_state;
	struct cm_keyiread_state *cm_keyiread_state;
	struct cm_csrgen_state *cm_csrgen_state;
	struct cm_scepgen_state *cm_scepgen_state;
	struct cm_submit_state *cm_submit_state;
	struct cm_certsave_state *cm_certsave_state;
	struct cm_hook_state *cm_hook_state;
	struct cm_certread_state *cm_certread_state;
	struct cm_notify_state *cm_notify_state;
	struct cm_casave_state *cm_casave_state;
};

struct cm_ca_state {
	enum cm_ca_phase cm_phase;
	struct cm_ca_analyze_state *cm_ca_cert_analyze_state;
	struct cm_ca_analyze_state *cm_ca_ecert_analyze_state;
	time_t cm_cert_refresh_delay;
	time_t cm_ecert_refresh_delay;
	struct cm_cadata_state *cm_task_state;
	struct cm_hook_state *cm_hook_state;
	struct cm_casave_state *cm_casave_state;
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
	case CM_NEED_KEY_GEN_TOKEN:
		entry->cm_state = CM_NEED_KEY_PAIR;
		break;
	case CM_NEED_KEY_GEN_PIN:
		entry->cm_state = CM_NEED_KEY_PAIR;
		break;
	case CM_NEED_KEY_GEN_PERMS:
		entry->cm_state = CM_NEED_KEY_PAIR;
		break;
	case CM_HAVE_KEY_PAIR:
		break;
	case CM_NEED_KEYINFO:
		break;
	case CM_READING_KEYINFO:
		entry->cm_state = CM_NEED_KEYINFO;
		break;
	case CM_NEED_KEYINFO_READ_TOKEN:
		entry->cm_state = CM_NEED_KEYINFO;
		break;
	case CM_NEED_KEYINFO_READ_PIN:
		entry->cm_state = CM_NEED_KEYINFO;
		break;
	case CM_HAVE_KEYINFO:
		break;
	case CM_NEED_CSR:
		entry->cm_state = CM_HAVE_KEYINFO;
		break;
	case CM_NEED_CSR_GEN_TOKEN:
		entry->cm_state = CM_HAVE_KEYINFO;
		break;
	case CM_NEED_CSR_GEN_PIN:
		entry->cm_state = CM_HAVE_KEYINFO;
		break;
	case CM_GENERATING_CSR:
		entry->cm_state = CM_HAVE_KEYINFO;
		break;
	case CM_HAVE_CSR:
		break;
	case CM_NEED_SCEP_DATA:
		break;
	case CM_NEED_SCEP_GEN_TOKEN:
		entry->cm_state = CM_NEED_SCEP_DATA;
		break;
	case CM_NEED_SCEP_GEN_PIN:
		entry->cm_state = CM_NEED_SCEP_DATA;
		break;
	case CM_NEED_SCEP_ENCRYPTION_CERT:
		entry->cm_state = CM_NEED_SCEP_DATA;
		break;
	case CM_NEED_SCEP_RSA_CLIENT_KEY:
		entry->cm_state = CM_NEED_SCEP_DATA;
		break;
	case CM_GENERATING_SCEP_DATA:
		entry->cm_state = CM_NEED_SCEP_DATA;
		break;
	case CM_HAVE_SCEP_DATA:
		break;
	case CM_NEED_TO_SUBMIT:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_SUBMITTING:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_NEED_TO_SAVE_CERT:
		break;
	case CM_START_SAVING_CERT:
		entry->cm_state = CM_NEED_TO_SAVE_CERT;
		break;
	case CM_PRE_SAVE_CERT:
		entry->cm_state = CM_NEED_TO_SAVE_CERT;
		break;
	case CM_SAVING_CERT:
		entry->cm_state = CM_NEED_TO_SAVE_CERT;
		break;
	case CM_NEED_CERTSAVE_PERMS:
		entry->cm_state = CM_NEED_TO_SAVE_CERT;
		break;
	case CM_NEED_CERTSAVE_TOKEN:
		entry->cm_state = CM_NEED_TO_SAVE_CERT;
		break;
	case CM_NEED_CERTSAVE_PIN:
		entry->cm_state = CM_NEED_TO_SAVE_CERT;
		break;
	case CM_NEED_TO_SAVE_CA_CERTS:
		break;
	case CM_START_SAVING_CA_CERTS:
		entry->cm_state = CM_NEED_TO_SAVE_CA_CERTS;
		break;
	case CM_SAVING_CA_CERTS:
		entry->cm_state = CM_NEED_TO_SAVE_CA_CERTS;
		break;
	case CM_NEED_CA_CERT_SAVE_PERMS:
		entry->cm_state = CM_NEED_TO_SAVE_CA_CERTS;
		break;
	case CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED:
		entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED;
		break;
	case CM_NOTIFYING_ISSUED_CA_SAVE_FAILED:
		entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED;
		break;
	case CM_NEED_TO_READ_CERT:
		break;
	case CM_READING_CERT:
		entry->cm_state = CM_NEED_TO_READ_CERT;
		break;
	case CM_SAVED_CERT:
		break;
	case CM_POST_SAVED_CERT:
		entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_SAVED;
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
	case CM_NEED_TO_NOTIFY_VALIDITY:
		entry->cm_state = CM_MONITORING;
		break;
	case CM_NOTIFYING_VALIDITY:
		entry->cm_state = CM_NEED_TO_NOTIFY_VALIDITY;
		break;
	case CM_NEED_TO_NOTIFY_REJECTION:
		break;
	case CM_NOTIFYING_REJECTION:
		entry->cm_state = CM_NEED_TO_NOTIFY_REJECTION;
		break;
	case CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED:
		break;
	case CM_NOTIFYING_ISSUED_SAVE_FAILED:
		entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED;
		break;
	case CM_NEED_TO_NOTIFY_ISSUED_SAVED:
		break;
	case CM_NOTIFYING_ISSUED_SAVED:
		entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_SAVED;
		break;
	case CM_NEED_TO_SAVE_ONLY_CA_CERTS:
		entry->cm_state = CM_NEED_TO_SAVE_ONLY_CA_CERTS;
		break;
	case CM_START_SAVING_ONLY_CA_CERTS:
		entry->cm_state = CM_NEED_TO_SAVE_ONLY_CA_CERTS;
		break;
	case CM_SAVING_ONLY_CA_CERTS:
		entry->cm_state = CM_NEED_TO_SAVE_ONLY_CA_CERTS;
		break;
	case CM_NEED_ONLY_CA_CERT_SAVE_PERMS:
		entry->cm_state = CM_NEED_TO_SAVE_ONLY_CA_CERTS;
		break;
	case CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED:
		entry->cm_state = CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED;
		break;
	case CM_NOTIFYING_ONLY_CA_SAVE_FAILED:
		entry->cm_state = CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED;
		break;
	case CM_NEWLY_ADDED:
		break;
	case CM_NEWLY_ADDED_START_READING_KEYINFO:
		entry->cm_state = CM_NEWLY_ADDED;
		break;
	case CM_NEWLY_ADDED_READING_KEYINFO:
		entry->cm_state = CM_NEWLY_ADDED;
		break;
	case CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN:
		entry->cm_state = CM_NEWLY_ADDED;
		break;
	case CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN:
		entry->cm_state = CM_NEWLY_ADDED;
		break;
	case CM_NEWLY_ADDED_START_READING_CERT:
		entry->cm_state = CM_NEWLY_ADDED;
		break;
	case CM_NEWLY_ADDED_READING_CERT:
		entry->cm_state = CM_NEWLY_ADDED;
		break;
	case CM_NEWLY_ADDED_DECIDING:
		entry->cm_state = CM_NEWLY_ADDED;
		break;
	case CM_INVALID:
		/* not reached */
		abort();
		break;
	}
}

void
cm_waitfor_readable_fd(int fd, int delay)
{
	fd_set fds, *fdset = NULL;
	struct timeval tv;

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = delay;
	FD_ZERO(&fds);
	if (fd != -1) {
		fdset = &fds;
		FD_SET(fd, fdset);
	}
	if (select(fd + 1, fdset, NULL, fdset, (delay >= 0) ? &tv : NULL) < 0) {
		if (delay < 0) {
			/* No defined delay, but an error. */
			cm_log(3, "indefinite select() on %d returned error: "
			       "%s\n", fd, strerror(errno));
		}
	}
}

/* Decide how long to wait before contacting the CA again. */
static time_t
cm_decide_ca_delay(time_t remaining)
{
	time_t delay;

	delay = CM_DELAY_CA_POLL;
	if ((remaining != (time_t) -1) && (remaining < 2 * delay)) {
		delay = remaining / 2;
		if (delay < CM_DELAY_CA_POLL_MINIMUM) {
			delay = CM_DELAY_CA_POLL_MINIMUM;
		}
		if (delay > CM_DELAY_CA_POLL_MAXIMUM) {
			delay = CM_DELAY_CA_POLL_MAXIMUM;
		}
	}
	return delay;
}

/* Decide how long to wait before looking at a certificate again. */
static time_t
cm_decide_monitor_delay(time_t remaining)
{
	time_t delay;

	delay = CM_DELAY_MONITOR_POLL;
	if ((remaining != (time_t) -1) && (remaining < 2 * delay)) {
		delay = remaining / 2;
		if (delay < CM_DELAY_MONITOR_POLL_MINIMUM) {
			delay = CM_DELAY_MONITOR_POLL_MINIMUM;
		}
	}
	return delay;
}

/* Decide how long to wait before attempting to contact the CA to retrieve
 * information again. */
static time_t
cm_decide_cadata_delay(void)
{
	time_t delay;

	delay = CM_DELAY_CADATA_POLL;
	return delay;
}

/* Manage a "lock" that we use to serialize access to THE REST OF THE WORLD. */
static void *writing_lock;
static enum cm_ca_phase writing_lock_ca_phase = cm_ca_phase_invalid;
static dbus_bool_t
cm_writing_has_lock(void *holder, enum cm_ca_phase phase)
{
	return (writing_lock == holder) &&
	       ((writing_lock_ca_phase == cm_ca_phase_invalid) ||
		(writing_lock_ca_phase == phase));
}
static dbus_bool_t
cm_writing_lock_by_entry(struct cm_store_entry *entry)
{
	if ((writing_lock == entry) || (writing_lock == NULL)) {
		if (writing_lock == NULL) {
			cm_log(3, "%s('%s') taking writing lock\n",
			       entry->cm_busname, entry->cm_nickname);
			writing_lock = entry;
		} else {
			abort();
		}
		return TRUE;
	} else {
		return FALSE;
	}
}
static dbus_bool_t
cm_writing_unlock_by_entry(struct cm_store_entry *entry)
{
	if ((writing_lock == entry) || (writing_lock == NULL)) {
		if (writing_lock == entry) {
			cm_log(3, "%s('%s') releasing writing lock\n",
			       entry->cm_busname, entry->cm_nickname);
			writing_lock = NULL;
		} else {
			abort();
		}
		return TRUE;
	} else {
		return FALSE;
	}
}
static dbus_bool_t
cm_writing_lock_by_ca(struct cm_store_ca *ca, enum cm_ca_phase phase)
{
	if (((writing_lock == ca) && (writing_lock_ca_phase == phase)) ||
	    (writing_lock == NULL)) {
		if (writing_lock == NULL) {
			cm_log(3, "%s('%s').%s taking writing lock\n",
			       ca->cm_busname, ca->cm_nickname,
			       cm_store_ca_phase_as_string(phase));
			writing_lock = ca;
			if (phase == cm_ca_phase_invalid) {
				abort();
			}
			writing_lock_ca_phase = phase;
		} else {
			abort();
		}
		return TRUE;
	} else {
		return FALSE;
	}
}
static dbus_bool_t
cm_writing_unlock_by_ca(struct cm_store_ca *ca, enum cm_ca_phase phase)
{
	if (((writing_lock == ca) && (writing_lock_ca_phase == phase)) ||
	    (writing_lock == NULL)) {
		if (writing_lock == ca) {
			cm_log(3, "%s('%s').%s releasing writing lock\n",
			       ca->cm_busname, ca->cm_nickname,
			       cm_store_ca_phase_as_string(phase));
			writing_lock = NULL;
			writing_lock_ca_phase = cm_ca_phase_invalid;
		} else {
			abort();
		}
		return TRUE;
	} else {
		return FALSE;
	}
}

/* Set up run-time data associated with the entry. */
int
cm_iterate_entry_init(struct cm_store_entry *entry, void **cm_iterate_state)
{
	struct cm_entry_state *state;
	int fd;
	state = talloc_ptrtype(entry, state);
	if (state == NULL) {
		return ENOMEM;
	}
	memset(state, 0, sizeof(*state));
	*cm_iterate_state = state;
	cm_entry_reset_state(entry);
	if (cm_writing_has_lock(entry, cm_ca_phase_invalid)) {
		cm_writing_unlock_by_entry(entry);
	}
	state->cm_keyiread_state = cm_keyiread_start(entry);
	if (state->cm_keyiread_state != NULL) {
		while (cm_keyiread_ready(state->cm_keyiread_state) != 0) {
			fd = cm_keyiread_get_fd(state->cm_keyiread_state);
			if (fd != -1) {
				cm_waitfor_readable_fd(fd, -1);
			}
		}
		cm_keyiread_done(state->cm_keyiread_state);
		state->cm_keyiread_state = NULL;
	}
	state->cm_certread_state = cm_certread_start(entry);
	if (state->cm_certread_state != NULL) {
		while (cm_certread_ready(state->cm_certread_state) != 0) {
			fd = cm_certread_get_fd(state->cm_certread_state);
			if (fd != -1) {
				cm_waitfor_readable_fd(fd, -1);
			}
		}
		cm_certread_done(state->cm_certread_state);
		state->cm_certread_state = NULL;
	}
	cm_store_entry_save(entry);
	cm_log(3, "%s('%s') starts in state '%s'\n",
	       entry->cm_busname, entry->cm_nickname,
	       cm_store_state_as_string(entry->cm_state));
	return 0;
}

/* Check if the entry's expiration has crossed an interesting threshold. */
static int
cm_check_expiration_is_noteworthy(struct cm_store_entry *entry,
				  int (*get_ttls)(const time_t **,
						  unsigned int *),
				  time_t *last_check)
{
	unsigned int i, n_ttls;
	time_t now, ttl, previous_ttl;
	const time_t *ttls;

	now = cm_time(NULL);
	/* Do we have validity information? */
	if (entry->cm_cert_not_after == 0) {
		return -1;
	}
	/* Is it at least (some arbitrary minimum) old? */
	if (entry->cm_cert_not_before > (now - CM_DELAY_MONITOR_POLL_MINIMUM)) {
		return -1;
	}
	/* How much time is left? */
	if (entry->cm_cert_not_after < now) {
		ttl = 0;
	} else {
		ttl = entry->cm_cert_not_after - now;
	}
	/* How much time was left, last time we checked? */
	if (entry->cm_cert_not_after < *last_check) {
		previous_ttl = 0;
	} else {
		previous_ttl = entry->cm_cert_not_after - *last_check;
	}
	/* Note that we're checking now. */
	*last_check = now;
	/* Which list of interesting values are we consulting? */
	ttls = NULL;
	n_ttls = 0;
	if (((*get_ttls)(&ttls, &n_ttls) != 0) || (n_ttls == 0)) {
		return -1;
	}
	/* Check for crosses. */
	for (i = 0; i < n_ttls; i++) {
		/* We crossed a threshold. */
		if ((ttl < ttls[i]) && (previous_ttl >= ttls[i])) {
			return 0;
		}
		/* We crossed a threshold... and time is running backwards. */
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
cm_iterate_entry(struct cm_store_entry *entry, struct cm_store_ca *ca,
		 struct cm_context *context,
		 struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
		 int (*get_n_cas)(struct cm_context *),
		 struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
		 int (*get_n_entries)(struct cm_context *),
		 void (*emit_entry_saved_cert)(struct cm_context *,
					       struct cm_store_entry *),
		 void (*emit_entry_changes)(struct cm_context *,
					    struct cm_store_entry *,
					    struct cm_store_entry *),
		 void *cm_iterate_state,
		 enum cm_time *when, int *delay, int *readfd)
{
	int i, j;
	time_t remaining;
	struct cm_entry_state *state;
	struct cm_store_ca *tmp_ca;
	struct cm_store_entry *old_entry;
	char *serial;
	const char *tmp_ca_name;

	state = cm_iterate_state;
	*readfd = -1;
	*when = cm_time_no_time;
	*delay = 0;

	old_entry = cm_store_entry_dup(entry, entry);
	if (entry->cm_cert_not_after != 0) {
		remaining = entry->cm_cert_not_after - cm_time(NULL);
	} else {
		remaining = -1;
	}

	switch (entry->cm_state) {
	case CM_NEED_KEY_PAIR:
		if (!cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		/* Start a helper. */
		state->cm_keygen_state = cm_keygen_start(entry);
		if (state->cm_keygen_state != NULL) {
			/* Note that we're generating a key. */
			entry->cm_state = CM_GENERATING_KEY_PAIR;
			/* Wait for status update, or poll. */
			*readfd = cm_keygen_get_fd(state->cm_keygen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start generating a key; try again. */
			cm_writing_unlock_by_entry(entry);
			*when = cm_time_soonish;
		}
		break;

	case CM_GENERATING_KEY_PAIR:
		if (cm_keygen_ready(state->cm_keygen_state) == 0) {
			if (!cm_writing_unlock_by_entry(entry)) {
				/* If for some reason we fail to release the
				 * lock that we have, try to release it again
				 * soon. */
				*when = cm_time_soon;
				cm_log(1, "%s('%s') failed to release saving "
				       "lock, probably a bug\n",
				       entry->cm_busname, entry->cm_nickname);
				break;
			}
			if (cm_keygen_saved_keypair(state->cm_keygen_state) == 0) {
				/* Saved key pair; move on. */
				cm_keygen_done(state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_HAVE_KEY_PAIR;
				*when = cm_time_now;
			} else
			if (cm_keygen_need_perms(state->cm_keygen_state) == 0) {
				/* Whoops, we need help. */
				cm_keygen_done(state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_NEED_KEY_GEN_PERMS;
				*when = cm_time_now;
			} else
			if (cm_keygen_need_token(state->cm_keygen_state) == 0) {
				/* Whoops, we need help. */
				cm_keygen_done(state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_NEED_KEY_GEN_TOKEN;
				*when = cm_time_now;
			} else
			if (cm_keygen_need_pin(state->cm_keygen_state) == 0) {
				/* Whoops, we need help. */
				cm_keygen_done(state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_NEED_KEY_GEN_PIN;
				*when = cm_time_now;
			} else {
				/* Failed to save key pair; take a breather and
				 * try again. */
				cm_keygen_done(state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_NEED_KEY_PAIR;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_keygen_get_fd(state->cm_keygen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_KEY_GEN_PERMS:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEED_KEY_GEN_TOKEN:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEED_KEY_GEN_PIN:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_HAVE_KEY_PAIR:
		entry->cm_state = CM_NEED_KEYINFO;
		*when = cm_time_now;
		break;

	case CM_NEED_KEYINFO:
		/* Try to read information about the key. */
		state->cm_keyiread_state = cm_keyiread_start(entry);
		if (state->cm_keyiread_state != NULL) {
			entry->cm_state = CM_READING_KEYINFO;
			/* Note that we're reading information about
			 * the key. */
			*readfd = cm_keyiread_get_fd(state->cm_keyiread_state);
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

	case CM_READING_KEYINFO:
		/* If we finished reading info about the key, move on to
		 * generating a CSR. */
		if (cm_keyiread_ready(state->cm_keyiread_state) == 0) {
			if (cm_keyiread_finished_reading(state->cm_keyiread_state) == 0) {
				entry->cm_state = CM_HAVE_KEYINFO;
				*when = cm_time_now;
			} else
			if (cm_keyiread_need_token(state->cm_keyiread_state) == 0) {
				/* If we need the token, just hang on. */
				entry->cm_state = CM_NEED_KEYINFO_READ_TOKEN;
				*when = cm_time_now;
			} else
			if (cm_keyiread_need_pin(state->cm_keyiread_state) == 0) {
				/* If we need the PIN, just hang on. */
				entry->cm_state = CM_NEED_KEYINFO_READ_PIN;
				*when = cm_time_now;
			} else {
				/* Otherwise try to generate a new key pair. */
				entry->cm_state = CM_NEED_KEY_PAIR;
				*when = cm_time_soonish;
			}
			cm_keyiread_done(state->cm_keyiread_state);
			state->cm_keyiread_state = NULL;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_keyiread_get_fd(state->cm_keyiread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_KEYINFO_READ_TOKEN:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEED_KEYINFO_READ_PIN:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_HAVE_KEYINFO:
		entry->cm_state = CM_NEED_CSR;
		*when = cm_time_now;
		break;

	case CM_NEED_CSR:
		state->cm_csrgen_state = cm_csrgen_start(entry);
		if (state->cm_csrgen_state != NULL) {
			/* Note that we're generating a CSR. */
			entry->cm_state = CM_GENERATING_CSR;
			/* Wait for status update, or poll. */
			*readfd = cm_csrgen_get_fd(state->cm_csrgen_state);
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
		if (cm_csrgen_ready(state->cm_csrgen_state) == 0) {
			if (cm_csrgen_save_csr(state->cm_csrgen_state) == 0) {
				/* Saved CSR; move on. */
				cm_csrgen_done(state->cm_csrgen_state);
				state->cm_csrgen_state = NULL;
				entry->cm_state = CM_HAVE_CSR;
				*when = cm_time_now;
			} else
			if (cm_csrgen_need_token(state->cm_csrgen_state) == 0) {
				/* Need a token; wait for it. */
				cm_csrgen_done(state->cm_csrgen_state);
				state->cm_csrgen_state = NULL;
				entry->cm_state = CM_NEED_CSR_GEN_TOKEN;
				*when = cm_time_now;
			} else
			if (cm_csrgen_need_pin(state->cm_csrgen_state) == 0) {
				/* Need a PIN; wait for it. */
				cm_csrgen_done(state->cm_csrgen_state);
				state->cm_csrgen_state = NULL;
				entry->cm_state = CM_NEED_CSR_GEN_PIN;
				*when = cm_time_now;
			} else {
				/* Failed to save CSR; try again. */
				cm_csrgen_done(state->cm_csrgen_state);
				state->cm_csrgen_state = NULL;
				entry->cm_state = CM_NEED_CSR;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_csrgen_get_fd(state->cm_csrgen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_CSR_GEN_TOKEN:
		*when = cm_time_no_time;
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
			*readfd = cm_submit_get_fd(state->cm_submit_state);
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
			/* In case we're talking to a server over SCEP, make a
			 * note of the nonce, so that we won't re-send an
			 * identical request. */
			if (entry->cm_scep_nonce != NULL) {
				entry->cm_scep_last_nonce = talloc_strdup(entry, entry->cm_scep_nonce);
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

	case CM_NEED_SCEP_DATA:
		state->cm_scepgen_state = cm_scepgen_start(ca, entry);
		if (state->cm_scepgen_state != NULL) {
			/* Note that we're in the process of generating SCEP
			 * data. */
			entry->cm_state = CM_GENERATING_SCEP_DATA;
			/* Wait for status update, or poll. */
			*readfd = cm_scepgen_get_fd(state->cm_scepgen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start generating data; take a breather and
			 * try again. */
			*when = cm_time_soonish;
		}
		break;

	case CM_GENERATING_SCEP_DATA:
		if (cm_scepgen_ready(state->cm_scepgen_state) == 0) {
			if (cm_scepgen_save_scep(state->cm_scepgen_state) == 0) {
				/* Saved SCEP data; move on. */
				cm_scepgen_done(state->cm_scepgen_state);
				state->cm_scepgen_state = NULL;
				entry->cm_state = CM_HAVE_SCEP_DATA;
				*when = cm_time_now;
			} else
			if (cm_scepgen_need_token(state->cm_scepgen_state) == 0) {
				/* Need a token; wait for it. */
				cm_scepgen_done(state->cm_scepgen_state);
				state->cm_scepgen_state = NULL;
				entry->cm_state = CM_NEED_SCEP_GEN_TOKEN;
				*when = cm_time_now;
			} else
			if (cm_scepgen_need_pin(state->cm_scepgen_state) == 0) {
				/* Need a PIN; wait for it. */
				cm_scepgen_done(state->cm_scepgen_state);
				state->cm_scepgen_state = NULL;
				entry->cm_state = CM_NEED_SCEP_GEN_PIN;
				*when = cm_time_now;
			} else
			if (cm_scepgen_need_encryption_certs(state->cm_scepgen_state) == 0) {
				/* Need the RA's encryption cert; wait for it. */
				cm_scepgen_done(state->cm_scepgen_state);
				state->cm_scepgen_state = NULL;
				entry->cm_state = CM_NEED_SCEP_ENCRYPTION_CERT;
				*when = cm_time_now;
			} else
			if (cm_scepgen_need_different_key_type(state->cm_scepgen_state) == 0) {
				/* Need an RSA key. */
				cm_scepgen_done(state->cm_scepgen_state);
				state->cm_scepgen_state = NULL;
				entry->cm_state = CM_NEED_SCEP_RSA_CLIENT_KEY;
				*when = cm_time_now;
			} else {
				/* Failed to save SCEP data; try again. */
				cm_scepgen_done(state->cm_scepgen_state);
				state->cm_scepgen_state = NULL;
				entry->cm_state = CM_NEED_SCEP_DATA;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_scepgen_get_fd(state->cm_scepgen_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_SCEP_GEN_TOKEN:
		*when = cm_time_no_time;
		break;

	case CM_NEED_SCEP_GEN_PIN:
		*when = cm_time_no_time;
		break;

	case CM_NEED_SCEP_ENCRYPTION_CERT:
		*when = cm_time_no_time;
		break;

	case CM_NEED_SCEP_RSA_CLIENT_KEY:
		*when = cm_time_no_time;
		break;

	case CM_HAVE_SCEP_DATA:
		entry->cm_state = CM_NEED_TO_SUBMIT;
		*when = cm_time_now;
		break;

	case CM_SUBMITTING:
		if (cm_submit_ready(state->cm_submit_state) == 0) {
			entry->cm_submitted = cm_time(NULL);
			if (cm_submit_issued(state->cm_submit_state) == 0) {
				/* We're all done.  Save the certificate to its
				 * real home. */
				cm_submit_clear_ca_cookie(state->cm_submit_state);
				cm_submit_done(state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_NEED_TO_SAVE_CERT;
				*when = cm_time_now;
			} else
			if (cm_submit_rejected(state->cm_submit_state) == 0) {
				/* The request was flat-out rejected. */
				cm_submit_clear_ca_cookie(state->cm_submit_state);
				cm_submit_done(state->cm_submit_state);
				state->cm_submit_state = NULL;
				if (entry->cm_cert != NULL) {
					cm_log(3, "%s('%s') already had a "
					       "certificate, going back to "
					       "monitoring it\n",
					       entry->cm_busname,
					       entry->cm_nickname);
					entry->cm_state = CM_MONITORING;
					*when = cm_time_soonish;
				} else {
					entry->cm_state = CM_NEED_TO_NOTIFY_REJECTION;
					*when = cm_time_now;
				}
			} else
			if (cm_submit_unreachable(state->cm_submit_state) == 0) {
				/* Let's try again later.  The cookie is left
				 * unmodified. */
				*delay = cm_submit_specified_delay(state->cm_submit_state);
				cm_submit_done(state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_CA_UNREACHABLE;
				*when = cm_time_delay;
				if (*delay < 0) {
					*delay = cm_decide_ca_delay(remaining);
				}
			} else
			if (cm_submit_save_ca_cookie(state->cm_submit_state) == 0) {
				/* Saved CA's identifier for our request; give
				 * it the specified time, or a little time, and
				 * then ask for a progress update. */
				cm_log(4, "%s('%s') provided CA "
				       "cookie \"%s\"\n", entry->cm_busname,
				       entry->cm_nickname, entry->cm_ca_cookie);
				*delay = cm_submit_specified_delay(state->cm_submit_state);
				cm_submit_done(state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_CA_WORKING;
				*when = cm_time_delay;
				if (*delay < 0) {
					*delay = cm_decide_ca_delay(remaining);
				}
			} else
			if (cm_submit_unconfigured(state->cm_submit_state) == 0) {
				/* Saved CA's identifier for our request; give
				 * it a little time and then ask. */
				*delay = cm_submit_specified_delay(state->cm_submit_state);
				cm_submit_done(state->cm_submit_state);
				state->cm_submit_state = NULL;
				if (entry->cm_cert != NULL) {
					cm_log(3, "%s('%s') already had a "
					       "certificate, going back to "
					       "monitoring it\n",
					       entry->cm_busname,
					       entry->cm_nickname);
					entry->cm_state = CM_MONITORING;
					*when = cm_time_soonish;
				} else {
					entry->cm_state = CM_CA_UNCONFIGURED;
					*when = cm_time_delay;
					if (*delay < 0) {
						*delay = cm_decide_ca_delay(remaining);
					}
				}
			} else
			if (cm_submit_need_scep_messages(state->cm_submit_state) == 0) {
				/* We need to generate SCEP data. */
				cm_submit_done(state->cm_submit_state);
				state->cm_submit_state = NULL;
				cm_log(3, "%s('%s') goes to a CA over SCEP, "
				       "need to generate SCEP data.\n",
				       entry->cm_busname, entry->cm_nickname);
				entry->cm_state = CM_NEED_SCEP_DATA;
				*when = cm_time_now;
			} else {
				/* Don't know what's going on. HELP! */
				cm_log(1,
				       "Unable to determine course of action "
				       "for %s('%s').\n",
				       entry->cm_busname,
				       entry->cm_nickname);
				cm_submit_done(state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_NEED_GUIDANCE;
				*when = cm_time_now;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_submit_get_fd(state->cm_submit_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_TO_SAVE_CERT:
		if (!cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		state->cm_hook_state = cm_hook_start_presave(entry,
							     context,
							     get_ca_by_index,
							     get_n_cas,
							     get_entry_by_index,
							     get_n_entries);
		if (state->cm_hook_state != NULL) {
			/* Note that we're doing the pre-save. */
			entry->cm_state = CM_PRE_SAVE_CERT;
			/* Wait for status update, or poll. */
			*readfd = cm_hook_get_fd(state->cm_hook_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start the pre-save, or nothing to do; skip
			 * it. */
			entry->cm_state = CM_START_SAVING_CERT;
			*when = cm_time_now;
		}
		break;

	case CM_PRE_SAVE_CERT:
		if (cm_hook_ready(state->cm_hook_state) == 0) {
			cm_hook_done(state->cm_hook_state);
			state->cm_hook_state = NULL;
			entry->cm_state = CM_START_SAVING_CERT;
			*when = cm_time_now;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_hook_get_fd(state->cm_hook_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_START_SAVING_CERT:
		state->cm_certsave_state = cm_certsave_start(entry);
		if (state->cm_certsave_state != NULL) {
			/* Note that we're saving the cert. */
			entry->cm_state = CM_SAVING_CERT;
			/* Wait for status update, or poll. */
			*readfd = cm_certsave_get_fd(state->cm_certsave_state);
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
		if (cm_certsave_ready(state->cm_certsave_state) == 0) {
			if (cm_certsave_saved(state->cm_certsave_state) == 0) {
				/* Saved certificate. */
				cm_certsave_done(state->cm_certsave_state);
				state->cm_certsave_state = NULL;
				entry->cm_state = CM_SAVED_CERT;
				*when = cm_time_now;
			} else
			if (cm_certsave_permissions_error(state->cm_certsave_state) == 0) {
				/* Whoops, we need help. */
				cm_certsave_done(state->cm_certsave_state);
				state->cm_certsave_state = NULL;
				entry->cm_state = CM_NEED_CERTSAVE_PERMS;
				*when = cm_time_now;
			} else
			if (cm_certsave_token_error(state->cm_certsave_state) == 0) {
				/* Whoops, we need help. */
				cm_certsave_done(state->cm_certsave_state);
				state->cm_certsave_state = NULL;
				entry->cm_state = CM_NEED_CERTSAVE_TOKEN;
				*when = cm_time_now;
			} else
			if (cm_certsave_pin_error(state->cm_certsave_state) == 0) {
				/* Whoops, we need help. */
				cm_certsave_done(state->cm_certsave_state);
				state->cm_certsave_state = NULL;
				entry->cm_state = CM_NEED_CERTSAVE_PIN;
				*when = cm_time_now;
			} else {
				/* Failed to save cert; make a note and try
				 * again in a bit. */
				cm_certsave_done(state->cm_certsave_state);
				state->cm_certsave_state = NULL;
				entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_certsave_get_fd(state->cm_certsave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_CERTSAVE_PERMS:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEED_CERTSAVE_TOKEN:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEED_CERTSAVE_PIN:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEED_TO_READ_CERT:
		/* We should already have the lock here.  In cases where we're
		 * resuming things at startup, try to acquire it if we don't
		 * have it. */
		if (!cm_writing_has_lock(entry, cm_ca_phase_invalid) && !cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		state->cm_certread_state = cm_certread_start(entry);
		if (state->cm_certread_state != NULL) {
			/* Note that we're reading the cert. */
			entry->cm_state = CM_READING_CERT;
			/* Wait for status update, or poll. */
			*readfd = cm_certread_get_fd(state->cm_certread_state);
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
		if (cm_certread_ready(state->cm_certread_state) == 0) {
			/* Finished reloading certificate. */
			cm_certread_done(state->cm_certread_state);
			state->cm_certread_state = NULL;
			if (emit_entry_saved_cert != NULL) {
				(*emit_entry_saved_cert)(context, entry);
			}
			/* Start the post-save hoook, if there is one. */
			state->cm_hook_state = cm_hook_start_postsave(entry,
								      context,
								      get_ca_by_index,
								      get_n_cas,
								      get_entry_by_index,
								      get_n_entries);
			if (state->cm_hook_state != NULL) {
				/* Note that we're doing the post-save. */
				entry->cm_state = CM_POST_SAVED_CERT;
				/* Wait for status update, or poll. */
				*readfd = cm_hook_get_fd(state->cm_hook_state);
				if (*readfd == -1) {
					*when = cm_time_soon;
				} else {
					*when = cm_time_no_time;
				}
			} else {
				/* Failed to start the post-save, or nothing to do;
				 * skip it. */
				entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_SAVED;
				*when = cm_time_now;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_certread_get_fd(state->cm_certread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_POST_SAVED_CERT:
		if (cm_hook_ready(state->cm_hook_state) == 0) {
			cm_hook_done(state->cm_hook_state);
			state->cm_hook_state = NULL;
			entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_SAVED;
			*when = cm_time_now;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_hook_get_fd(state->cm_hook_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_SAVED_CERT:
		entry->cm_state = CM_NEED_TO_SAVE_CA_CERTS;
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
		*when = cm_time_soonish;
		break;

	case CM_CA_UNCONFIGURED:
		*when = cm_time_no_time;
		break;

	case CM_NEED_GUIDANCE:
		*when = cm_time_no_time;
		break;

	case CM_NEED_CA:
		*when = cm_time_no_time;
		break;

	case CM_MONITORING:
		if (entry->cm_monitor &&
		    (cm_check_expiration_is_noteworthy(entry,
						       &cm_prefs_notify_ttls,
						       &entry->cm_last_need_notify_check) == 0)) {
			/* Kick off a notification. */
			entry->cm_state = CM_NEED_TO_NOTIFY_VALIDITY;
			*when = cm_time_now;
		} else
		if (entry->cm_autorenew &&
		    (cm_check_expiration_is_noteworthy(entry,
						       &cm_prefs_enroll_ttls,
						       &entry->cm_last_need_enroll_check) == 0)) {
			/* Kick off an enrollment attempt.  We need to go all
			 * the way back to generating the CSR because the user
			 * may have asked us to request with parameters that
			 * have changed since we last generated a CSR. */
			entry->cm_state = CM_NEED_CSR;
			*when = cm_time_now;
		} else {
			/* Nothing to do here.  Check again at an appropriate time. */
			*when = cm_time_delay;
			*delay = cm_decide_monitor_delay(remaining);
		}
		break;

	case CM_NEED_TO_NOTIFY_VALIDITY:
		state->cm_notify_state = cm_notify_start(entry,
							 cm_notify_event_validity_ending);
		if (state->cm_notify_state != NULL) {
			entry->cm_state = CM_NOTIFYING_VALIDITY;
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
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

	case CM_NOTIFYING_VALIDITY:
		if (cm_notify_ready(state->cm_notify_state) == 0) {
			cm_notify_done(state->cm_notify_state);
			state->cm_notify_state = NULL;
			if (entry->cm_autorenew &&
			    (cm_check_expiration_is_noteworthy(entry,
							       &cm_prefs_enroll_ttls,
							       &entry->cm_last_need_enroll_check) == 0)) {
				/* Kick off an enrollment attempt.  We need to go all
				 * the way back to generating the CSR because the user
				 * may have asked us to request with parameters that
				 * have changed since we last generated a CSR. */
				entry->cm_state = CM_NEED_CSR;
				*when = cm_time_now;
			} else {
				entry->cm_state = CM_MONITORING;
				*when = cm_time_delay;
				*delay = cm_decide_monitor_delay(-1);
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_TO_NOTIFY_REJECTION:
		state->cm_notify_state = cm_notify_start(entry,
							 cm_notify_event_rejected);
		if (state->cm_notify_state != NULL) {
			entry->cm_state = CM_NOTIFYING_REJECTION;
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
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

	case CM_NOTIFYING_REJECTION:
		if (cm_notify_ready(state->cm_notify_state) == 0) {
			cm_notify_done(state->cm_notify_state);
			state->cm_notify_state = NULL;
			entry->cm_state = CM_CA_REJECTED;
			*when = cm_time_soon;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED:
		/* We should already have the lock here.  In cases where we're
		 * resuming things at startup, try to acquire it if we don't
		 * have it. */
		if (!cm_writing_has_lock(entry, cm_ca_phase_invalid) && !cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		if (!cm_writing_unlock_by_entry(entry)) {
			/* If for some reason we fail to release the lock that
			 * we have, try to release it again soon. */
			*when = cm_time_soon;
			cm_log(1, "%s('%s') failed to release saving "
			       "lock, probably a bug\n",
			       entry->cm_busname, entry->cm_nickname);
			break;
		}
		state->cm_notify_state = cm_notify_start(entry,
							 cm_notify_event_issued_not_saved);
		if (state->cm_notify_state != NULL) {
			entry->cm_state = CM_NOTIFYING_ISSUED_SAVE_FAILED;
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
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

	case CM_NOTIFYING_ISSUED_SAVE_FAILED:
		if (cm_notify_ready(state->cm_notify_state) == 0) {
			cm_notify_done(state->cm_notify_state);
			state->cm_notify_state = NULL;
			entry->cm_state = CM_START_SAVING_CERT;
			*when = cm_time_soonish;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_TO_SAVE_CA_CERTS:
		/* We should already have the lock here.  In cases where we're
		 * resuming things at startup, try to acquire it if we don't
		 * have it. */
		if (!cm_writing_has_lock(entry, cm_ca_phase_invalid) && !cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		entry->cm_state = CM_START_SAVING_CA_CERTS;
		*when = cm_time_now;
		break;

	case CM_START_SAVING_CA_CERTS:
		state->cm_casave_state = cm_casave_start(entry, NULL, context,
							 get_ca_by_index,
							 get_n_cas,
							 get_entry_by_index,
							 get_n_entries);
		if (state->cm_casave_state != NULL) {
			entry->cm_state = CM_SAVING_CA_CERTS;
			/* Wait for status update, or poll. */
			*readfd = cm_casave_get_fd(state->cm_casave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start saving CA certs; try again. */
			*when = cm_time_soonish;
		}
		break;

	case CM_SAVING_CA_CERTS:
		if (cm_casave_ready(state->cm_casave_state) == 0) {
			if (cm_casave_saved(state->cm_casave_state) == 0) {
				/* Saved CA certificates, no go re-read the
				 * issued certificate. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				entry->cm_state = CM_NEED_TO_READ_CERT;
				*when = cm_time_now;
			} else
			if (cm_casave_permissions_error(state->cm_casave_state) == 0) {
				/* Whoops, we need help. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				entry->cm_state = CM_NEED_CA_CERT_SAVE_PERMS;
				*when = cm_time_now;
			} else {
				/* Failed to save CA certs. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				entry->cm_state = CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_casave_get_fd(state->cm_casave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_CA_CERT_SAVE_PERMS:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEED_TO_NOTIFY_ISSUED_SAVED:
		/* We should already have the lock here.  In cases where we're
		 * resuming things at startup, try to acquire it if we don't
		 * have it. */
		if (!cm_writing_has_lock(entry, cm_ca_phase_invalid) && !cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		if (!cm_writing_unlock_by_entry(entry)) {
			/* If for some reason we fail to release the lock that
			 * we have, try to release it again soon. */
			*when = cm_time_soon;
			cm_log(1, "%s('%s') failed to release saving "
			       "lock, probably a bug\n",
			       entry->cm_busname, entry->cm_nickname);
			break;
		}
		state->cm_notify_state = cm_notify_start(entry,
							 cm_notify_event_issued_and_saved);
		if (state->cm_notify_state != NULL) {
			entry->cm_state = CM_NOTIFYING_ISSUED_SAVED;
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
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

	case CM_NOTIFYING_ISSUED_SAVED:
		if (cm_notify_ready(state->cm_notify_state) == 0) {
			cm_notify_done(state->cm_notify_state);
			state->cm_notify_state = NULL;
			entry->cm_state = CM_MONITORING;
			*when = cm_time_soon;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED:
		/* We should already have the lock here.  In cases where we're
		 * resuming things at startup, try to acquire it if we don't
		 * have it. */
		if (!cm_writing_has_lock(entry, cm_ca_phase_invalid) && !cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		if (!cm_writing_unlock_by_entry(entry)) {
			/* If for some reason we fail to release the lock that
			 * we have, try to release it again soon. */
			*when = cm_time_soon;
			cm_log(1, "%s('%s') failed to release saving "
			       "lock, probably a bug\n",
			       entry->cm_busname, entry->cm_nickname);
			break;
		}
		state->cm_notify_state = cm_notify_start(entry,
							 cm_notify_event_issued_ca_not_saved);
		if (state->cm_notify_state != NULL) {
			entry->cm_state = CM_NOTIFYING_ISSUED_CA_SAVE_FAILED;
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
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

	case CM_NOTIFYING_ISSUED_CA_SAVE_FAILED:
		if (cm_notify_ready(state->cm_notify_state) == 0) {
			cm_notify_done(state->cm_notify_state);
			state->cm_notify_state = NULL;
			entry->cm_state = CM_NEED_TO_SAVE_CA_CERTS;
			*when = cm_time_soonish;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_TO_SAVE_ONLY_CA_CERTS:
		if (!cm_writing_has_lock(entry, cm_ca_phase_invalid) && !cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		entry->cm_state = CM_START_SAVING_ONLY_CA_CERTS;
		*when = cm_time_now;
		break;

	case CM_START_SAVING_ONLY_CA_CERTS:
		state->cm_casave_state = cm_casave_start(entry, NULL, context,
							 get_ca_by_index,
							 get_n_cas,
							 get_entry_by_index,
							 get_n_entries);
		if (state->cm_casave_state != NULL) {
			entry->cm_state = CM_SAVING_ONLY_CA_CERTS;
			/* Wait for status update, or poll. */
			*readfd = cm_casave_get_fd(state->cm_casave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start saving CA certs; try again. */
			*when = cm_time_soonish;
		}
		break;

	case CM_SAVING_ONLY_CA_CERTS:
		if (cm_casave_ready(state->cm_casave_state) == 0) {
			if (cm_casave_saved(state->cm_casave_state) == 0) {
				if (!cm_writing_unlock_by_entry(entry)) {
					/* If for some reason we fail to release the lock that
					 * we have, try to release it again soon. */
					*when = cm_time_soon;
					cm_log(1, "%s('%s') failed to release saving "
					       "lock, probably a bug\n",
					       entry->cm_busname, entry->cm_nickname);
					break;
				}
				/* Saved certificates. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				entry->cm_state = CM_MONITORING;
				*when = cm_time_now;
			} else
			if (cm_casave_permissions_error(state->cm_casave_state) == 0) {
				if (!cm_writing_unlock_by_entry(entry)) {
					/* If for some reason we fail to release the lock that
					 * we have, try to release it again soon. */
					*when = cm_time_soon;
					cm_log(1, "%s('%s') failed to release saving "
					       "lock, probably a bug\n",
					       entry->cm_busname, entry->cm_nickname);
					break;
				}
				/* Whoops, we need help. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				entry->cm_state = CM_NEED_ONLY_CA_CERT_SAVE_PERMS;
				*when = cm_time_now;
			} else {
				/* Failed to save certs. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				entry->cm_state = CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_casave_get_fd(state->cm_casave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEED_ONLY_CA_CERT_SAVE_PERMS:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED:
		/* We should already have the lock here.  In cases where we're
		 * resuming things at startup, try to acquire it if we don't
		 * have it. */
		if (!cm_writing_has_lock(entry, cm_ca_phase_invalid) && !cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for saving lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		if (!cm_writing_unlock_by_entry(entry)) {
			/* If for some reason we fail to release the lock that
			 * we have, try to release it again soon. */
			*when = cm_time_soon;
			cm_log(1, "%s('%s') failed to release saving "
			       "lock, probably a bug\n",
			       entry->cm_busname, entry->cm_nickname);
			break;
		}
		state->cm_notify_state = cm_notify_start(entry,
							 cm_notify_event_ca_not_saved);
		if (state->cm_notify_state != NULL) {
			entry->cm_state = CM_NOTIFYING_ONLY_CA_SAVE_FAILED;
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
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

	case CM_NOTIFYING_ONLY_CA_SAVE_FAILED:
		if (cm_notify_ready(state->cm_notify_state) == 0) {
			cm_notify_done(state->cm_notify_state);
			state->cm_notify_state = NULL;
			entry->cm_state = CM_MONITORING;
			*when = cm_time_soonish;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_notify_get_fd(state->cm_notify_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEWLY_ADDED:
		/* Take the lock here because the database is opened read-write
		 * in case we need to set a password on it. */
		if (!cm_writing_lock_by_entry(entry)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another entry. */
			cm_log(3, "%s('%s') waiting for reading lock\n",
			       entry->cm_busname, entry->cm_nickname);
			*when = cm_time_soon;
			break;
		}
		/* We need to do some recon, and then decide what we need to
		 * do to make things the way the user has specified that they
		 * should be. */
		if (entry->cm_key_storage_type != cm_key_storage_none) {
			entry->cm_state = CM_NEWLY_ADDED_START_READING_KEYINFO;
			*when = cm_time_now;
		} else {
			entry->cm_state = CM_NEWLY_ADDED_START_READING_CERT;
			*when = cm_time_now;
		}
		break;

	case CM_NEWLY_ADDED_START_READING_KEYINFO:
		/* Try to read information about the key. */
		state->cm_keyiread_state = cm_keyiread_start(entry);
		if (state->cm_keyiread_state != NULL) {
			entry->cm_state = CM_NEWLY_ADDED_READING_KEYINFO;
			/* Note that we're reading information about
			 * the key. */
			*readfd = cm_keyiread_get_fd(state->cm_keyiread_state);
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

	case CM_NEWLY_ADDED_READING_KEYINFO:
		/* If we finished reading info about the key, move on to try
		 * and read the certificate. */
		if (cm_keyiread_ready(state->cm_keyiread_state) == 0) {
			if (cm_keyiread_finished_reading(state->cm_keyiread_state) == 0) {
				entry->cm_state = CM_NEWLY_ADDED_START_READING_CERT;
				*when = cm_time_now;
			} else
			if (cm_keyiread_need_token(state->cm_keyiread_state) == 0) {
				if (!cm_writing_unlock_by_entry(entry)) {
					/* If for some reason we fail to
					 * release the lock that we have, try
					 * to release it again soon. */
					*when = cm_time_soon;
					cm_log(1, "%s('%s') failed to release "
					       "reading lock, probably a bug\n",
					       entry->cm_busname,
					       entry->cm_nickname);
					break;
				}
				/* If we need the token, just hang on. */
				entry->cm_state = CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN;
				*when = cm_time_now;
			} else
			if (cm_keyiread_need_pin(state->cm_keyiread_state) == 0) {
				if (!cm_writing_unlock_by_entry(entry)) {
					/* If for some reason we fail to
					 * release the lock that we have, try
					 * to release it again soon. */
					*when = cm_time_soon;
					cm_log(1, "%s('%s') failed to release "
					       "reading lock, probably a bug\n",
					       entry->cm_busname,
					       entry->cm_nickname);
					break;
				}
				/* If we need the PIN, just hang on. */
				entry->cm_state = CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN;
				*when = cm_time_now;
			} else {
				/* Otherwise try to move on. */
				entry->cm_state = CM_NEWLY_ADDED_START_READING_CERT;
				*when = cm_time_now;
			}
			cm_keyiread_done(state->cm_keyiread_state);
			state->cm_keyiread_state = NULL;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_keyiread_get_fd(state->cm_keyiread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN:
		/* Revisit this later. */
		*when = cm_time_no_time;
		break;

	case CM_NEWLY_ADDED_START_READING_CERT:
		/* Try to read the certificate. */
		state->cm_certread_state = cm_certread_start(entry);
		if (state->cm_certread_state != NULL) {
			entry->cm_state = CM_NEWLY_ADDED_READING_CERT;
			/* Note that we're reading information about
			 * the certificate. */
			*readfd = cm_certread_get_fd(state->cm_certread_state);
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
		if (cm_certread_ready(state->cm_certread_state) == 0) {
			cm_certread_done(state->cm_certread_state);
			state->cm_certread_state = NULL;
			entry->cm_state = CM_NEWLY_ADDED_DECIDING;
			*when = cm_time_now;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_certread_get_fd(state->cm_certread_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;

	case CM_NEWLY_ADDED_DECIDING:
		if (!cm_writing_unlock_by_entry(entry)) {
			/* If for some reason we fail to release the lock that
			 * we have, try to release it again soon. */
			*when = cm_time_soon;
			cm_log(1, "%s('%s') failed to release reading lock, "
			       "probably a bug\n",
			       entry->cm_busname, entry->cm_nickname);
			break;
		}
		/* Decide what to do next.  Assign a CA if it doesn't have one
		 * assigned to it already. */
		if ((entry->cm_ca_nickname == NULL) &&
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
						entry->cm_ca_nickname = talloc_strdup(entry, tmp_ca->cm_nickname);
					}
				}
			}
		}
		/* No match -> assign the default. */
		if (entry->cm_ca_nickname == NULL) {
			for (i = 0; i < (*get_n_cas)(context); i++) {
				tmp_ca = (*get_ca_by_index)(context, i);
				if (tmp_ca->cm_ca_is_default) {
					entry->cm_ca_nickname = talloc_strdup(entry, tmp_ca->cm_nickname);
				}
			}
		}
		/* No default in our data store -> use the config file's. */
		if (entry->cm_ca_nickname == NULL) {
			tmp_ca_name = cm_prefs_default_ca();
			if (tmp_ca_name != NULL) {
				entry->cm_ca_nickname = talloc_strdup(entry,
								      tmp_ca_name);
			}
		}
		/* If we have a certificate in the expected location, we go
		 * straight to monitoring it.  If we didn't get any explicit
		 * requests for names, SAN, KU and EKU values, then try to pull
		 * them from the certificate, too. */
		if (entry->cm_cert != NULL) {
			cm_store_set_if_not_set_s(entry,
						  &entry->cm_template_subject_der,
						  entry->cm_cert_subject_der);
			cm_store_set_if_not_set_s(entry,
						  &entry->cm_template_subject,
						  entry->cm_cert_subject);
			cm_store_set_if_not_set_as(entry,
						   &entry->cm_template_hostname,
						   entry->cm_cert_hostname);
			cm_store_set_if_not_set_as(entry,
						   &entry->cm_template_email,
						   entry->cm_cert_email);
			cm_store_set_if_not_set_as(entry,
						   &entry->cm_template_principal,
						   entry->cm_cert_principal);
			cm_store_set_if_not_set_as(entry,
						   &entry->cm_template_ipaddress,
						   entry->cm_cert_ipaddress);
			cm_store_set_if_not_set_s(entry,
						  &entry->cm_template_ku,
						  entry->cm_cert_ku);
			cm_store_set_if_not_set_s(entry,
						  &entry->cm_template_eku,
						  entry->cm_cert_eku);
			cm_store_set_if_not_set_s(entry,
						  &entry->cm_template_ns_comment,
						  entry->cm_cert_ns_comment);
			cm_store_set_if_not_set_s(entry,
						  &entry->cm_template_profile,
						  entry->cm_cert_profile);
			/* Walk the list of known names of known CAs and try to
			 * find the entry's CA. */
			tmp_ca = NULL;
			for (i = 0; i < (*get_n_cas)(context); i++) {
				tmp_ca = (*get_ca_by_index)(context, i);
				if ((tmp_ca->cm_nickname != NULL) &&
				    (entry->cm_ca_nickname != NULL) &&
				    (strcmp(entry->cm_ca_nickname,
					    tmp_ca->cm_nickname) == 0)) {
					break;
				}
				tmp_ca = NULL;
			}
			/* If there's an associated CA, and we know of
			 * certificates for it, and we need them to be stored
			 * somewhere, we need to make sure they'll show up in
			 * the expected locations. */
			if ((tmp_ca != NULL) &&
			    (((tmp_ca->cm_ca_root_certs != NULL) &&
			      ((entry->cm_root_cert_store_files != NULL) ||
			       (entry->cm_root_cert_store_nssdbs != NULL))) ||
			     ((tmp_ca->cm_ca_other_root_certs != NULL) &&
			      ((entry->cm_other_root_cert_store_files != NULL) ||
			       (entry->cm_other_root_cert_store_nssdbs != NULL))) ||
			     ((tmp_ca->cm_ca_other_certs != NULL) &&
			      ((entry->cm_other_cert_store_files != NULL) ||
			       (entry->cm_other_cert_store_nssdbs != NULL))))) {
				cm_log(3, "%s('%s') already had a "
				       "certificate, making sure CA "
				       "certificates will be there\n",
				       entry->cm_busname,
				       entry->cm_nickname);
				entry->cm_state = CM_NEED_TO_SAVE_ONLY_CA_CERTS;
			} else {
				cm_log(3, "%s('%s') has a certificate, "
				       "monitoring it\n",
				       entry->cm_busname,
				       entry->cm_nickname);
				entry->cm_state = CM_MONITORING;
			}
			*when = cm_time_now;
		} else
		/* If we don't have a certificate, but we know where the key
		 * should be, we have some options. */
		if (entry->cm_key_storage_type != cm_key_storage_none) {
			/* If we don't have a certificate, but we have a key,
			 * the next step is to generate a CSR. */
			if (entry->cm_key_type.cm_key_size > 0) {
				cm_log(3, "%s('%s') has no certificate, will "
				       "attempt enrollment using "
				       "already-present key\n",
				       entry->cm_busname, entry->cm_nickname);
				entry->cm_state = CM_NEED_CSR;
				*when = cm_time_now;
			} else {
				/* No certificate, no key, start with
				 * generating the key. */
				cm_log(3, "%s('%s') has no key or certificate, "
				       "will generate keys and attempt "
				       "enrollment\n",
				       entry->cm_busname, entry->cm_nickname);
				entry->cm_state = CM_NEED_KEY_PAIR;
				*when = cm_time_now;
			}
		} else {
			/* And if we don't have a place for the key, we're
			 * screwed.  Hopefully this didn't happen normally. */
			cm_log(3, "%s('%s') has no key or certificate location,"
			       " don't know what to do about that\n",
			       entry->cm_busname, entry->cm_nickname);
			entry->cm_state = CM_NEED_GUIDANCE;
			*when = cm_time_now;
		}
		break;

	case CM_INVALID:
		/* not reached */
		abort();
		break;
	}
	if (old_entry->cm_state != entry->cm_state) {
		cm_log(3, "%s('%s') moved to state '%s'\n",
		       entry->cm_busname,
		       entry->cm_nickname ?
		       entry->cm_nickname : "(unnamed entry)",
		       cm_store_state_as_string(entry->cm_state));
		cm_store_entry_save(entry);
	}
	if (emit_entry_changes != NULL) {
		(*emit_entry_changes)(context, old_entry, entry);
	}
	talloc_free(old_entry);
	return 0;
}

/* Cancel and clean up any in-progress work and then free the working state. */
int
cm_iterate_entry_done(struct cm_store_entry *entry, void *cm_iterate_state)
{
	struct cm_entry_state *state;

	state = cm_iterate_state;
	if (state != NULL) {
		if (state->cm_submit_state != NULL) {
			cm_submit_done(state->cm_submit_state);
			state->cm_submit_state = NULL;
		}
		if (state->cm_csrgen_state != NULL) {
			cm_csrgen_done(state->cm_csrgen_state);
			state->cm_csrgen_state = NULL;
		}
		if (state->cm_scepgen_state != NULL) {
			cm_scepgen_done(state->cm_scepgen_state);
			state->cm_scepgen_state = NULL;
		}
		if (state->cm_keyiread_state != NULL) {
			cm_keyiread_done(state->cm_keyiread_state);
			state->cm_keyiread_state = NULL;
		}
		if (state->cm_keygen_state != NULL) {
			cm_keygen_done(state->cm_keygen_state);
			state->cm_keygen_state = NULL;
		}
		if (state->cm_notify_state != NULL) {
			cm_notify_done(state->cm_notify_state);
			state->cm_notify_state = NULL;
		}
		if (state->cm_casave_state != NULL) {
			cm_casave_done(state->cm_casave_state);
			state->cm_casave_state = NULL;
		}
		talloc_free(state);
	}
	cm_entry_reset_state(entry);
	cm_log(3, "%s('%s') ends in state '%s'\n",
	       entry->cm_busname, entry->cm_nickname,
	       cm_store_state_as_string(entry->cm_state));
	if (cm_writing_has_lock(entry, cm_ca_phase_invalid)) {
		cm_writing_unlock_by_entry(entry);
	}
	return 0;
}

/* Set up run-time data associated with the CA. */
int
cm_iterate_ca_init(struct cm_store_ca *ca, enum cm_ca_phase phase,
		   void **cm_iterate_state)
{
	struct cm_ca_state *state;

	state = talloc_ptrtype(ca, state);
	if (state == NULL) {
		return ENOMEM;
	}
	memset(state, 0, sizeof(*state));

	state->cm_phase = phase;
	ca->cm_ca_state[phase] = CM_CA_NEED_TO_REFRESH;
	*cm_iterate_state = state;

	if (cm_writing_has_lock(ca, phase)) {
		cm_writing_unlock_by_ca(ca, phase);
	}

	cm_store_ca_save(ca);

	cm_log(3, "%s('%s').%s starts (%s)\n",
	       ca->cm_busname, ca->cm_nickname,
	       cm_store_ca_phase_as_string(state->cm_phase),
	       cm_store_ca_state_as_string(ca->cm_ca_state[phase]));
	return 0;
}

int
cm_iterate_ca(struct cm_store_ca *ca,
	      struct cm_context *context,
	      struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
	      int (*get_n_cas)(struct cm_context *),
	      struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
	      int (*get_n_entries)(struct cm_context *),
	      void (*emit_ca_changes)(struct cm_context *,
				      struct cm_store_ca *,
				      struct cm_store_ca *),
	      void *cm_iterate_state,
	      enum cm_time *when,
	      int *delay,
	      int *readfd)
{
	struct cm_store_ca *old_ca;
	struct cm_ca_state *state = cm_iterate_state;

	*readfd = -1;
	old_ca = cm_store_ca_dup(ca, ca);

	switch (ca->cm_ca_state[state->cm_phase]) {
	case CM_CA_NEED_TO_REFRESH:
		switch (state->cm_phase) {
		case cm_ca_phase_identify:
			state->cm_task_state = cm_cadata_start_identify(ca);
			break;
		case cm_ca_phase_certs:
			state->cm_task_state = cm_cadata_start_certs(ca);
			break;
		case cm_ca_phase_profiles:
			state->cm_task_state = cm_cadata_start_profiles(ca);
			break;
		case cm_ca_phase_default_profile:
			state->cm_task_state =
				cm_cadata_start_default_profile(ca);
			break;
		case cm_ca_phase_enroll_reqs:
			state->cm_task_state = cm_cadata_start_enroll_reqs(ca);
			break;
		case cm_ca_phase_renew_reqs:
			state->cm_task_state = cm_cadata_start_renew_reqs(ca);
			break;
		case cm_ca_phase_capabilities:
			state->cm_task_state = cm_cadata_start_capabilities(ca);
			break;
		case cm_ca_phase_encryption_certs:
			state->cm_task_state = cm_cadata_start_encryption_certs(ca);
			break;
		case cm_ca_phase_invalid:
			abort();
			break;
		}
		if (state->cm_task_state == NULL) {
			ca->cm_ca_state[state->cm_phase] = CM_CA_DISABLED;
			*when = cm_time_now;
		} else {
			ca->cm_ca_state[state->cm_phase] = CM_CA_REFRESHING;
			*readfd = cm_cadata_get_fd(state->cm_task_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_CA_REFRESHING:
		if (cm_cadata_ready(state->cm_task_state) == 0) {
			if (cm_cadata_modified(state->cm_task_state) == 0) {
				cm_log(3, "%s('%s').%s data updated\n",
				       ca->cm_busname, ca->cm_nickname,
				       cm_store_ca_phase_as_string(state->cm_phase));
				cm_cadata_done(state->cm_task_state);
				state->cm_task_state = NULL;
				switch (state->cm_phase) {
				case cm_ca_phase_certs:
					ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_SAVE_DATA;
					break;
				case cm_ca_phase_identify:
				case cm_ca_phase_profiles:
				case cm_ca_phase_default_profile:
				case cm_ca_phase_enroll_reqs:
				case cm_ca_phase_renew_reqs:
				case cm_ca_phase_capabilities:
					if (emit_ca_changes != NULL) {
						cm_restart_entries_by_ca(context,
									 ca->cm_nickname);
					}
					ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_ANALYZE;
					break;
				case cm_ca_phase_encryption_certs:
					if (emit_ca_changes != NULL) {
						cm_restart_entries_by_ca(context,
									 ca->cm_nickname);
					}
					ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_ANALYZE;
					break;
				case cm_ca_phase_invalid:
					abort();
					break;
				}
				*when = cm_time_now;
			} else
			if (cm_cadata_needs_retry(state->cm_task_state) == 0) {
				*when = cm_time_delay;
				*delay = cm_cadata_specified_delay(state->cm_task_state);
				if (*delay < 0) {
					*delay = cm_decide_cadata_delay();
				}
				cm_cadata_done(state->cm_task_state);
				state->cm_task_state = NULL;
				cm_log(3, "%s('%s').%s server needs retry\n",
				       ca->cm_busname, ca->cm_nickname,
				       cm_store_ca_phase_as_string(state->cm_phase));
				ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_REFRESH;
			} else
			if (cm_cadata_rejected(state->cm_task_state) == 0) {
				cm_cadata_done(state->cm_task_state);
				state->cm_task_state = NULL;
				cm_log(3, "%s('%s').%s server doesn't support that\n",
				       ca->cm_busname, ca->cm_nickname,
				       cm_store_ca_phase_as_string(state->cm_phase));
				ca->cm_ca_state[state->cm_phase] = CM_CA_IDLE;
				*when = cm_time_delay;
				*delay = CM_DELAY_CA_POLL_MAXIMUM;
			} else
			if (cm_cadata_unreachable(state->cm_task_state) == 0) {
				cm_cadata_done(state->cm_task_state);
				state->cm_task_state = NULL;
				cm_log(3, "%s('%s').%s server unreachable\n",
				       ca->cm_busname, ca->cm_nickname,
				       cm_store_ca_phase_as_string(state->cm_phase));
				ca->cm_ca_state[state->cm_phase] = CM_CA_DATA_UNREACHABLE;
				*when = cm_time_delay;
				*delay = cm_decide_cadata_delay();
			} else
			if (cm_cadata_unsupported(state->cm_task_state) == 0) {
				cm_cadata_done(state->cm_task_state);
				switch (state->cm_phase) {
				case cm_ca_phase_certs:
					ca->cm_ca_root_certs = NULL;
					ca->cm_ca_other_root_certs = NULL;
					ca->cm_ca_other_certs = NULL;
					break;
				case cm_ca_phase_identify:
					break;
				case cm_ca_phase_profiles:
					break;
				case cm_ca_phase_default_profile:
					break;
				case cm_ca_phase_enroll_reqs:
					break;
				case cm_ca_phase_renew_reqs:
					break;
				case cm_ca_phase_capabilities:
					ca->cm_ca_capabilities = NULL;
					break;
				case cm_ca_phase_encryption_certs:
					ca->cm_ca_encryption_cert = NULL;
					ca->cm_ca_encryption_issuer_cert = NULL;
					ca->cm_ca_encryption_cert_pool = NULL;
					break;
				case cm_ca_phase_invalid:
					abort();
					break;
				}
				state->cm_task_state = NULL;
				cm_log(3, "%s('%s').%s retrieval unsupported\n",
				       ca->cm_busname, ca->cm_nickname,
				       cm_store_ca_phase_as_string(state->cm_phase));
				ca->cm_ca_state[state->cm_phase] = CM_CA_DISABLED;
				*when = cm_time_now;
			} else
			if (cm_cadata_unconfigured(state->cm_task_state) == 0) {
				cm_cadata_done(state->cm_task_state);
				state->cm_task_state = NULL;
				cm_log(3, "%s('%s').%s missing configuration\n",
				       ca->cm_busname, ca->cm_nickname,
				       cm_store_ca_phase_as_string(state->cm_phase));
				ca->cm_ca_state[state->cm_phase] = CM_CA_DATA_UNREACHABLE;
				*when = cm_time_delay;
				*delay = cm_decide_cadata_delay();
			} else {
				cm_cadata_done(state->cm_task_state);
				state->cm_task_state = NULL;
				cm_log(3, "%s('%s').%s data is unchanged\n",
				       ca->cm_busname, ca->cm_nickname,
				       cm_store_ca_phase_as_string(state->cm_phase));
				ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_ANALYZE;
				*when = cm_time_now;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_cadata_get_fd(state->cm_task_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_CA_NEED_TO_SAVE_DATA:
		if (!cm_writing_lock_by_ca(ca, state->cm_phase)) {
			/* Just hang out in this state while we're messing
			 * around with the outside world for another CA. */
			cm_log(3, "%s('%s').%s waiting for saving lock\n",
			       ca->cm_busname, ca->cm_nickname,
			       cm_store_ca_phase_as_string(state->cm_phase));
			*when = cm_time_soon;
			break;
		}
		state->cm_hook_state = cm_hook_start_ca_presave(ca,
							        context,
							        get_ca_by_index,
							        get_n_cas,
							        get_entry_by_index,
							        get_n_entries);
		if (state->cm_hook_state != NULL) {
			/* Note that we're doing the pre-save. */
			ca->cm_ca_state[state->cm_phase] = CM_CA_PRE_SAVE_DATA;
			/* Wait for status update, or poll. */
			*readfd = cm_hook_get_fd(state->cm_hook_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start the pre-save; skip it. */
			ca->cm_ca_state[state->cm_phase] = CM_CA_START_SAVING_DATA;
			*when = cm_time_now;
		}
		break;
	case CM_CA_PRE_SAVE_DATA:
		if (cm_hook_ready(state->cm_hook_state) == 0) {
			cm_hook_done(state->cm_hook_state);
			state->cm_hook_state = NULL;
			ca->cm_ca_state[state->cm_phase] = CM_CA_START_SAVING_DATA;
			*when = cm_time_now;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_hook_get_fd(state->cm_hook_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_CA_START_SAVING_DATA:
		state->cm_casave_state = cm_casave_start(NULL, ca, context,
							 get_ca_by_index,
							 get_n_cas,
							 get_entry_by_index,
							 get_n_entries);
		if (state->cm_casave_state != NULL) {
			ca->cm_ca_state[state->cm_phase] = CM_CA_SAVING_DATA;
			/* Wait for status update, or poll. */
			*readfd = cm_casave_get_fd(state->cm_casave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_CA_SAVING_DATA:
		if (cm_casave_ready(state->cm_casave_state) == 0) {
			if (cm_casave_saved(state->cm_casave_state) == 0) {
				/* Saved certificates. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_POST_SAVE_DATA;
				*when = cm_time_now;
			} else
			if (cm_casave_permissions_error(state->cm_casave_state) == 0) {
				/* Whoops, we need help. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_POST_SAVE_DATA;
				*when = cm_time_now;
			} else {
				/* Failed to save certs. */
				cm_casave_done(state->cm_casave_state);
				state->cm_casave_state = NULL;
				ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_POST_SAVE_DATA;
				*when = cm_time_soonish;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_casave_get_fd(state->cm_casave_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_CA_NEED_POST_SAVE_DATA:
		state->cm_hook_state = cm_hook_start_ca_postsave(ca,
							         context,
							         get_ca_by_index,
							         get_n_cas,
							         get_entry_by_index,
							         get_n_entries);
		if (state->cm_hook_state != NULL) {
			/* Note that we're doing the post-save. */
			ca->cm_ca_state[state->cm_phase] = CM_CA_POST_SAVE_DATA;
			/* Wait for status update, or poll. */
			*readfd = cm_hook_get_fd(state->cm_hook_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start the post-save, or nothing to do;
			 * skip it. */
			ca->cm_ca_state[state->cm_phase] = CM_CA_SAVED_DATA;
			*when = cm_time_now;
		}
		break;
	case CM_CA_POST_SAVE_DATA:
		if (cm_hook_ready(state->cm_hook_state) == 0) {
			cm_hook_done(state->cm_hook_state);
			state->cm_hook_state = NULL;
			ca->cm_ca_state[state->cm_phase] = CM_CA_SAVED_DATA;
			*when = cm_time_now;
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_hook_get_fd(state->cm_hook_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_CA_SAVED_DATA:
		if (!cm_writing_unlock_by_ca(ca, state->cm_phase)) {
			/* If for some reason we fail to release the lock that
			 * we have, try to release it again soon. */
			*when = cm_time_soon;
			cm_log(1, "%s('%s').%s failed to release saving "
			       "lock, probably a bug\n",
			       ca->cm_busname, ca->cm_nickname,
			       cm_store_ca_phase_as_string(state->cm_phase));
			break;
		}
		ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_ANALYZE;
		*when = cm_time_now;
		break;
	case CM_CA_NEED_TO_ANALYZE:
		switch (state->cm_phase) {
		case cm_ca_phase_certs:
			state->cm_ca_cert_analyze_state = cm_ca_analyze_start_certs(ca);
			if (state->cm_ca_cert_analyze_state == NULL) {
				ca->cm_ca_state[state->cm_phase] = CM_CA_DISABLED;
				*when = cm_time_now;
			} else {
				*readfd = cm_ca_analyze_get_fd(state->cm_ca_cert_analyze_state);
				if (*readfd == -1) {
					cm_ca_analyze_done(state->cm_ca_cert_analyze_state);
					ca->cm_ca_state[state->cm_phase] = CM_CA_DISABLED;
				} else {
					ca->cm_ca_state[state->cm_phase] = CM_CA_ANALYZING;
					*when = cm_time_no_time;
				}
			}
			break;
		case cm_ca_phase_identify:
		case cm_ca_phase_profiles:
		case cm_ca_phase_default_profile:
		case cm_ca_phase_enroll_reqs:
		case cm_ca_phase_renew_reqs:
		case cm_ca_phase_capabilities:
			ca->cm_ca_state[state->cm_phase] = CM_CA_IDLE;
			*when = cm_time_now;
			break;
		case cm_ca_phase_encryption_certs:
			state->cm_ca_ecert_analyze_state = cm_ca_analyze_start_encryption_certs(ca);
			if (state->cm_ca_ecert_analyze_state == NULL) {
				ca->cm_ca_state[state->cm_phase] = CM_CA_DISABLED;
				*when = cm_time_now;
			} else {
				*readfd = cm_ca_analyze_get_fd(state->cm_ca_ecert_analyze_state);
				if (*readfd == -1) {
					cm_ca_analyze_done(state->cm_ca_ecert_analyze_state);
					ca->cm_ca_state[state->cm_phase] = CM_CA_DISABLED;
				} else {
					ca->cm_ca_state[state->cm_phase] = CM_CA_ANALYZING;
					*when = cm_time_no_time;
				}
			}
			break;
		case cm_ca_phase_invalid:
			abort();
			break;
		}
		break;
	case CM_CA_ANALYZING:
		switch (state->cm_phase) {
		case cm_ca_phase_certs:
			if (cm_ca_analyze_ready(state->cm_ca_cert_analyze_state) == 0) {
				state->cm_cert_refresh_delay = cm_ca_analyze_get_delay(state->cm_ca_cert_analyze_state);
				cm_ca_analyze_done(state->cm_ca_cert_analyze_state);
				state->cm_ca_cert_analyze_state = NULL;
				if (state->cm_cert_refresh_delay != 0) {
					ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_REFRESH;
					*delay = state->cm_cert_refresh_delay;
					if (*delay < CM_DELAY_CA_POLL_MINIMUM) {
						*delay = CM_DELAY_CA_POLL_MINIMUM;
					}
					if (*delay > CM_DELAY_CA_POLL_MAXIMUM) {
						*delay = CM_DELAY_CA_POLL_MAXIMUM;
					}
					*when = cm_time_delay;
				} else {
					ca->cm_ca_state[state->cm_phase] = CM_CA_IDLE;
					*when = cm_time_now;
				}
			} else {
				/* Wait for status update, or poll. */
				*readfd = cm_ca_analyze_get_fd(state->cm_ca_cert_analyze_state);
				if (*readfd == -1) {
					*when = cm_time_soon;
				} else {
					*when = cm_time_no_time;
				}
			}
			break;
		case cm_ca_phase_encryption_certs:
			if (cm_ca_analyze_ready(state->cm_ca_ecert_analyze_state) == 0) {
				state->cm_ecert_refresh_delay = cm_ca_analyze_get_delay(state->cm_ca_ecert_analyze_state);
				cm_ca_analyze_done(state->cm_ca_ecert_analyze_state);
				state->cm_ca_ecert_analyze_state = NULL;
				if (state->cm_ecert_refresh_delay != 0) {
					ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_REFRESH;
					*delay = state->cm_ecert_refresh_delay;
					if (*delay < CM_DELAY_CA_POLL_MINIMUM) {
						*delay = CM_DELAY_CA_POLL_MINIMUM;
					}
					if (*delay > CM_DELAY_CA_POLL_MAXIMUM) {
						*delay = CM_DELAY_CA_POLL_MAXIMUM;
					}
					*when = cm_time_delay;
				} else {
					ca->cm_ca_state[state->cm_phase] = CM_CA_IDLE;
					*when = cm_time_now;
				}
			} else {
				/* Wait for status update, or poll. */
				*readfd = cm_ca_analyze_get_fd(state->cm_ca_ecert_analyze_state);
				if (*readfd == -1) {
					*when = cm_time_soon;
				} else {
					*when = cm_time_no_time;
				}
			}
			break;
		case cm_ca_phase_identify:
		case cm_ca_phase_profiles:
		case cm_ca_phase_default_profile:
		case cm_ca_phase_enroll_reqs:
		case cm_ca_phase_renew_reqs:
		case cm_ca_phase_capabilities:
		case cm_ca_phase_invalid:
			abort();
			break;
		}
		break;
	case CM_CA_DATA_UNREACHABLE:
		ca->cm_ca_state[state->cm_phase] = CM_CA_NEED_TO_REFRESH;
		*when = cm_time_soonish;
		break;
	case CM_CA_IDLE:
	case CM_CA_DISABLED:
		*when = cm_time_no_time;
		break;
	}
	if (ca->cm_ca_state[state->cm_phase] != old_ca->cm_ca_state[state->cm_phase]) {
		cm_log(3, "%s('%s').%s moved to state '%s'\n",
		       ca->cm_busname, ca->cm_nickname,
		       cm_store_ca_phase_as_string(state->cm_phase),
		       cm_store_ca_state_as_string(ca->cm_ca_state[state->cm_phase]));
		cm_store_ca_save(ca);
	}
	if (emit_ca_changes != NULL) {
		(*emit_ca_changes)(context, old_ca, ca);
	}
	talloc_free(old_ca);
	return 0;
}

/* Cancel and clean up any in-progress work and then free the working state. */
int
cm_iterate_ca_done(struct cm_store_ca *ca, void *cm_iterate_state)
{
	struct cm_ca_state *state;
	enum cm_ca_phase phase = cm_ca_phase_invalid;
	const char *phases, *states;

	state = cm_iterate_state;

	phases = cm_store_ca_phase_as_string(phase);
	states = cm_store_ca_state_as_string(CM_CA_DISABLED);

	if (state != NULL) {
	       phase = state->cm_phase,
	       phases = cm_store_ca_phase_as_string(phase),
	       states = cm_store_ca_state_as_string(ca->cm_ca_state[phase]);
		if (state->cm_ca_cert_analyze_state != NULL) {
			cm_ca_analyze_done(state->cm_ca_cert_analyze_state);
			state->cm_ca_cert_analyze_state = NULL;
		}
		if (state->cm_ca_ecert_analyze_state != NULL) {
			cm_ca_analyze_done(state->cm_ca_ecert_analyze_state);
			state->cm_ca_ecert_analyze_state = NULL;
		}
		if (state->cm_task_state != NULL) {
			cm_cadata_done(state->cm_task_state);
			state->cm_task_state = NULL;
		}
		if (state->cm_hook_state != NULL) {
			cm_hook_done(state->cm_hook_state);
			state->cm_hook_state = NULL;
		}
		if (state->cm_casave_state != NULL) {
			cm_casave_done(state->cm_casave_state);
			state->cm_casave_state = NULL;
		}
		talloc_free(state);
	}

	cm_log(3, "%s('%s').%s ends (%s)\n",
	       ca->cm_busname, ca->cm_nickname, phases, states);

	if (cm_writing_has_lock(ca, phase)) {
		cm_writing_unlock_by_ca(ca, phase);
	}
	return 0;
}
