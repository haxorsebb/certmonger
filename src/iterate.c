#include "config.h"

#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <talloc.h>

#include "certread.h"
#include "certsave.h"
#include "csrgen.h"
#include "keygen.h"
#include "log.h"
#include "notify.h"
#include "submit.h"
#include "store.h"
#include "iterate.h"
#include "store-int.h"

struct cm_iterate_state {
	struct cm_keygen_state *cm_keygen_state;
	struct cm_csrgen_state *cm_csrgen_state;
	struct cm_submit_state *cm_submit_state;
	struct cm_certsave_state *cm_certsave_state;
	struct cm_notify_state *cm_notify_state;
};

/* Helper routine to replace in-progress states with the previous "stable"
 * state. */
static void
cm_entry_reset_state(struct cm_store_entry *entry)
{
	switch (entry->cm_state) {
	case CM_NEED_KEY_PAIR:
	case CM_GENERATING_KEY_PAIR:
		entry->cm_state = CM_NEED_KEY_PAIR;
		break;
	case CM_HAVE_KEY_PAIR:
	case CM_NEED_CSR:
	case CM_GENERATING_CSR:
		entry->cm_state = CM_HAVE_KEY_PAIR;
		break;
	case CM_HAVE_CSR:
	case CM_NEED_TO_SUBMIT:
	case CM_SUBMITTING:
		entry->cm_state = CM_HAVE_CSR;
		break;
	case CM_HAVE_SUBMITTED:
	case CM_NEED_CA_STATUS:
	case CM_POLLING_CA_STATUS:
	case CM_RETRIEVING_CERT:
		entry->cm_state = CM_HAVE_SUBMITTED;
		break;
	case CM_NEED_TO_SAVE_CERT:
	case CM_SAVING_CERT:
		entry->cm_state = CM_NEED_TO_SAVE_CERT;
		break;
	case CM_SAVED_CERT:
		entry->cm_state = CM_MONITORING;
		break;
	case CM_NEED_GUIDANCE:
		break;
	case CM_MONITORING:
	case CM_NOTIFYING:
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
	struct cm_certread_state *readstate;
	int fd;
	state = talloc_ptrtype(entry, state);
	if (state == NULL) {
		return ENOMEM;
	}
	memset(state, 0, sizeof(*state));
	*cm_iterate_state = state;
	cm_entry_reset_state(entry);
	readstate = cm_certread_start(entry);
	if (readstate != NULL) {
		while (cm_certread_ready(entry, readstate) != 0) {
			fd = cm_certread_get_fd(entry, readstate);
			if (fd != -1) {
				cm_waitfor_readable_fd(fd, -1);
			}
		}
		cm_certread_done(entry, readstate);
		cm_store_entry_save(entry);
	}
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
	if (entry->cm_cert_expiration > now) {
		ttl = 0;
	} else {
		ttl = entry->cm_cert_expiration - now;
	}
	/* How much time was left, last time we checked? */
	if (entry->cm_cert_expiration > entry->cm_last_expiration_check) {
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
	return -1;
}

int
cm_iterate(struct cm_store_entry *entry,
	   void *cm_iterate_state,
	   enum cm_time *when, int *delay, int *readfd)
{
	struct cm_iterate_state *state;
	enum cm_state old_entry_state;
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
	case CM_HAVE_CSR:
		entry->cm_state = CM_NEED_TO_SUBMIT;
		*when = cm_time_now;
		break;
	case CM_NEED_TO_SUBMIT:
		state->cm_submit_state = cm_submit_start(entry);
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
		} else {
			/* Failed to start submission; take a breather and try
			 * again. */
			*when = cm_time_soonish;
		}
		break;
	case CM_SUBMITTING:
		if (cm_submit_sent(entry, state->cm_submit_state) == 0) {
			entry->cm_submitted = time(NULL);
			if (cm_submit_issued(entry,
					     state->cm_submit_state) == 0) {
				/* CA issued a cert. */
				if (cm_submit_needs_retrieval(entry,
							      state->cm_submit_state) == 0) {
					/* We're done, but we need to retrieve
					 * the certificate in another step.
					 * Give the CA a second to be polite. */
					entry->cm_state = CM_RETRIEVING_CERT;
					*when = cm_time_soon;
				} else {
					/* We're all done, and we even have the
					 * issued certificate.  Save the
					 * certificate to its real home. */
					cm_submit_done(entry,
						       state->cm_submit_state);
					state->cm_submit_state = NULL;
					entry->cm_state = CM_NEED_TO_SAVE_CERT;
					*when = cm_time_now;
				}
			} else
			if (cm_submit_save_ca_cookie(entry,
						     state->cm_submit_state) == 0) {
				/* Saved CA's identifier for our request; move
				 * on. */
				entry->cm_state = CM_HAVE_SUBMITTED;
				*when = cm_time_now;
			} else {
				/* Couldn't retrieve acknowledgement from the
				 * CA, so we have to try submitting another
				 * request. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_NEED_TO_SUBMIT;
				*when = cm_time_soon;
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
	case CM_HAVE_SUBMITTED:
		entry->cm_state = CM_NEED_CA_STATUS;
		*when = cm_time_now;
		break;
	case CM_NEED_CA_STATUS:
		if (state->cm_submit_state == NULL) {
			/* Pick up where we left off, if need be. */
			state->cm_submit_state = cm_submit_resume(entry);
		}
		if (state->cm_submit_state != NULL) {
			/* We're working on checking our status. */
			entry->cm_state = CM_POLLING_CA_STATUS;
			/* Wait for status update, or poll. */
			*readfd = cm_submit_get_fd(entry,
						   state->cm_submit_state);
			if (*readfd == -1) {
				*when = cm_time_soon;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Couldn't start polling for status; try again after a
			 * bit. */
			*when = cm_time_soonish;
		}
		break;
	case CM_POLLING_CA_STATUS:
		if (cm_submit_status_ready(entry,
					   state->cm_submit_state) == 0) {
			/* We've retrieved status from the CA. */
			if (cm_submit_issued(entry,
					     state->cm_submit_state) == 0) {
				/* CA issued a cert. */
				if (cm_submit_needs_retrieval(entry,
							      state->cm_submit_state) == 0) {
					/* We're done, but we need to retrieve
					 * the certificate in another step. */
					entry->cm_state = CM_RETRIEVING_CERT;
					*when = cm_time_soon;
				} else {
					/* We're all done, and we even have the
					 * issued certificate.  Save the
					 * certificate to its real home. */
					cm_submit_done(entry,
						       state->cm_submit_state);
					state->cm_submit_state = NULL;
					entry->cm_state = CM_NEED_TO_SAVE_CERT;
					*when = cm_time_now;
				}
			} else {
				/* The CA denied our request. HELP! */
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
	case CM_RETRIEVING_CERT:
		if (cm_submit_status_ready(entry,
					   state->cm_submit_state) == 0) {
			/* We've retrieved the cert, but we haven't saved it
			 * anywhere yet. */
			cm_submit_done(entry, state->cm_submit_state);
			state->cm_submit_state = NULL;
			entry->cm_state = CM_NEED_TO_SAVE_CERT;
			*when = cm_time_now;
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
				/* Saved certificate; move on. */
				cm_certsave_done(entry, state->cm_certsave_state);
				state->cm_certsave_state = NULL;
				entry->cm_state = CM_SAVED_CERT;
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
	case CM_SAVED_CERT:
		entry->cm_state = CM_MONITORING;
		*when = cm_time_now;
		break;
	case CM_NEED_GUIDANCE:
		*when = cm_time_soonish;
		break;
	case CM_MONITORING:
		if ((entry->cm_monitor || entry->cm_monitor_default) && /* XXX */
		    (cm_check_expiration_is_noteworthy(entry) == 0)) {
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
				/* Try to log it ourselves. */
				cm_log(0, "'%s' will expire in %d days.\n",
				       (entry->cm_cert_expiration - time(NULL))/
				       (24 * 60 * 60));
				*delay = 24 * 60 * 60; /* XXX */
				*when = cm_time_delay;
			}
		} else {
			/* Nothing to do here. */
			*delay = 24 * 60 * 60; /* XXX */
			*when = cm_time_delay;
		}
		break;
	case CM_NOTIFYING:
		if (cm_notify_ready(entry, state->cm_notify_state) == 0) {
			cm_notify_done(entry, state->cm_notify_state);
			state->cm_notify_state = NULL;
		}
		if ((entry->cm_autorenew || entry->cm_autorenew_default)) { /* XXX */
			entry->cm_state = CM_NEED_CSR;
			*when = cm_time_soon;
		} else {
			entry->cm_state = CM_MONITORING;
			*when = cm_time_soon;
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
	if (state->cm_submit_state != NULL) {
		cm_submit_done(entry, state->cm_submit_state);
		state->cm_submit_state = NULL;
	}
	if (state->cm_csrgen_state != NULL) {
		cm_csrgen_done(entry, state->cm_csrgen_state);
		state->cm_csrgen_state = NULL;
	}
	if (state->cm_keygen_state != NULL) {
		cm_keygen_done(entry, state->cm_keygen_state);
		state->cm_keygen_state = NULL;
	}
	if (state->cm_notify_state != NULL) {
		cm_notify_done(entry, state->cm_notify_state);
		state->cm_notify_state = NULL;
	}
	cm_entry_reset_state(entry);
	cm_log(3, "'%s' ends in state '%s'\n", entry->cm_id,
	       cm_store_state_as_string(entry->cm_state));
	return 0;
}
