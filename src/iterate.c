#include "config.h"

#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "csrgen.h"
#include "keygen.h"
#include "submit.h"
#include "store.h"
#include "iterate.h"
#include "store-int.h"

struct cm_iterate_state {
	struct cm_keygen_state *cm_keygen_state;
	struct cm_csrgen_state *cm_csrgen_state;
	struct cm_submit_state *cm_submit_state;
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
	case CM_NEED_GUIDANCE:
		break;
	case CM_MONITORING:
		break;
	case CM_INVALID:
		abort();
		break;
	}
}

int
cm_iterate_init(struct cm_store_entry *entry, void **cm_iterate_state)
{
	struct cm_iterate_state *state;
	state = malloc(sizeof(*state));
	if (state == NULL) {
		return ENOMEM;
	}
	memset(state, 0, sizeof(*state));
	*cm_iterate_state = state;
	cm_entry_reset_state(entry);
	return 0;
}

int
cm_iterate(struct cm_store_entry *entry,
	   void *cm_iterate_state,
	   enum cm_time *when, int *delay, int *readfd)
{
	struct cm_iterate_state *state;
	state = cm_iterate_state;
	*readfd = -1;
	*when = cm_time_no_time;
	*delay = 0;
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
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start generating a key; try again. */
			*when = cm_time_soon;
		}
		break;
	case CM_GENERATING_KEY_PAIR:
		if (cm_keygen_ready(entry, state->cm_keygen_state) == 0) {
			if (cm_keygen_save_keypair(entry,
						   state->cm_keygen_state) == 0) {
				/* Saved key pair; move on. */
				cm_keygen_done(entry, state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_HAVE_KEY_PAIR;
				*when = cm_time_soon;
			} else {
				/* Failed to save key pair; try again. */
				cm_keygen_done(entry, state->cm_keygen_state);
				state->cm_keygen_state = NULL;
				entry->cm_state = CM_NEED_KEY_PAIR;
				*when = cm_time_soon;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_keygen_get_fd(entry,
						   state->cm_keygen_state);
			if (*readfd == -1) {
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_HAVE_KEY_PAIR:
		entry->cm_state = CM_NEED_CSR;
		*when = cm_time_soon;
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
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start generating a CSR; try again. */
			*when = cm_time_soon;
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
				*when = cm_time_soon;
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
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_HAVE_CSR:
		entry->cm_state = CM_NEED_TO_SUBMIT;
		*when = cm_time_soon;
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
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Failed to start submission; try again. */
			*when = cm_time_soon;
		}
		break;
	case CM_SUBMITTING:
		if (cm_submit_sent(entry, state->cm_submit_state) == 0) {
			if ((cm_submit_issued(entry,
					      state->cm_submit_state) == 0) &&
			    (cm_submit_save_cert(entry,
			   			 state->cm_submit_state) == 0)) {
				/* We're all done.  Sit back and wait
				 * for it to near expiration. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_MONITORING;
				*when = cm_time_soon;
			} else
			if (cm_submit_save_ca_cookie(entry,
						     state->cm_submit_state) == 0) {
				/* Saved CA's identifier for our request; move
				 * on. */
				entry->cm_state = CM_HAVE_SUBMITTED;
				*when = cm_time_soon;
			} else {
				/* Couldn't retrieve acknowledgement from the
				 * CA, so we have to try again. */
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
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_HAVE_SUBMITTED:
		entry->cm_state = CM_NEED_CA_STATUS;
		*when = cm_time_soon;
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
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		} else {
			/* Couldn't start polling for status; try again. */
			*when = cm_time_soon;
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
					/* We need to retrieve the certificate
					 * in another step. */
					entry->cm_state = CM_RETRIEVING_CERT;
					*when = cm_time_soon;
				} else {
					if (cm_submit_save_cert(entry,
							        state->cm_submit_state) == 0) {
						/* We're all done.  Sit back
						 * and wait for it to near
						 * expiration. */
						cm_submit_done(entry, state->cm_submit_state);
						state->cm_submit_state = NULL;
						entry->cm_state = CM_MONITORING;
						*when = cm_time_soon;
					} else {
						/* Couldn't save it, but we
						 * know that it was issued, so
						 * try to retrieve it again. */
						cm_submit_done(entry, state->cm_submit_state);
						state->cm_submit_state = NULL;
						entry->cm_state = CM_NEED_CA_STATUS;
						*when = cm_time_soon;
					}
				}
			} else {
				/* The CA denied our request. HELP! */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_NEED_GUIDANCE;
				*when = cm_time_soon;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_submit_get_fd(entry,
						   state->cm_submit_state);
			if (*readfd == -1) {
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_RETRIEVING_CERT:
		if (cm_submit_status_ready(entry,
					   state->cm_submit_state) == 0) {
			if (cm_submit_save_cert(entry,
						state->cm_submit_state) == 0) {
				/* We're all done.  Sit back and wait for it to
				 * near expiration. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_MONITORING;
				*when = cm_time_soon;
			} else {
				/* Couldn't save it, but we know that it was
				 * issued, so try to retrieve it again. */
				cm_submit_done(entry, state->cm_submit_state);
				state->cm_submit_state = NULL;
				entry->cm_state = CM_NEED_CA_STATUS;
				*when = cm_time_soon;
			}
		} else {
			/* Wait for status update, or poll. */
			*readfd = cm_submit_get_fd(entry,
						   state->cm_submit_state);
			if (*readfd == -1) {
				*when = cm_time_soonish;
			} else {
				*when = cm_time_no_time;
			}
		}
		break;
	case CM_NEED_GUIDANCE:
		*when = cm_time_soonish;
		break;
	case CM_MONITORING:
		*delay = 24 * 60 * 60;
		*when = cm_time_delay;
		break;
	case CM_INVALID:
		/* not reached */
		abort();
		break;
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
	cm_entry_reset_state(entry);
	free(state);
	return 0;
}
