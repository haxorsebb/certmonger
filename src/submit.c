#include "config.h"
#include "submit.h"
#include "submit-int.h"
#include "store-int.h"

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_start(struct cm_store_entry *entry)
{
	switch (entry->cm_ca_type) {
	case cm_ca_dummy:
		switch (entry->cm_key_storage_type) {
#ifdef HAVE_OPENSSL
		case cm_key_storage_file:
			return cm_submit_o_start(entry);
			break;
#endif
#ifdef HAVE_NSS
		case cm_key_storage_nssdb:
			return cm_submit_n_start(entry);
			break;
#endif
		}
		break;
	}
	return NULL;
}

/* Pick up after a CSR has been submitted, in case we haven't yet gotten a
 * decision about it. */
struct cm_submit_state *
cm_submit_resume(struct cm_store_entry *entry)
{
	switch (entry->cm_key_storage_type) {
#ifdef HAVE_OPENSSL
	case cm_key_storage_file:
		return cm_submit_o_resume(entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_key_storage_nssdb:
		return cm_submit_n_resume(entry);
		break;
	}
#endif
	return NULL;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_submit_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->get_fd(entry, state);
}

/* Check if the CSR was submitted to the CA yet. */
int
cm_submit_sent(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->sent(entry, state);
}

/* Save CA-specific identifier for our submitted request. */
int
cm_submit_save_ca_cookie(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->save_ca_cookie(entry, state);
}

/* Check if an attempt to get status has succeeded. */
int
cm_submit_status_ready(struct cm_store_entry *entry,
		       struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->status_ready(entry, state);
}

/* Check if the certificate was issued. */
int
cm_submit_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->issued(entry, state);
}

/* Check if we need to make another request to actually retrieve the cert. */
int
cm_submit_needs_retrieval(struct cm_store_entry *entry,
			  struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	return pvt->needs_retrieval(entry, state);
}

/* Done talking to the CA. */
void
cm_submit_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	struct cm_submit_state_pvt *pvt = (struct cm_submit_state_pvt *) state;
	pvt->done(entry, state);
}
