#ifndef cmsubmit_h
#define cmsubmit_h

struct cm_submit_state;
struct cm_store_entry;

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *cm_submit_start(struct cm_store_entry *entry);
struct cm_submit_state *cm_submit_n_start(struct cm_store_entry *entry);
struct cm_submit_state *cm_submit_o_start(struct cm_store_entry *entry);

/* Pick up after a CSR has been submitted, in case we haven't yet gotten a
 * decision about it. */
struct cm_submit_state *cm_submit_resume(struct cm_store_entry *entry);
struct cm_submit_state *cm_submit_n_resume(struct cm_store_entry *entry);
struct cm_submit_state *cm_submit_o_resume(struct cm_store_entry *entry);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_submit_get_fd(struct cm_store_entry *entry,
		     struct cm_submit_state *state);

/* Check if the CSR was submitted to the CA yet. */
int cm_submit_sent(struct cm_store_entry *entry, struct cm_submit_state *state);

/* Save CA-specific identifier for our submitted request. */
int cm_submit_save_ca_cookie(struct cm_store_entry *entry,
			     struct cm_submit_state *state);

/* Check if an attempt to get status has succeeded. */
int cm_submit_status_ready(struct cm_store_entry *entry,
			   struct cm_submit_state *state);

/* Check if the certificate was issued. */
int cm_submit_issued(struct cm_store_entry *entry,
		     struct cm_submit_state *state);

/* Check if we need to make another request to actually retrieve the cert. */
int cm_submit_needs_retrieval(struct cm_store_entry *entry,
			      struct cm_submit_state *state);

/* Done talking to the CA. */
void cm_submit_done(struct cm_store_entry *entry,
		    struct cm_submit_state *state);

#endif
