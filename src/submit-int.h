#ifndef cmsubmitint_h
#define cmsubmitint_h

struct cm_submit_state;
struct cm_store_entry;
struct cm_submit_state_pvt {
	/* Get a selectable-for-read descriptor we can poll for status changes.
	 */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_submit_state *state);
	/* Check if the CSR was submitted to the CA yet. */
	int (*sent)(struct cm_store_entry *entry,
		    struct cm_submit_state *state);
	/* Save CA-specific identifier for our submitted request. */
	int (*save_ca_cookie)(struct cm_store_entry *entry,
			      struct cm_submit_state *state);
	/* Check if an attempt to get status has succeeded. */
	int (*status_ready)(struct cm_store_entry *entry,
			    struct cm_submit_state *state);
	/* Check if the certificate was issued. */
	int (*issued)(struct cm_store_entry *entry,
		      struct cm_submit_state *state);
	/* Check if we need to make another request to actually retrieve the
	 * cert. */
	int (*needs_retrieval)(struct cm_store_entry *entry,
			       struct cm_submit_state *state);
	/* Done talking to the CA. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_submit_state *state);
};

#endif
