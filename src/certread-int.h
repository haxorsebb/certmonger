#ifndef cmcertreadint_h
#define cmcertreadint_h

struct cm_certread_state_pvt {
	/* Check if something changed, for example we finished reading the
	 * cert. */
	int (*ready)(struct cm_store_entry *entry,
		     struct cm_certread_state *state);
	/* Get a selectable-for-read descriptor we can poll for status changes.
	 * */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_certread_state *state);
	/* Clean up after reading the certificate. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_certread_state *state);
};

#endif
