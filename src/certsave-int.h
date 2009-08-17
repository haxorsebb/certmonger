#ifndef cmcertsaveint_h
#define cmcertsaveint_h

struct cm_certsave_state_pvt {
	/* Check if something changed, for example we finished saving the cert.
	 */
	int (*ready)(struct cm_store_entry *entry,
		     struct cm_certsave_state *state);
	/* Get a selectable-for-read descriptor that we can poll for status
	 * changes.  */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_certsave_state *state);
	/* Check if we saved the certificate. */
	int (*saved)(struct cm_store_entry *entry,
		     struct cm_certsave_state *state);
	/* Clean up after saving the certificate. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_certsave_state *state);
};

#endif
