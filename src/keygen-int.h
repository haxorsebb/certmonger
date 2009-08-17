#ifndef cmkeygenint_h
#define cmkeygenint_h

struct cm_keygen_state_pvt {
	/* Check if the keypair is ready. */
	int (*ready)(struct cm_store_entry *entry,
		     struct cm_keygen_state *state);
	/* Get a selectable-for-read descriptor we can poll for status changes.
	 */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_keygen_state *state);
	/* Tell us if the keypair was saved to the right location. */
	int (*saved_keypair)(struct cm_store_entry *entry,
			     struct cm_keygen_state *state);
	/* Clean up after key generation. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_keygen_state *state);
};

#endif
