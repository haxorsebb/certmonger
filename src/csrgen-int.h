#ifndef cmcsrgenint_h
#define cmcsrgenint_h

struct cm_csrgen_state_pvt {
	/* Check if a CSR is ready. */
	int (*ready)(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state);
	/* Get a selectable-for-read descriptor we can poll for status changes.
	 */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_csrgen_state *state);
	/* Save the CSR to the entry. */
	int (*save_csr)(struct cm_store_entry *entry,
		        struct cm_csrgen_state *state);
	/* Clean up after CSR generation. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state);
};

#endif
