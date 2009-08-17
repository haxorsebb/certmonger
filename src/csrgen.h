#ifndef cmcsrgen_h
#define cmcsrgen_h

struct cm_csrgen_state;
struct cm_store_entry;

/* Start CSR generation using template information in the entry. */
struct cm_csrgen_state *cm_csrgen_start(struct cm_store_entry *entry);
struct cm_csrgen_state *cm_csrgen_n_start(struct cm_store_entry *entry);
struct cm_csrgen_state *cm_csrgen_o_start(struct cm_store_entry *entry);

/* Check if a CSR is ready. */
int cm_csrgen_ready(struct cm_store_entry *entry,
		    struct cm_csrgen_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_csrgen_get_fd(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state);

/* Save the CSR to the entry. */
int cm_csrgen_save_csr(struct cm_store_entry *entry,
		       struct cm_csrgen_state *state);

/* Clean up after CSR generation. */
void cm_csrgen_done(struct cm_store_entry *entry,
		    struct cm_csrgen_state *state);

#endif
