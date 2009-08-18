#ifndef cmcertread_h
#define cmcertread_h

struct cm_certread_state;
struct cm_store_entry;

/* Start refreshing the certificate and associated data from the entry from the
 * configured location. */
struct cm_certread_state *cm_certread_start(struct cm_store_entry *entry);
struct cm_certread_state *cm_certread_n_start(struct cm_store_entry *entry);
struct cm_certread_state *cm_certread_o_start(struct cm_store_entry *entry);
/* Check if something changed, for example we finished reading the cert. */
int cm_certread_ready(struct cm_store_entry *entry,
		      struct cm_certread_state *state);
/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_certread_get_fd(struct cm_store_entry *entry,
		       struct cm_certread_state *state);
/* Clean up after reading the certificate. */
void cm_certread_done(struct cm_store_entry *entry,
		      struct cm_certread_state *state);

#endif
