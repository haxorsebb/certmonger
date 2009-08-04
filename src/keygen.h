#ifndef cmkeygen_h
#define cmkeygen_h


struct cm_keygen_state;
struct cm_store_entry;

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *cm_keygen_start(struct cm_store_entry *entry);
/* Check if the keypair is ready. */
int cm_keygen_ready(struct cm_store_entry *entry,
		    struct cm_keygen_state *state);
/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_keygen_get_fd(struct cm_store_entry *entry,
		     struct cm_keygen_state *state);
/* Save the keypair to the location specified in the entry. */
int cm_keygen_save_keypair(struct cm_store_entry *entry,
			   struct cm_keygen_state *state);
/* Clean up after key generation. */
void cm_keygen_done(struct cm_store_entry *entry,
		    struct cm_keygen_state *state);

#endif
