#ifndef cmcertsave_h
#define cmcertsave_h

struct cm_certsave_state;
struct cm_store_entry;

/* Start writing the certificate from the entry to the configured location. */
struct cm_certsave_state *cm_certsave_start(struct cm_store_entry *entry);
/* Check if something changed, for example we finished saving the cert. */
int cm_certsave_ready(struct cm_store_entry *entry,
		      struct cm_certsave_state *state);
/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_certsave_get_fd(struct cm_store_entry *entry,
		       struct cm_certsave_state *state);
/* Check if we saved the certificate. */
int cm_certsave_saved(struct cm_store_entry *entry,
		      struct cm_certsave_state *state);
/* Clean up after saving the certificate. */
void cm_certsave_done(struct cm_store_entry *entry,
		      struct cm_certsave_state *state);

#endif
