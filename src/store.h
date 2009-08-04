#ifndef cmstore_h
#define cmstore_h

struct cm_store_entry;

/* Generic routines. */
struct cm_store_entry *cm_store_entry_new();
void cm_store_entry_free(struct cm_store_entry *entry);
int cm_store_entry_save(struct cm_store_entry *entry);
int cm_store_entry_delete(struct cm_store_entry *entry);

/* Store-specific bits. */
struct cm_store_entry *cm_store_get_defaults();
void cm_store_entry_free(struct cm_store_entry *entry);
struct cm_store_entry **cm_store_get_entries();
void cm_store_entry_freev(struct cm_store_entry **entry);

#endif
