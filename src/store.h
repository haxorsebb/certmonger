#ifndef cmstore_h
#define cmstore_h

struct cm_store_entry;

/* Generic routines. */
struct cm_store_entry *cm_store_entry_new(void *parent);

/* Store-specific bits. */
int cm_store_entry_save(struct cm_store_entry *entry);
int cm_store_entry_delete(struct cm_store_entry *entry);
struct cm_store_entry *cm_store_get_defaults(void);
struct cm_store_entry **cm_store_get_all_entries(void *parent);

/* Utility functions. */
time_t cm_store_time_from_timestamp(const char *timestamp);
char *cm_store_timestamp_from_time(time_t when, char timestamp[15]);

#endif
