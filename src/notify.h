#ifndef cmnotify_h
#define cmnotify_h

struct cm_store_entry;
struct cm_notify_state;

/* Start to notify the administrator or user that expiration is imminent. */
struct cm_notify_state *cm_notify_start(struct cm_store_entry *entry);
/* Get a selectable-for-read descriptor we can poll for status changes when
 * we're finished sending the notification. */
int cm_notify_get_fd(struct cm_store_entry *entry,
		     struct cm_notify_state *state);
/* Check if we're ready to call notification done. */
int cm_notify_ready(struct cm_store_entry *entry,
		    struct cm_notify_state *state);
/* Clean up after notification. */
void cm_notify_done(struct cm_store_entry *entry,
		    struct cm_notify_state *state);

#endif
