#ifndef iterate_h
#define iterate_h

/* Start tracking a working state for this entry. */
int cm_iterate_init(struct cm_store_entry *entry, void **cm_iterate_state);
/* Figure out what to do next about this specific entry. */
enum cm_time {
	cm_time_now,	/* Poke again without delay. */
	cm_time_soon,	/* Soon - small delays ok. */
	cm_time_soonish,/* Small delay. */
	cm_time_delay,	/* At specified delay. */
	cm_time_no_time	/* Wait for data on specified descriptor. */
};
int cm_iterate(struct cm_store_entry *entry,
	       void *cm_iterate_state,
	       enum cm_time *when,
	       struct timeval *delay,
	       int *readfd);
/* We're shutting down. */
int cm_iterate_done(struct cm_store_entry *entry, void *cm_iterate_state);

#endif
