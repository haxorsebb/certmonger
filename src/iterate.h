#ifndef iterate_h
#define iterate_h

/* Figure out what to do next about this specific entry. */
int cm_iterate(struct cm_store_entry *entry,
	       void **cm_iterate_state,
	       int *readfd,
	       int *immediate,
	       struct timeval *delay);

#endif
