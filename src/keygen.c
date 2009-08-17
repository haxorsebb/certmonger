#include "config.h"
#include "keygen.h"
#include "keygen-int.h"
#include "store-int.h"

struct cm_keygen_state *
cm_keygen_start(struct cm_store_entry *entry)
{
	switch (entry->cm_key_storage_type) {
#ifdef HAVE_OPENSSL
	case cm_key_storage_file:
		return cm_keygen_o_start(entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_key_storage_nssdb:
		return cm_keygen_n_start(entry);
		break;
#endif
	}
	return NULL;
}

/* Check if the keypair is ready. */
int
cm_keygen_ready(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	return pvt->ready(entry, state);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_keygen_get_fd(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	return pvt->get_fd(entry, state);
}

/* Tell us if the keypair was saved to the location specified in the entry. */
int
cm_keygen_saved_keypair(struct cm_store_entry *entry,
			struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	return pvt->saved_keypair(entry, state);
}

/* Clean up after key generation. */
void
cm_keygen_done(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	struct cm_keygen_state_pvt *pvt = (struct cm_keygen_state_pvt *) state;
	pvt->done(entry, state);
}
