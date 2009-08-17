#include "config.h"
#include "certread.h"
#include "certread-int.h"
#include "store-int.h"

/* Start refreshing the certificate and associated data from the entry from the
 * configured location. */
struct cm_certread_state *
cm_certread_start(struct cm_store_entry *entry)
{
	switch (entry->cm_cert_storage_type) {
#ifdef HAVE_OPENSSL
	case cm_cert_storage_file:
		return cm_certread_o_start(entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_cert_storage_nssdb:
		return cm_certread_n_start(entry);
		break;
#endif
	}
	return NULL;
}

/* Check if something changed, for example we finished reading the cert. */
int
cm_certread_ready(struct cm_store_entry *entry, struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;
	pvt = (struct cm_certread_state_pvt *) state;
	return pvt->ready(entry, state);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_certread_get_fd(struct cm_store_entry *entry,
		   struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;
	pvt = (struct cm_certread_state_pvt *) state;
	return pvt->get_fd(entry, state);
}

/* Clean up after reading the certificate. */
void
cm_certread_done(struct cm_store_entry *entry, struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;
	pvt = (struct cm_certread_state_pvt *) state;
	pvt->done(entry, state);
}
