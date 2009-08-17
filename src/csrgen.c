#include "config.h"
#include "csrgen.h"
#include "csrgen-int.h"
#include "store-int.h"

struct cm_csrgen_state *
cm_csrgen_start(struct cm_store_entry *entry)
{
	switch (entry->cm_key_storage_type) {
#ifdef HAVE_OPENSSL
	case cm_key_storage_file:
		return cm_csrgen_o_start(entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_key_storage_nssdb:
		return cm_csrgen_n_start(entry);
		break;
	}
#endif
	return NULL;
}

int
cm_csrgen_ready(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;
	return pvt->ready(entry, state);
}

int
cm_csrgen_get_fd(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;
	return pvt->get_fd(entry, state);
}

int
cm_csrgen_save_csr(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;
	return pvt->save_csr(entry, state);
}

void
cm_csrgen_done(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;
	pvt->done(entry, state);
}
