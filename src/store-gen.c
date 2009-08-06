#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "store.h"
#include "store-int.h"

static struct {
	const char *name;
	enum cm_state state;
} cm_state_names[] = {
	{"INVALID", CM_INVALID},
	{"NEED_KEY_PAIR", CM_NEED_KEY_PAIR},
	{"GENERATING_KEY_PAIR", CM_GENERATING_KEY_PAIR},
	{"HAVE_KEY_PAIR", CM_HAVE_KEY_PAIR},
	{"NEED_CSR", CM_NEED_CSR},
	{"GENERATING_CSR", CM_GENERATING_CSR},
	{"HAVE_CSR", CM_HAVE_CSR},
	{"NEED_TO_SUBMIT", CM_NEED_TO_SUBMIT},
	{"SUBMITTING", CM_SUBMITTING},
	{"HAVE_SUBMITTED", CM_HAVE_SUBMITTED},
	{"NEED_CA_STATUS", CM_NEED_CA_STATUS},
	{"POLLING_CA_STATUS", CM_POLLING_CA_STATUS},
	{"RETRIEVING_CERT", CM_RETRIEVING_CERT},
	{"MONITORING", CM_MONITORING},
	{"NEED_GUIDANCE", CM_NEED_GUIDANCE},
};

const char *
cm_store_state_as_string(enum cm_state state)
{
	unsigned int i;
	for (i = 0;
	     i < sizeof(cm_state_names) / sizeof(cm_state_names[0]);
	     i++) {
		if (cm_state_names[i].state == state) {
			return cm_state_names[i].name;
		}
	}
	return cm_state_names[0].name;
}

enum cm_state
cm_store_state_from_string(const char *name)
{
	unsigned int i;
	for (i = 0;
	     i < sizeof(cm_state_names) / sizeof(cm_state_names[0]);
	     i++) {
		if (strcasecmp(cm_state_names[i].name, name) == 0) {
			return cm_state_names[i].state;
		}
	}
	return CM_INVALID;
}

/* Generic routines. */
struct cm_store_entry *
cm_store_entry_new()
{
	struct cm_store_entry *entry;
	entry = malloc(sizeof(*entry));
	if (entry != NULL) {
		memset(entry, 0, sizeof(*entry));
	}
	return entry;
}

void
cm_store_entry_free(struct cm_store_entry *entry)
{
	free(entry->cm_store_private); /* XXX */

	free(entry->cm_key_storage_location);

	free(entry->cm_cert_storage_location);
	free(entry->cm_cert_nickname);

	free(entry->cm_cert_issuer);
	free(entry->cm_cert_serial);
	free(entry->cm_cert_subject);
	free(entry->cm_cert_spki);
	free(entry->cm_cert_email);
	free(entry->cm_cert_principal);
	free(entry->cm_cert_ku);
	free(entry->cm_cert_eku);

	free(entry->cm_ttls);

	free(entry->cm_notification_destination);

	free(entry->cm_template_subject);
	free(entry->cm_template_email);
	free(entry->cm_template_principal);
	free(entry->cm_template_ku);
	free(entry->cm_template_eku);

	free(entry->cm_csr);

	free(entry->cm_ca_location);
	free(entry->cm_ca_cookie);

	free(entry);
}

void
cm_store_entry_freev(struct cm_store_entry **entry)
{
	int i;
	for (i = 0; (entry != NULL) && (entry[i] != NULL); i++) {
		cm_store_entry_free(entry[i]);
	}
	free(entry);
}
