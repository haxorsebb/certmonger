#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "store.h"
#include "store-int.h"

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
	free(entry->cm_key_storage_location);

	free(entry->cm_cert_storage_location);
	free(entry->cm_cert_nickname);

	free(entry->cm_issuer);
	free(entry->cm_serial);
	free(entry->cm_subject);
	free(entry->cm_spki);
	free(entry->cm_email);
	free(entry->cm_principal);
	free(entry->cm_ku);
	free(entry->cm_eku);

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
