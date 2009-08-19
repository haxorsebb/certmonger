#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <talloc.h>

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
	{"NEED_TO_SAVE_CERT", CM_NEED_TO_SAVE_CERT},
	{"SAVING_CERT", CM_SAVING_CERT},
	{"SAVED_CERT", CM_SAVED_CERT},
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
cm_store_entry_new(void *parent)
{
	struct cm_store_entry *entry;
	entry = talloc_ptrtype(parent, entry);
	if (entry != NULL) {
		memset(entry, 0, sizeof(*entry));
	}
	return entry;
}
