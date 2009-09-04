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

time_t
cm_store_time_from_timestamp(const char *timestamp)
{
	struct tm stamp;
	char buf[5];
	time_t t;
	int i;
	if (strlen(timestamp) < 12) {
		return 0;
	}
	memset(&stamp, 0, sizeof(stamp));
	if ((strlen(timestamp) == 14) || (strlen(timestamp) == 15)){
		memcpy(buf, timestamp, 4);
		i = 4;
		buf[i] = '\0';
		stamp.tm_year = atoi(buf) - 1900;
	} else {
		if ((strlen(timestamp) == 12) || (strlen(timestamp) == 13)) {
			memcpy(buf, timestamp, 2);
			i = 2;
			buf[i] = '\0';
			stamp.tm_year = atoi(buf);
			if (stamp.tm_year < 50) {
				stamp.tm_year += 100;
			}
		} else {
			return 0;
		}
	}
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	stamp.tm_mon = atoi(buf) - 1;
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	stamp.tm_mday = atoi(buf);
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	stamp.tm_hour = atoi(buf);
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	stamp.tm_min = atoi(buf);
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	stamp.tm_sec = atoi(buf);
	t = timegm(&stamp);
	return t;
}

char *
cm_store_timestamp_from_time(time_t when, char timestamp[15])
{
	struct tm tm;
	if ((when != 0) && (gmtime_r(&when, &tm) == &tm)) {
		sprintf(timestamp, "%04d%02d%02d%02d%02d%02d",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	} else {
		strcpy(timestamp, "19700101000000");
	}
	return timestamp;
}
