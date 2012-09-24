/*
 * Copyright (C) 2009,2011,2012 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <sys/types.h>
#include <ctype.h>
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
	{"NEED_KEY_GEN_PIN", CM_NEED_KEY_GEN_PIN},
	{"NEED_KEY_GEN_TOKEN", CM_NEED_KEY_GEN_TOKEN},
	{"HAVE_KEY_PAIR", CM_HAVE_KEY_PAIR},
	{"NEED_KEYINFO", CM_NEED_KEYINFO},
	{"READING_KEYINFO", CM_READING_KEYINFO},
	{"NEED_KEYINFO_READ_PIN", CM_NEED_KEYINFO_READ_PIN},
	{"NEED_KEYINFO_READ_TOKEN", CM_NEED_KEYINFO_READ_TOKEN},
	{"HAVE_KEYINFO", CM_HAVE_KEYINFO},
	{"NEED_CSR", CM_NEED_CSR},
	{"GENERATING_CSR", CM_GENERATING_CSR},
	{"NEED_CSR_GEN_PIN", CM_NEED_CSR_GEN_PIN},
	{"NEED_CSR_GEN_TOKEN", CM_NEED_CSR_GEN_TOKEN},
	{"HAVE_CSR", CM_HAVE_CSR},
	{"NEED_TO_SUBMIT", CM_NEED_TO_SUBMIT},
	{"SUBMITTING", CM_SUBMITTING},
	{"NEED_CA", CM_NEED_CA},
	{"CA_UNREACHABLE", CM_CA_UNREACHABLE},
	{"CA_UNCONFIGURED", CM_CA_UNCONFIGURED},
	{"CA_REJECTED", CM_CA_REJECTED},
	{"CA_WORKING", CM_CA_WORKING},
	{"NEED_TO_SAVE_CERT", CM_NEED_TO_SAVE_CERT},
	{"PRE_SAVE_CERT", CM_PRE_SAVE_CERT},
	{"START_SAVING_CERT", CM_START_SAVING_CERT},
	{"SAVING_CERT", CM_SAVING_CERT},
	{"NEED_TO_READ_CERT", CM_NEED_TO_READ_CERT},
	{"READING_CERT", CM_READING_CERT},
	{"SAVED_CERT", CM_SAVED_CERT},
	{"POST_SAVED_CERT", CM_POST_SAVED_CERT},
	{"MONITORING", CM_MONITORING},
	{"NEED_TO_NOTIFY_VALIDITY", CM_NEED_TO_NOTIFY_VALIDITY},
	{"NOTIFYING_VALIDITY", CM_NOTIFYING_VALIDITY},
	{"NEED_TO_NOTIFY_REJECTION", CM_NEED_TO_NOTIFY_REJECTION},
	{"NOTIFYING_REJECTION", CM_NOTIFYING_REJECTION},
	{"NEED_TO_NOTIFY_ISSUED_FAILED", CM_NEED_TO_NOTIFY_ISSUED_FAILED},
	{"NOTIFYING_ISSUED_FAILED", CM_NOTIFYING_ISSUED_FAILED},
	{"NEED_TO_NOTIFY_ISSUED_SAVED", CM_NEED_TO_NOTIFY_ISSUED_SAVED},
	{"NOTIFYING_ISSUED_SAVED", CM_NOTIFYING_ISSUED_SAVED},
	{"NEED_GUIDANCE", CM_NEED_GUIDANCE},
	{"NEWLY_ADDED", CM_NEWLY_ADDED},
	{"NEWLY_ADDED_START_READING_KEYINFO", CM_NEWLY_ADDED_START_READING_KEYINFO},
	{"NEWLY_ADDED_READING_KEYINFO", CM_NEWLY_ADDED_READING_KEYINFO},
	{"NEWLY_ADDED_NEED_KEYINFO_READ_PIN", CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN},
	{"NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN", CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN},
	{"NEWLY_ADDED_START_READING_CERT", CM_NEWLY_ADDED_START_READING_CERT},
	{"NEWLY_ADDED_READING_CERT", CM_NEWLY_ADDED_READING_CERT},
	{"NEWLY_ADDED_DECIDING", CM_NEWLY_ADDED_DECIDING},
	/* old names */
	{"NEED_TO_NOTIFY", CM_NEED_TO_NOTIFY_VALIDITY},
	{"NOTIFYING", CM_NOTIFYING_VALIDITY},
	{"NEWLY_ADDED_START_READING_KEYI", CM_NEWLY_ADDED_START_READING_KEYINFO},
	{"NEWLY_ADDED_READING_KEYI", CM_NEWLY_ADDED_READING_KEYINFO},
	{"NEWLY_ADDED_NEED_KEYI_READ_PIN", CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN},
};

char *
cm_store_maybe_strdup(void *parent, const char *s)
{
	if ((s != NULL) && (strlen(s) > 0)) {
		return talloc_strdup(parent, s);
	}
	return NULL;
}

char **
cm_store_maybe_strdupv(void *parent, char **s)
{
	int i;
	char **ret = NULL;
	for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
		continue;
	}
	if (i > 0) {
		ret = talloc_array_ptrtype(parent, ret, i + 1);
		if (ret != NULL) {
			for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
				ret[i] = talloc_strdup(ret, s[i]);
			}
			ret[i] = NULL;
		}
	}
	return ret;
}

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
	return "UNKNOWN";
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

struct cm_store_ca *
cm_store_ca_new(void *parent)
{
	struct cm_store_ca *ca;
	ca = talloc_ptrtype(parent, ca);
	if (ca != NULL) {
		memset(ca, 0, sizeof(*ca));
	}
	return ca;
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

char *
cm_store_timestamp_from_time_for_display(time_t when, char timestamp[21])
{
	struct tm tm;
	if ((when != 0) && (gmtime_r(&when, &tm) == &tm)) {
		sprintf(timestamp, "%04d-%02d-%02d %02d:%02d:%02d UTC",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	} else {
		strcpy(timestamp, "19700101000000");
	}
	return timestamp;
}

char *
cm_store_increment_serial(void *parent, const char *old_serial)
{
	char *tmp, *serial;
	int len, i;
	if ((old_serial == NULL) || (strlen(old_serial) < 2)) {
		return talloc_strdup(parent, "01");
	}
	tmp = talloc_strdup(parent, old_serial);
	len = strlen(tmp);
	for (i = len - 1; i >= 0; i--) {
		switch (tmp[i]) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
			tmp[i]++;
			break;
		case '9':
			tmp[i] = 'A';
			break;
		case 'F':
		case 'f':
			tmp[i] = '0';
			/* carry */
			continue;
			break;
		}
		/* stop */
		break;
	}
	if (i < 0) {
		/* ran out of digits, need to prepend another byte */
		serial = talloc_asprintf(parent, "01%s", tmp);
		talloc_free(tmp);
	} else {
		if (strchr("89abcdefABCDEF", tmp[0]) != NULL) {
			/* prepend a zero byte to keep it unsigned */
			serial = talloc_asprintf(parent, "00%s", tmp);
			talloc_free(tmp);
		} else {
			/* ok as is */
			serial = tmp;
		}
	}
	return serial;
}

/* Produce a hex representation of the binary data. */
char *
cm_store_hex_from_bin(void *parent, const unsigned char *serial, int length)
{
	const char *hexchars = "0123456789ABCDEF";
	char *ret;
	int i;
	ret = talloc_zero_size(parent, length * 2 + 1);
	for (i = 0; i < length; i++) {
		ret[i * 2] = hexchars[(serial[i] >> 4) & 0x0f];
		ret[i * 2 + 1] = hexchars[(serial[i]) & 0x0f];
	}
	ret[i * 2] = '\0';
	return ret;
}

/* Produce a hex representation of the hex serial number encoded as a DER
 * integer. XXX has an upper limit on the length. */
char *
cm_store_serial_to_der(void *parent, const char *serial)
{
	const char *hexchars = "0123456789ABCDEF";
	char *ret;
	int length;
	length = strlen(serial);
	ret = talloc_zero_size(parent, length + 5);
	ret[0] = '0';
	ret[1] = '2';
	ret[2] = hexchars[((length / 2) >> 4) & 0x0f];
	ret[3] = hexchars[(length / 2) & 0x0f];
	strcpy(ret + 4, serial);
	return ret;
}

/* Convert hex chars to fill a buffer.  Input characters which don't belong are
 * treated as zeros.  We stop when we run out of input characters or run out of
 * space in the output buffer. */
void
cm_store_hex_to_bin(const char *serial, unsigned char *buf, int length)
{
	const char *p, *q, *chars = "0123456789abcdef";
	unsigned char *b, u;
	p = serial;
	b = buf;
	u = 0;
	for (p = serial, b = buf;
	     ((*p != '\0') && ((b - buf) < length));
	     p++) {
		switch ((p - serial) % 2) {
		case 0:
			q = strchr(chars, tolower(*p));
			if (q == NULL) {
				q = strchr(chars, toupper(*p));
			}
			u = q ? q - chars : 0;
			break;
		case 1:
			q = strchr(chars, tolower(*p));
			if (q == NULL) {
				q = strchr(chars, toupper(*p));
			}
			u = (u << 4) | (q ? q - chars : 0);
			*b++ = u;
			break;
		}
	}
}

char *
cm_store_canonicalize_directory(void *parent, const char *path)
{
	char *tmp, *p;
	int i;
	i = strlen(path);
	if (i > 1) {
		while ((i > 1) && (path[i - 1] == '/')) {
			i--;
		}
		tmp = talloc_strndup(parent, path, i);
	} else {
		tmp = talloc_strdup(parent, path);
	}
	while ((p = strstr(tmp, "/./")) != NULL) {
		memmove(p, p + 2, strlen(p) - 1);
	}
	while ((p = strstr(tmp, "//")) != NULL) {
		memmove(p, p + 1, strlen(p));
	}
	return tmp;
}

void
cm_store_set_if_not_set_s(void *parent, char **dest, char *src)
{
	if ((*dest == NULL) && (src != NULL) && (strlen(src) > 0)) {
		*dest = talloc_strdup(parent, src);
	}
}

void
cm_store_set_if_not_set_as(void *parent, char ***dest, char **src)
{
	int i, j;
	char **ret;
	if (*dest == NULL) {
		for (i = 0; (src != NULL) && (src[i] != NULL); i++) {
			continue;
		}
		if (i > 0) {
			ret = talloc_zero_size(parent,
					       sizeof(char *) * (i + 1));
			if (ret != NULL) {
				for (j = 0; j < i; j++) {
					ret[j] = talloc_strdup(ret, src[j]);
					if (ret[j] == NULL) {
						/* Out of space? */
						break;
					}
				}
				ret[j] = NULL;
				if (i != j) {
					/* Out of space? */
					ret = NULL;
				}
			}
			*dest = ret;
		}
	}
}
