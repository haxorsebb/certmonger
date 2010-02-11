/*
 * Copyright (C) 2010 Red Hat, Inc.
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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>

#include <talloc.h>

#include "log.h"
#include "store-int.h"

enum cm_pin_type {
	cm_pin_key,
	cm_pin_cert,
};

static char *
cm_pin_read(struct cm_store_entry *entry, enum cm_pin_type pin_type)
{
	const char *pinfile, *pinvalue;
	char *pin;
	struct stat st;
	int fd, l;

	switch (pin_type) {
	case cm_pin_key:
		pinfile = entry->cm_key_pin_file;
		pinvalue = entry->cm_key_pin;
		break;
	case cm_pin_cert:
		pinfile = entry->cm_cert_pin_file;
		pinvalue = entry->cm_cert_pin;
		break;
	}

	pin = NULL;
	if ((pinfile != NULL) && (strlen(pinfile) > 0)) {
		fd = open(pinfile, O_RDONLY);
		if (fd != -1) {
			if ((fstat(fd, &st) == 0) && (st.st_size > 0)) {
				pin = talloc_zero_size(entry, st.st_size + 1);
				if (pin != NULL) {
					if (read(fd, pin, st.st_size) != -1) {
						l = strcspn(pin, "\r\n");
						if (l == 0) {
							talloc_free(pin);
							pin = NULL;
						} else {
							pin[l] = '\0';
						}
					} else {
						cm_log(1,
						       "Error reading \"%s\": "
						       "%s.\n",
						       pinfile,
						       strerror(errno));
						talloc_free(pin);
						pin = NULL;
					}
				}
			} else {
				cm_log(1, "Error determining size of \"%s\": "
				       "%s.\n",
				       pinfile, strerror(errno));
			}
			close(fd);
		} else {
			cm_log(1, "Error reading PIN from \"%s\": %s.\n",
			       pinfile, strerror(errno));
		}
	}
	if (pin == NULL) {
		if (pinvalue != NULL) {
			pin = talloc_strdup(entry, pinvalue);
		}
	}
	return pin;
}

char *
cm_pin_cb(PK11SlotInfo *slot, PRBool retry, void *arg,
	  enum cm_pin_type pin_type)
{
	struct cm_store_entry *entry;
	entry = arg;
	return cm_pin_read(entry, pin_type);
}

char *
cm_pin_read_key(struct cm_store_entry *entry)
{
	return cm_pin_read(entry, cm_pin_key);
}

char *
cm_pin_read_cert(struct cm_store_entry *entry)
{
	return cm_pin_read(entry, cm_pin_cert);
}

char *
cm_pin_cb_key(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	return cm_pin_cb(slot, retry, arg, cm_pin_key);
}

char *
cm_pin_cb_cert(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	return cm_pin_cb(slot, retry, arg, cm_pin_key);
}
