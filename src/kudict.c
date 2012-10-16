/*
 * Copyright (C) 2012 Red Hat, Inc.
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

#include <string.h>

#include "kudict.h"

static struct {
	int bit;
	const char *name;
} key_usage_dict[] = {
	{ .bit = 0, .name = "digitalSignature" },
	{ .bit = 1, .name = "nonRepudiation" },
	{ .bit = 1, .name = "contentCommitment" }, /* an alias */
	{ .bit = 2, .name = "keyEncipherment" },
	{ .bit = 3, .name = "dataEncipherment" },
	{ .bit = 4, .name = "keyAgreement" },
	{ .bit = 5, .name = "keyCertSign" },
	{ .bit = 6, .name = "cRLSign" },
	{ .bit = 7, .name = "encipherOnly" },
	{ .bit = 8, .name = "decipherOnly" },
};

int
cm_ku_n_names(void)
{
	return (int) (sizeof(key_usage_dict) / sizeof(key_usage_dict[0]));
}

const char *
cm_ku_to_name(int bit)
{
	int i;
	for (i = 0; i < cm_ku_n_names(); i++) {
		if (bit == key_usage_dict[i].bit) {
			return key_usage_dict[i].name;
		}
	}
	return NULL;
}

int
cm_ku_from_name(const char *name)
{
	int i;
	for (i = 0; i < cm_ku_n_names(); i++) {
		if (strcasecmp(name, key_usage_dict[i].name) == 0) {
			return key_usage_dict[i].bit;
		}
	}
	return -1;
}
