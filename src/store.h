/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#ifndef cmstore_h
#define cmstore_h

struct cm_store_entry;
struct cm_store_ca;

/* Generic routines. */
struct cm_store_entry *cm_store_entry_new(void *parent);
struct cm_store_ca *cm_store_ca_new(void *parent);

/* Store-specific entry storage. */
int cm_store_entry_save(struct cm_store_entry *entry);
int cm_store_entry_delete(struct cm_store_entry *entry);
struct cm_store_entry *cm_store_get_defaults(void);
struct cm_store_entry **cm_store_get_all_entries(void *parent);

/* Store-specific CA storage. */
int cm_store_ca_save(struct cm_store_ca *ca);
int cm_store_ca_delete(struct cm_store_ca *ca);
struct cm_store_ca **cm_store_get_all_cas(void *parent);

/* Utility functions. */
time_t cm_store_time_from_timestamp(const char *timestamp);
char *cm_store_timestamp_from_time(time_t when, char timestamp[15]);
char *cm_store_increment_serial(void *parent, const char *old_serial);
char *cm_store_serial_from_binary(void *parent,
				  const unsigned char *serial, int length);
char *cm_store_serial_to_binary(void *parent,
				const unsigned char *serial, int length);
char *cm_store_serial_to_der(void *parent,
			     const unsigned char *serial, int length);
void cm_store_hex_to_bin(const char *serial, unsigned char *buf, int length);

#endif
