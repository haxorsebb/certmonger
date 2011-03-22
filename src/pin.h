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

#ifndef cmpin_h
#define cmpin_h

#define CM_STATUS_ERROR_INITIALIZING	1
#define CM_STATUS_ERROR_INTERNAL	2
#define CM_STATUS_ERROR_NO_TOKEN	3
#define CM_STATUS_ERROR_AUTH		4

struct cm_store_entry;
int cm_pin_read_for_key_ossl_cb(char *buf, int size, int rwflag, void *u);
char *cm_pin_read_for_key(struct cm_store_entry *entry);
char *cm_pin_read_for_cert(struct cm_store_entry *entry);
char *cm_pin_read_for_key_nss_cb(PK11SlotInfo *slot, PRBool retry, void *arg);
char *cm_pin_read_for_cert_nss_cb(PK11SlotInfo *slot, PRBool retry, void *arg);

#endif
