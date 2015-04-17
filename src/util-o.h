/*
 * Copyright (C) 2010,2012,2014,2015 Red Hat, Inc.
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

#ifndef utilo_h
#define utilo_h

struct cm_store_entry;

void util_o_init(void);
char *util_build_next_filename(const char *prefix, const char *marker);
char *util_build_old_filename(const char *prefix, const char *serial);
void util_set_fd_owner_perms(int fd, const char *filename,
			     const char *owner, mode_t perms);
void util_set_fd_entry_key_owner(int keyfd, const char *filename,
				 struct cm_store_entry *entry);
void util_set_fd_entry_cert_owner(int certfd, const char *filename,
				  struct cm_store_entry *entry);

#endif
