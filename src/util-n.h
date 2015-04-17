/*
 * Copyright (C) 2012,2015 Red Hat, Inc.
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

#ifndef utiln_h
#define utiln_h

struct cm_store_entry;

enum force_fips_mode { do_not_force_fips, do_force_fips };
void util_n_set_fips(enum force_fips_mode force);
const char *util_n_fips_hook(void);
char *util_build_next_nickname(const char *prefix, const char *marker);
char *util_build_old_nickname(const char *prefix, const char *serial);
void util_set_db_entry_key_owner(const char *dbdir,
				 struct cm_store_entry *entry);
void util_set_db_entry_cert_owner(const char *dbdir,
				  struct cm_store_entry *entry);

#endif
