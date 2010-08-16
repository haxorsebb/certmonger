/*
 * Copyright (C) 2009,2010 Red Hat, Inc.
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

#ifndef cmsubmitu_h
#define cmsubmitu_h

char *cm_submit_u_from_file(const char *filename);
char *cm_submit_u_from_file_single(const char *filename);
char *cm_submit_princ_realm_data(krb5_context ctx, krb5_principal princ);
int cm_submit_princ_realm_len(krb5_context ctx, krb5_principal princ);

#endif
