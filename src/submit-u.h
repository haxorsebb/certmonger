/*
 * Copyright (C) 2009,2010,2012 Red Hat, Inc.
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
char *cm_submit_u_base64_from_text(const char *base64_or_pem);
char *cm_submit_u_pem_from_base64(const char *what, int dos, const char *base64);
char *cm_submit_u_url_encode(const char *plain);

#ifdef HAVE_UUID
/* Generate UUIDs. */
int cm_submit_uuid_new(unsigned char uuid[16]);
extern int cm_submit_uuid_fixed_for_testing;
#endif

/* Convert a delta in string form to a time_t. */
int cm_submit_u_delta_from_string(const char *deltas, time_t now, time_t *delta);

#endif
