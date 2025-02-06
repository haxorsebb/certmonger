/*
 * Copyright (C) 2024 Red Hat, Inc.
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

#ifndef util_ipa_h
#define util_ipa_h

#include <ldap.h>
#include <krb5.h>

char * get_error_message(krb5_context ctx, krb5_error_code kcode);
char * cm_submit_ccache_realm(char **msg);
krb5_error_code cm_submit_make_ccache(const char *ktname, const char *principal, char **msg);
int parse_json_result(const char *result, char **error_message);
#endif
