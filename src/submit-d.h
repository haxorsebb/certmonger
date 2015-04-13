/*
 * Copyright (C) 2010,2012,2015 Red Hat, Inc.
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

#ifndef cmsubmitd_h
#define cmsubmitd_h

int cm_submit_d_submit_result(void *parent, const char *xml,
			      char **error_code, char **error_reason,
			      char **error, char **status,
			      char **requestId, char **cert);
int cm_submit_d_check_result(void *parent, const char *xml,
			     char **error_code, char **error_reason,
			     char **error, char **status,
			     char **requestId);
int cm_submit_d_reject_result(void *parent, const char *xml,
			      char **error_code, char **error_reason,
			      char **error, char **status,
			      char **requestId);
int cm_submit_d_review_result(void *parent, const char *xml,
			      char **error_code, char **error_reason,
			      char **error, char **status,
			      char **requestId);
int cm_submit_d_approve_result(void *parent, const char *xml,
			       char **error_code, char **error_reason,
			       char **error, char **status,
			       char **requestId);
int cm_submit_d_fetch_result(void *parent, const char *xml,
			     char **error_code, char **error_reason,
			     char **error, char **status,
			     char **requestId, char **cert);
int cm_submit_d_profiles_result(void *parent, const char *xml,
				char **error_code, char **error_reason,
				char **error, char **status,
				char ***profiles);
enum cm_external_status cm_submit_d_submit_eval(void *parent, const char *xml,
						const char *url,
						dbus_bool_t can_agent,
						char **out, char **err);
enum cm_external_status cm_submit_d_check_eval(void *parent, const char *xml,
					       const char *url,
					       dbus_bool_t can_agent,
					       char **out, char **err);
enum cm_external_status cm_submit_d_reject_eval(void *parent, const char *xml,
						const char *url,
						dbus_bool_t can_agent,
						char **out, char **err);
enum cm_external_status cm_submit_d_review_eval(void *parent, const char *xml,
						const char *url,
						dbus_bool_t can_agent,
						char **out, char **err);
enum cm_external_status cm_submit_d_approve_eval(void *parent, const char *xml,
						 const char *url,
						 dbus_bool_t can_agent,
						 char **out, char **err);
enum cm_external_status cm_submit_d_fetch_eval(void *parent, const char *xml,
					       const char *url,
					       dbus_bool_t can_agent,
					       char **out, char **err);
enum cm_external_status cm_submit_d_profiles_eval(void *parent, const char *xml,
						  const char *url,
						  dbus_bool_t can_agent,
						  char **out, char **err);

struct dogtag_default {
	enum {
		dogtag_none,
		dogtag_boolean,
		dogtag_int,
		dogtag_choice,
		dogtag_string,
		dogtag_string_list,
		dogtag_unknown
	} syntax;
	char *name;
	char *value;
};
struct dogtag_default **cm_submit_d_xml_defaults(void *parent, const char *xml);

#endif
