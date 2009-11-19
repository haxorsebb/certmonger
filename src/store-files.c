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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <dbus/dbus.h>
#include <talloc.h>

#include "store.h"
#include "store-int.h"
#include "log.h"

enum cm_store_file_field {
	cm_store_file_field_invalid = 0,
	cm_store_file_field_id,

	cm_store_entry_field_key_type_default,
	cm_store_entry_field_key_type,
	cm_store_entry_field_key_gen_type,
	cm_store_entry_field_key_size,
	cm_store_entry_field_key_gen_size,

	cm_store_entry_field_key_storage_type,
	cm_store_entry_field_key_storage_location,
	cm_store_entry_field_key_token,
	cm_store_entry_field_key_nickname,

	cm_store_entry_field_cert_storage_type,
	cm_store_entry_field_cert_storage_location,
	cm_store_entry_field_cert_token,
	cm_store_entry_field_cert_nickname,

	cm_store_entry_field_cert_issuer,
	cm_store_entry_field_cert_serial,
	cm_store_entry_field_cert_subject,
	cm_store_entry_field_cert_spki,
	cm_store_entry_field_cert_expiration,
	cm_store_entry_field_cert_hostname,
	cm_store_entry_field_cert_email,
	cm_store_entry_field_cert_principal,
	cm_store_entry_field_cert_ku,
	cm_store_entry_field_cert_eku,

	cm_store_entry_field_ttls_default,
	cm_store_entry_field_ttls,
	cm_store_entry_field_last_expiration_check,

	cm_store_entry_field_notification_default,
	cm_store_entry_field_notification_method,
	cm_store_entry_field_notification_destination,

	cm_store_entry_field_template_subject,
	cm_store_entry_field_template_hostname,
	cm_store_entry_field_template_email,
	cm_store_entry_field_template_principal,
	cm_store_entry_field_template_ku,
	cm_store_entry_field_template_eku,

	cm_store_entry_field_csr,
	cm_store_entry_field_state,

	cm_store_entry_field_autorenew_default,
	cm_store_entry_field_autorenew,
	cm_store_entry_field_monitor_default,
	cm_store_entry_field_monitor,

	cm_store_entry_field_ca_default,
	cm_store_entry_field_ca_name,

	cm_store_entry_field_submitted,
	cm_store_entry_field_ca_cookie,

	cm_store_entry_field_cert,

	cm_store_ca_field_known_issuer_names,
	cm_store_ca_field_is_default,

	cm_store_ca_field_type,
	cm_store_ca_field_internal_serial,
	cm_store_ca_field_internal_lifetime,
	cm_store_ca_field_internal_issue_time,
	cm_store_ca_field_external_helper,

	cm_store_file_field_invalid_high,
};
static struct cm_store_file_field_list {
	enum cm_store_file_field field;
	const char *name;
} cm_store_file_field_list[] = {
	{cm_store_file_field_id, "id"},
	{cm_store_entry_field_key_type_default, "key_type_default"},
	{cm_store_entry_field_key_type, "key_type"},
	{cm_store_entry_field_key_gen_type, "key_gen_type"},
	{cm_store_entry_field_key_size, "key_size"},
	{cm_store_entry_field_key_gen_size, "key_gen_size"},

	{cm_store_entry_field_key_storage_type, "key_storage_type"},
	{cm_store_entry_field_key_storage_location, "key_storage_location"},
	{cm_store_entry_field_key_token, "key_token"},
	{cm_store_entry_field_key_nickname, "key_nickname"},

	{cm_store_entry_field_cert_storage_type, "cert_storage_type"},
	{cm_store_entry_field_cert_storage_location, "cert_storage_location"},
	{cm_store_entry_field_cert_token, "cert_token"},
	{cm_store_entry_field_cert_nickname, "cert_nickname"},

	{cm_store_entry_field_cert_issuer, "cert_issuer"},
	{cm_store_entry_field_cert_serial, "cert_serial"},
	{cm_store_entry_field_cert_subject, "cert_subject"},
	{cm_store_entry_field_cert_spki, "cert_spki"},
	{cm_store_entry_field_cert_expiration, "cert_expiration"},
	{cm_store_entry_field_cert_hostname, "cert_hostname"},
	{cm_store_entry_field_cert_email, "cert_email"},
	{cm_store_entry_field_cert_principal, "cert_principal"},
	{cm_store_entry_field_cert_ku, "cert_ku"},
	{cm_store_entry_field_cert_eku, "cert_eku"},

	{cm_store_entry_field_ttls_default, "ttls_default"},
	{cm_store_entry_field_ttls, "ttls"},
	{cm_store_entry_field_last_expiration_check, "last_expiration_check"},

	{cm_store_entry_field_notification_default, "notification_default"},
	{cm_store_entry_field_notification_method, "notification_method"},
	{cm_store_entry_field_notification_destination,
	 "notification_destination"},

	{cm_store_entry_field_template_subject, "template_subject"},
	{cm_store_entry_field_template_hostname, "template_hostname"},
	{cm_store_entry_field_template_email, "template_email"},
	{cm_store_entry_field_template_principal, "template_principal"},
	{cm_store_entry_field_template_ku, "template_ku"},
	{cm_store_entry_field_template_eku, "template_eku"},

	{cm_store_entry_field_csr, "csr"},
	{cm_store_entry_field_state, "state"},

	{cm_store_entry_field_autorenew_default, "autorenew_default"},
	{cm_store_entry_field_autorenew, "autorenew"},
	{cm_store_entry_field_monitor_default, "monitor_default"},
	{cm_store_entry_field_monitor, "monitor"},

	{cm_store_entry_field_ca_default, "ca_default"},
	{cm_store_entry_field_ca_name, "ca_name"},

	{cm_store_entry_field_submitted, "submitted"},
	{cm_store_entry_field_ca_cookie, "ca_cookie"},

	{cm_store_entry_field_cert, "cert"},

	{cm_store_ca_field_known_issuer_names, "ca_issuer_names"},
	{cm_store_ca_field_is_default, "ca_is_default"},

	{cm_store_ca_field_type, "ca_type"},
	{cm_store_ca_field_internal_serial, "ca_internal_serial"},
	{cm_store_ca_field_internal_lifetime, "ca_internal_lifetime"},
	{cm_store_ca_field_internal_issue_time, "ca_internal_issue_time"},
	{cm_store_ca_field_external_helper, "ca_external_helper"},
};

static enum cm_store_file_field
cm_store_file_field_of_line(char *p)
{
	unsigned int i, len;
	struct cm_store_file_field_list *entry;
	for (i = 0;
	     i < sizeof(cm_store_file_field_list) /
		 sizeof(cm_store_file_field_list[0]);
	     i++) {
		entry = &cm_store_file_field_list[i];
		len = strlen(entry->name);
		if (strcspn(p, "\r\n") < len) {
			continue;
		}
		if ((strncasecmp(p, entry->name, len) == 0) &&
		    (p[len] == '=')) {
			memmove(p, p + len + 1, strlen(p + len));
			return entry->field;
		}
	}
	return cm_store_file_field_invalid_high;
}

static const char *
cm_store_file_line_of_field(enum cm_store_file_field field)
{
	unsigned int i;
	struct cm_store_file_field_list *entry;
	for (i = 0;
	     i < sizeof(cm_store_file_field_list) /
		 sizeof(cm_store_file_field_list[0]);
	     i++) {
		entry = &cm_store_file_field_list[i];
		if (entry->field == field) {
			return entry->name;
		}
	}
	return NULL;
}

static dbus_bool_t
cm_store_should_ignore_file(const char *filename)
{
	const char *ignore[] = {".tmp",
				".rpmsave", ".rpmorig", ".rpmnew",
				"~", "#"};
	unsigned int i, len, ilen;
	len = strlen(filename);
	for (i = 0; i < sizeof(ignore) / sizeof(ignore[0]); i++) {
		ilen = strlen(ignore[i]);
		if ((len > ilen) &&
		    (strcmp(filename + len - ilen, ignore[i]) == 0)) {
			return TRUE;
		}
	}
	return FALSE;
}

static char **
cm_store_file_read_lines(void *parent, FILE *fp)
{
	char buf[LINE_MAX], *s, *t, **lines, **tlines;
	int n_lines, trim, offset;
	s = NULL;
	lines = NULL;
	n_lines = 0;
	trim = 1;
	while (fgets(buf, sizeof(buf), fp) == buf) {
		offset = 0;
		switch (buf[0]) {
		case '=':
			offset = 1;
			/* fall through */
		default:
			/* If we've already been reading a line, append it to
			 * the list. */
			if (s != NULL) {
				tlines = talloc_realloc(parent, lines,
							char *, n_lines + 2);
				if (tlines != NULL) {
					if (trim) {
						s[strcspn(s, "\r\n")] = '\0';
					}
					talloc_steal(tlines, s);
					tlines[n_lines++] = s;
					tlines[n_lines] = NULL;
					lines = tlines;
				}
			}
			/* Store this line's data, and default to trimming off
			 * end-of-line markers. */
			trim = 1;
			s = talloc_strdup(parent, buf + offset);
			break;
		case ' ':
			/* Since this is a multi-line item, refrain from
			 * trimming off any end-of-line characters, and just
			 * append it to the list of things we've read. */
			trim = 0;
			t = talloc_strdup_append(s, buf + 1);
			if (t != NULL) {
				s = t;
			}
			break;
		case '#':
		case ';':
			break;
		}
	}
	/* If we were reading a line, append it to the list. */
	if (s != NULL) {
		tlines = talloc_realloc(parent, lines, char *, n_lines + 2);
		if (tlines != NULL) {
			if (trim) {
				s[strcspn(s, "\r\n")] = '\0';
			}
			talloc_steal(tlines, s);
			tlines[n_lines++] = s;
			tlines[n_lines] = NULL;
			lines = tlines;
		}
	}
	return lines;
}

static char *
free_if_empty(char *s)
{
	if ((s != NULL) && (strlen(s) == 0)) {
		talloc_free(s);
		s = NULL;
	}
	return s;
}

static char **
free_if_empty_multi(void *parent, char *p)
{
	char **s;
	int i, j, k;
	if ((p != NULL) && (strlen(p) == 0)) {
		talloc_free(p);
		p = NULL;
		return NULL;
	}
	s = talloc_zero_array(parent, char *, strlen(p) + 2);
	i = 0;
	while (*p != '\0') {
		s[i] = talloc_strdup(parent, p);
		j = 0;
		k = 0;
		while ((p[j] != ',') && (p[j] != '\0')) {
			switch (p[j]) {
			case '\\':
				j++;
				memmove(s[i] + k, p + j,
					strlen(p + j));
				break;
			default:
				break;
			}
			j++;
			k++;
		}
		s[i][k] = '\0';
		i++;
		if (p[j] == '\0') {
			break;
		} else {
			p += (j + 1);
		}
	}
	s[i] = NULL;
	return s;
}

static struct cm_store_entry *
cm_store_entry_read(void *parent, const char *filename, FILE *fp)
{
	struct cm_store_entry *ret;
	char **s, *p;
	int i, j;
	enum cm_store_file_field field;
	ret = talloc_ptrtype(parent, ret);
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		s = cm_store_file_read_lines(ret, fp);
		ret->cm_store_private = talloc_strdup(ret, filename);
		for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
			p = s[i];
			field = cm_store_file_field_of_line(p);
			switch (field) {
			case cm_store_file_field_invalid:
			case cm_store_file_field_invalid_high:
				break;
			case cm_store_ca_field_known_issuer_names:
			case cm_store_ca_field_is_default:
			case cm_store_ca_field_type:
			case cm_store_ca_field_internal_serial:
			case cm_store_ca_field_internal_lifetime:
			case cm_store_ca_field_internal_issue_time:
			case cm_store_ca_field_external_helper:
				break;
			case cm_store_file_field_id:
				ret->cm_id = free_if_empty(p);
				break;
			case cm_store_entry_field_key_type_default:
				ret->cm_key_type_default = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_type:
				if (strcasecmp(s[i], "RSA") == 0) {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_rsa;
				} else {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_rsa;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_gen_type:
				if (strcasecmp(s[i], "RSA") == 0) {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_rsa;
				} else {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_rsa;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_size:
				ret->cm_key_type.cm_key_size = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_gen_size:
				ret->cm_key_type.cm_key_gen_size = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_storage_type:
				if (strcasecmp(p, "FILE") == 0) {
					ret->cm_key_storage_type =
						cm_key_storage_file;
				} else
				if (strcasecmp(p, "NSSDB") == 0) {
					ret->cm_key_storage_type =
						cm_key_storage_nssdb;
				} else
				if (strcasecmp(p, "NONE") == 0) {
					ret->cm_key_storage_type =
						cm_key_storage_none;
				} else {
					ret->cm_key_storage_type =
						cm_key_storage_none;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_storage_location:
				ret->cm_key_storage_location = free_if_empty(p);
				break;
			case cm_store_entry_field_key_token:
				ret->cm_key_token = free_if_empty(p);
				break;
			case cm_store_entry_field_key_nickname:
				ret->cm_key_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_storage_type:
				if (strcasecmp(p, "FILE") == 0) {
					ret->cm_cert_storage_type =
						cm_cert_storage_file;
				} else
				if (strcasecmp(p, "NSSDB") == 0) {
					ret->cm_cert_storage_type =
						cm_cert_storage_nssdb;
				} else {
					ret->cm_cert_storage_type =
						cm_cert_storage_file;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_storage_location:
				ret->cm_cert_storage_location = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_token:
				ret->cm_cert_token = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_nickname:
				ret->cm_cert_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_issuer:
				ret->cm_cert_issuer = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_serial:
				ret->cm_cert_serial = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_subject:
				ret->cm_cert_subject = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_spki:
				ret->cm_cert_spki = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_expiration:
				ret->cm_cert_expiration =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_hostname:
				ret->cm_cert_hostname =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_email:
				ret->cm_cert_email =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_principal:
				ret->cm_cert_principal =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_ku:
				ret->cm_cert_ku = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_eku:
				ret->cm_cert_eku = free_if_empty(p);
				break;
			case cm_store_entry_field_ttls_default:
				ret->cm_ttls_default = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_ttls:
				ret->cm_ttls = talloc_array_ptrtype(ret,
								    ret->cm_ttls,
								    strlen(p));
				if (ret->cm_ttls != NULL) {
					j = 0;
					while (strspn(p, "0123456789") > 0) {
						ret->cm_ttls[j] = strtol(p, &p, 10);
						p += strcspn(p, "0123456789");
						j++;
					}
					ret->cm_n_ttls = j;
				}
				talloc_free(s[i]);
				break;
			case cm_store_entry_field_last_expiration_check:
				ret->cm_last_expiration_check =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_notification_default:
				ret->cm_notification_default = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_notification_method:
				if (strcasecmp(p, "STDOUT") == 0) {
					ret->cm_notification_method = cm_notification_stdout;
				} else
				if (strcasecmp(p, "SYSLOG") == 0) {
					ret->cm_notification_method = cm_notification_syslog;
				} else
				if (strcasecmp(p, "EMAIL") == 0) {
					ret->cm_notification_method = cm_notification_email;
				} else {
					ret->cm_notification_method = cm_notification_syslog;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_notification_destination:
				ret->cm_notification_destination =
					free_if_empty(p);
				break;
			case cm_store_entry_field_template_subject:
				ret->cm_template_subject = free_if_empty(p);
				break;
			case cm_store_entry_field_template_hostname:
				ret->cm_template_hostname =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_email:
				ret->cm_template_email =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_principal:
				ret->cm_template_principal =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_ku:
				ret->cm_template_ku = free_if_empty(p);
				break;
			case cm_store_entry_field_template_eku:
				ret->cm_template_eku = free_if_empty(p);
				break;
			case cm_store_entry_field_csr:
				ret->cm_csr = free_if_empty(p);
				break;
			case cm_store_entry_field_state:
				ret->cm_state = cm_store_state_from_string(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_autorenew_default:
				ret->cm_autorenew_default = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_autorenew:
				ret->cm_autorenew = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_monitor_default:
				ret->cm_monitor_default = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_monitor:
				ret->cm_monitor = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_ca_default:
				ret->cm_ca_default = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_ca_name:
				ret->cm_ca_name = free_if_empty(p);
				break;
			case cm_store_entry_field_submitted:
				ret->cm_submitted =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_ca_cookie:
				ret->cm_ca_cookie = free_if_empty(p);
				break;
			case cm_store_entry_field_cert:
				ret->cm_cert = free_if_empty(p);
				break;
			}
		}
	}
	return ret;
}

struct cm_store_entry *
cm_store_files_entry_read(void *parent, const char *filename)
{
	FILE *fp;
	struct cm_store_entry *ret;
	fp = fopen(filename, "r");
	if (fp != NULL) {
		ret = cm_store_entry_read(parent, filename, fp);
		fclose(fp);
	} else {
		ret = NULL;
	}
	return ret;
}

static struct cm_store_ca *
cm_store_ca_read(void *parent, const char *filename, FILE *fp)
{
	struct cm_store_ca *ret;
	char **s, *p;
	int i;
	enum cm_store_file_field field;
	ret = talloc_ptrtype(parent, ret);
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		s = cm_store_file_read_lines(ret, fp);
		ret->cm_store_private = talloc_strdup(ret, filename);
		for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
			p = s[i];
			field = cm_store_file_field_of_line(p);
			switch (field) {
			case cm_store_file_field_invalid:
			case cm_store_file_field_invalid_high:
				break;
			case cm_store_entry_field_key_type_default:
			case cm_store_entry_field_key_type:
			case cm_store_entry_field_key_gen_type:
			case cm_store_entry_field_key_size:
			case cm_store_entry_field_key_gen_size:
			case cm_store_entry_field_key_storage_type:
			case cm_store_entry_field_key_storage_location:
			case cm_store_entry_field_key_token:
			case cm_store_entry_field_key_nickname:
			case cm_store_entry_field_cert_storage_type:
			case cm_store_entry_field_cert_storage_location:
			case cm_store_entry_field_cert_token:
			case cm_store_entry_field_cert_nickname:
			case cm_store_entry_field_cert_issuer:
			case cm_store_entry_field_cert_serial:
			case cm_store_entry_field_cert_subject:
			case cm_store_entry_field_cert_spki:
			case cm_store_entry_field_cert_expiration:
			case cm_store_entry_field_cert_hostname:
			case cm_store_entry_field_cert_email:
			case cm_store_entry_field_cert_principal:
			case cm_store_entry_field_cert_ku:
			case cm_store_entry_field_cert_eku:
			case cm_store_entry_field_ttls_default:
			case cm_store_entry_field_ttls:
			case cm_store_entry_field_last_expiration_check:
			case cm_store_entry_field_notification_default:
			case cm_store_entry_field_notification_method:
			case cm_store_entry_field_notification_destination:
			case cm_store_entry_field_template_subject:
			case cm_store_entry_field_template_hostname:
			case cm_store_entry_field_template_email:
			case cm_store_entry_field_template_principal:
			case cm_store_entry_field_template_ku:
			case cm_store_entry_field_template_eku:
			case cm_store_entry_field_csr:
			case cm_store_entry_field_state:
			case cm_store_entry_field_autorenew_default:
			case cm_store_entry_field_autorenew:
			case cm_store_entry_field_monitor_default:
			case cm_store_entry_field_monitor:
			case cm_store_entry_field_ca_default:
			case cm_store_entry_field_ca_name:
			case cm_store_entry_field_submitted:
			case cm_store_entry_field_ca_cookie:
			case cm_store_entry_field_cert:
				break;
			case cm_store_file_field_id:
				ret->cm_id = free_if_empty(p);
				break;
			case cm_store_ca_field_known_issuer_names:
				ret->cm_ca_known_issuer_names =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_is_default:
				ret->cm_ca_is_default = atoi(p);
				talloc_free(p);
				break;
			case cm_store_ca_field_type:
				if (strcasecmp(p, "EXTERNAL") == 0) {
					ret->cm_ca_type = cm_ca_external;
				} else
				if (strcasecmp(p, "INTERNAL:SELF") == 0) {
					ret->cm_ca_type = cm_ca_internal_self;
				} else {
					ret->cm_ca_type = cm_ca_external;
				}
				talloc_free(p);
				break;
			case cm_store_ca_field_internal_serial:
				ret->cm_ca_internal_serial = free_if_empty(p);
				break;
			case cm_store_ca_field_internal_lifetime:
				ret->cm_ca_internal_lifetime = free_if_empty(p);
				break;
			case cm_store_ca_field_internal_issue_time:
				ret->cm_ca_internal_force_issue_time = 1;
				ret->cm_ca_internal_issue_time = atol(p);
				talloc_free(p);
				break;
			case cm_store_ca_field_external_helper:
				ret->cm_ca_external_helper = free_if_empty(p);
				break;
			}
		}
	}
	if (ret->cm_ca_internal_serial == NULL) {
		ret->cm_ca_internal_serial = talloc_strdup(ret, CM_DEFAULT_CERT_SERIAL);
	}
	if (ret->cm_ca_internal_lifetime == NULL) {
		ret->cm_ca_internal_lifetime = talloc_strdup(ret, CM_DEFAULT_CERT_LIFETIME);
	}
	return ret;
}

struct cm_store_ca *
cm_store_files_ca_read(void *parent, const char *filename)
{
	FILE *fp;
	struct cm_store_ca *ret;
	fp = fopen(filename, "r");
	if (fp != NULL) {
		ret = cm_store_ca_read(parent, filename, fp);
		fclose(fp);
	} else {
		ret = NULL;
	}
	return ret;
}

static int
cm_store_file_write_int(FILE *fp, enum cm_store_file_field field, long value)
{
	fprintf(fp, "%s=%ld\n", cm_store_file_line_of_field(field), value);
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write_ints(FILE *fp, enum cm_store_file_field field,
			 int n, int *values)
{
	int i;
	if ((n == 0) && (values == NULL)) {
		return 0;
	}
	fprintf(fp, "%s=", cm_store_file_line_of_field(field));
	if (ferror(fp)) {
		return -1;
	}
	for (i = 0; i < n; i++) {
		fprintf(fp, "%s%d", (i > 0) ? " " : "", values[i]);
		if (ferror(fp)) {
			return -1;
		}
	}
	fprintf(fp, "\n");
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write_longs(FILE *fp, enum cm_store_file_field field,
			  int n, long *values)
{
	int i;
	if ((n == 0) && (values == NULL)) {
		return 0;
	}
	fprintf(fp, "%s=", cm_store_file_line_of_field(field));
	if (ferror(fp)) {
		return -1;
	}
	for (i = 0; i < n; i++) {
		fprintf(fp, "%s%ld", (i > 0) ? " " : "", values[i]);
		if (ferror(fp)) {
			return -1;
		}
	}
	fprintf(fp, "\n");
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write_str(FILE *fp, enum cm_store_file_field field, const char *s)
{
	const char *p, *q;
	if ((s == NULL) || (s[0] == '\0')) {
		return 0;
	}
	p = s ?: "";
	q = p + strcspn(p, "\r\n");
	fprintf(fp, "%s=%.*s\n", cm_store_file_line_of_field(field),
		(int) (q - p), p);
	p = q + strspn(q, "\r\n");
	while (*p != '\0') {
		q = p + strcspn(p, "\r\n");
		fprintf(fp, " %.*s\n", (int) (q - p), p);
		p = q + strspn(q, "\r\n");
	}
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write_strs(FILE *fp, enum cm_store_file_field field, char **s)
{
	int i, j;
	if ((s == NULL) || (s[0] == NULL)) {
		return 0;
	}
	fprintf(fp, "%s=", cm_store_file_line_of_field(field));
	for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
		if (i > 0) {
			fputc(',', fp);
		}
		for (j = 0; s[i][j] != '\0'; j++) {
			switch (s[i][j]) {
			case '\\':
			case ',':
				fputc('\\', fp);
				/* fall through */
			default:
				fputc(s[i][j], fp);
				break;
			}
		}
		if (ferror(fp)) {
			return -1;
		}
	}
	fprintf(fp, "\n");
	return 0;
}

static int
cm_store_entry_write(FILE *fp, struct cm_store_entry *entry)
{
	char timestamp[15];
	const char *p;

	if (entry->cm_id == NULL) {
		p = cm_store_timestamp_from_time(time(NULL), timestamp);
	} else {
		p = entry->cm_id;
	}
	cm_store_file_write_str(fp, cm_store_file_field_id, p);

	cm_store_file_write_int(fp, cm_store_entry_field_key_type_default,
				 entry->cm_key_type_default);
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_rsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"RSA");
		break;
	}
	switch (entry->cm_key_type.cm_key_gen_algorithm) {
	case cm_key_rsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"RSA");
		break;
	}
	cm_store_file_write_int(fp, cm_store_entry_field_key_size,
				entry->cm_key_type.cm_key_size);
	cm_store_file_write_int(fp, cm_store_entry_field_key_gen_size,
				entry->cm_key_type.cm_key_gen_size);

	switch (entry->cm_key_storage_type) {
	case cm_key_storage_file:
		cm_store_file_write_str(fp,
					cm_store_entry_field_key_storage_type,
					"FILE");
		break;
	case cm_key_storage_nssdb:
		cm_store_file_write_str(fp,
					cm_store_entry_field_key_storage_type,
					"NSSDB");
		break;
	case cm_key_storage_none:
		cm_store_file_write_str(fp,
					cm_store_entry_field_key_storage_type,
					"NONE");
		break;
	}
	cm_store_file_write_str(fp, cm_store_entry_field_key_storage_location,
				entry->cm_key_storage_location);
	cm_store_file_write_str(fp, cm_store_entry_field_key_token,
				entry->cm_key_token);
	cm_store_file_write_str(fp, cm_store_entry_field_key_nickname,
				entry->cm_key_nickname);

	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		cm_store_file_write_str(fp,
					cm_store_entry_field_cert_storage_type,
					"FILE");
		break;
	case cm_cert_storage_nssdb:
		cm_store_file_write_str(fp,
					cm_store_entry_field_cert_storage_type,
					"NSSDB");
		break;
	}
	cm_store_file_write_str(fp, cm_store_entry_field_cert_storage_location,
				entry->cm_cert_storage_location);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_token,
				entry->cm_cert_token);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_nickname,
				entry->cm_cert_nickname);

	cm_store_file_write_str(fp, cm_store_entry_field_cert_issuer,
				entry->cm_cert_issuer);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_serial,
				entry->cm_cert_serial);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_subject,
				entry->cm_cert_subject);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_spki,
				entry->cm_cert_spki);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_expiration,
				cm_store_timestamp_from_time(entry->cm_cert_expiration,
							     timestamp));
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_hostname,
				 entry->cm_cert_hostname);
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_email,
				 entry->cm_cert_email);
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_principal,
				 entry->cm_cert_principal);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_ku,
				entry->cm_cert_ku);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_eku,
				entry->cm_cert_eku);

	cm_store_file_write_int(fp, cm_store_entry_field_ttls_default,
				entry->cm_ttls_default);
	if (sizeof(entry->cm_ttls[0]) == sizeof(int)) {
		cm_store_file_write_ints(fp, cm_store_entry_field_ttls,
					 entry->cm_n_ttls,
					 (int *) entry->cm_ttls);
	} else
	if (sizeof(entry->cm_ttls[0]) == sizeof(long)) {
		cm_store_file_write_longs(fp, cm_store_entry_field_ttls,
					  entry->cm_n_ttls,
					  (long *) entry->cm_ttls);
	} else {
		/* not reached */
		cm_log(0, "time_t is not a known integer type\n");
		abort();
	}
	cm_store_file_write_str(fp, cm_store_entry_field_last_expiration_check,
				cm_store_timestamp_from_time(entry->cm_last_expiration_check,
							     timestamp));

	cm_store_file_write_int(fp, cm_store_entry_field_notification_default,
				entry->cm_notification_default);
	switch (entry->cm_notification_method) {
	case cm_notification_stdout:
		cm_store_file_write_str(fp,
					cm_store_entry_field_notification_method,
					"STDOUT");
		break;
	case cm_notification_syslog:
		cm_store_file_write_str(fp,
					cm_store_entry_field_notification_method,
					"SYSLOG");
		break;
	case cm_notification_email:
		cm_store_file_write_str(fp,
					cm_store_entry_field_notification_method,
					"EMAIL");
		break;
	}
	cm_store_file_write_str(fp,
				cm_store_entry_field_notification_destination,
				entry->cm_notification_destination);

	cm_store_file_write_str(fp, cm_store_entry_field_template_subject,
				entry->cm_template_subject);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_hostname,
				 entry->cm_template_hostname);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_email,
				 entry->cm_template_email);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_principal,
				 entry->cm_template_principal);
	cm_store_file_write_str(fp, cm_store_entry_field_template_ku,
				entry->cm_template_ku);
	cm_store_file_write_str(fp, cm_store_entry_field_template_eku,
				entry->cm_template_eku);

	cm_store_file_write_str(fp, cm_store_entry_field_csr, entry->cm_csr);

	cm_store_file_write_str(fp, cm_store_entry_field_state,
				cm_store_state_as_string(entry->cm_state));

	cm_store_file_write_int(fp, cm_store_entry_field_autorenew_default,
				entry->cm_autorenew_default);
	cm_store_file_write_int(fp, cm_store_entry_field_autorenew,
				entry->cm_autorenew);

	cm_store_file_write_int(fp, cm_store_entry_field_monitor_default,
				entry->cm_monitor_default);
	cm_store_file_write_int(fp, cm_store_entry_field_monitor,
				entry->cm_monitor);

	cm_store_file_write_int(fp, cm_store_entry_field_ca_default,
				entry->cm_ca_default);
	cm_store_file_write_str(fp, cm_store_entry_field_ca_name,
				entry->cm_ca_name);
	cm_store_file_write_str(fp, cm_store_entry_field_submitted,
				cm_store_timestamp_from_time(entry->cm_submitted,
							      timestamp));
	cm_store_file_write_str(fp, cm_store_entry_field_ca_cookie,
				entry->cm_ca_cookie);
	cm_store_file_write_str(fp, cm_store_entry_field_cert, entry->cm_cert);
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

int
cm_store_entry_delete(struct cm_store_entry *entry)
{
	int ret;
	const char *filename;

	if (entry->cm_store_private != NULL) {
		filename = (const char *) entry->cm_store_private;
		ret = remove(filename);
		if (ret == 0) {
			cm_log(3, "Removed file \"%s\".\n", filename);
			talloc_free(entry->cm_store_private);
			entry->cm_store_private = NULL;
		} else {
			cm_log(1, "Failed to remove file \"%s\": %s.\n",
			       filename, strerror(errno));
		}
	} else {
		cm_log(3, "No file to remove for \"%s\".\n",
		       entry->cm_id);
		ret = 0;
	}
	return 0;
}

static void
cm_store_create_containing_dir(const char *path, int mode)
{
	char dir[PATH_MAX];
	struct stat st;
	int i;
	if (strlen(path) >= sizeof(dir)) {
		return;
	}
	for (i = 0, dir[0] = '\0'; path[i] != '\0'; i++) {
		if ((i > 0) && (path[i] == '/')) { /* XXX */
			if ((stat(dir, &st) == -1) && (errno == ENOENT)) {
				if (mkdir(dir, mode) == -1) {
					cm_log(1, "Failed to create \"%s\": "
					       "%s.\n", dir, strerror(errno));
					break;
				}
				cm_log(2, "Created \"%s\".\n", dir);
			}
		}
		dir[i] = path[i];
		dir[i + 1] = '\0';
	}
}

int
cm_store_entry_save(struct cm_store_entry *entry)
{
	FILE *fp;
	char timestamp[15], path[PATH_MAX];
	int i, fd, give_up;
	const char *directory;

	if (entry->cm_store_private == NULL) {
		cm_store_timestamp_from_time(time(NULL), timestamp);
		directory = getenv(CM_STORE_REQUESTS_DIRECTORY_ENV);
		if ((directory == NULL) || (strlen(directory) == 0)) {
			directory = CM_STORE_REQUESTS_DIRECTORY;
		}
		snprintf(path, sizeof(path), "%s/%s", directory, timestamp);
		fd = open(path,
			  O_WRONLY | O_CREAT | O_EXCL,
			  S_IRUSR | S_IWUSR);
		if ((fd == -1) && (errno == ENOENT)) {
			cm_store_create_containing_dir(path, S_IRWXU);
			fd = open(path,
				  O_WRONLY | O_CREAT | O_EXCL,
				  S_IRUSR | S_IWUSR);
		}
		if (fd == -1) {
			switch (errno) {
			case ENOENT:
			case EPERM:
			case EACCES:
				break;
			default:
				for (give_up = 0, i = 1;
				     !give_up && (i < 1024);
				     i++) {
					snprintf(path, sizeof(path), "%s/%s-%d",
						 directory, timestamp, i);
					fd = open(path,
						  O_WRONLY | O_CREAT | O_EXCL,
						  S_IRUSR | S_IWUSR);
					if (fd != -1) {
						break;
					}
					switch (errno) {
					case ENOENT:
					case EPERM:
					case EACCES:
						give_up++;
						break;
					}
				}
				break;
			}
		}
		if (fd == -1) {
			return -1;
		}
		close(fd);
		entry->cm_store_private = talloc_strdup(entry, path);
	}

	snprintf(path, sizeof(path), "%s.tmp",
		 (const char *) entry->cm_store_private);
	fp = fopen(path, "w");
	if (fp != NULL) {
		if (cm_store_entry_write(fp, entry) == 0) {
			fclose(fp);
			rename(path, (const char *) entry->cm_store_private);
			return 0;
		} else {
			fclose(fp);
			remove(path);
			return -1;
		}
	} else {
		cm_log(1, "Error opening \"%s\" for writing: %s.\n",
		       path, strerror(errno));
		return -1;
	}
}

struct cm_store_entry *
cm_store_get_defaults(void)
{
	static struct cm_store_entry *defaults = NULL;
	const char *filename;
	FILE *fp;
	enum cm_notification_method method = CM_DEFAULT_NOTIFICATION_METHOD;
	const char *dest = NULL;

	switch (method) {
	case cm_notification_stdout:
		break;
	case cm_notification_syslog:
		dest = CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY;
		break;
	case cm_notification_email:
		dest = CM_DEFAULT_NOTIFICATION_MAIL;
		break;
	}

	if (defaults == NULL) {
		filename = getenv(CM_STORE_REQUEST_DEFAULTS_ENV);
		if ((filename == NULL) || (strlen(filename) == 0)) {
			filename = CM_STORE_REQUEST_DEFAULTS;
		}
		fp = fopen(filename, "r");
		if (fp != NULL) {
			defaults = cm_store_entry_read(talloc_new(NULL),
						       filename, fp);
		} else {
			defaults = talloc_ptrtype(NULL, defaults);
			if (defaults != NULL) {
				memset(defaults, 0, sizeof(*defaults));
				defaults->cm_notification_method = method;
				defaults->cm_notification_destination =
					talloc_strdup(defaults, dest);
			}
		}
	}
	return defaults;
}

struct cm_store_entry **
cm_store_get_all_entries(void *parent)
{
	struct cm_store_entry **ret;
	unsigned int i;
	int j, k;
	const char *directory;
	char path[PATH_MAX + 1], *p;
	FILE *fp;
	glob_t globs;

	directory = getenv(CM_STORE_REQUESTS_DIRECTORY_ENV);
	if ((directory == NULL) || (strlen(directory) == 0)) {
		directory = CM_STORE_REQUESTS_DIRECTORY;
	}
	snprintf(path, sizeof(path), "%s/*", directory);
	memset(&globs, 0, sizeof(globs));
	ret = NULL;
	if (glob(path, 0, NULL, &globs) == 0) {
		ret = talloc_array_ptrtype(parent, ret, globs.gl_pathc + 1);
		if (ret != NULL) {
			for (i = 0, j = 0; i < globs.gl_pathc; i++) {
				p = globs.gl_pathv[i];
				if (cm_store_should_ignore_file(p)) {
					continue;
				}
				fp = fopen(globs.gl_pathv[i], "r");
				if (fp != NULL) {
					ret[j] = cm_store_entry_read(ret,
								     globs.gl_pathv[i],
								     fp);
					if (ret[j] != NULL) {
						/* Check for duplicate names. */
						for (k = 0; k < j; k++) {
							if (strcmp(ret[k]->cm_id,
								   ret[j]->cm_id) == 0) {
								cm_store_entry_delete(ret[j]);
								talloc_free(ret[j]);
								ret[j] = NULL;
								break;
							}
						}
						if (k == j) {
							j++;
						}
					}
					fclose(fp);
				}
			}
			ret[j] = NULL;
		}
		globfree(&globs);
	}
	return ret;
}

static int
cm_store_ca_write(FILE *fp, struct cm_store_ca *ca)
{
	const char *p;
	char timestamp[15];

	if (ca->cm_id == NULL) {
		p = cm_store_timestamp_from_time(time(NULL), timestamp);
	} else {
		p = ca->cm_id;
	}
	cm_store_file_write_str(fp, cm_store_file_field_id, p);
	cm_store_file_write_strs(fp,
				 cm_store_ca_field_known_issuer_names,
				 ca->cm_ca_known_issuer_names);
	cm_store_file_write_int(fp, cm_store_ca_field_is_default,
				ca->cm_ca_is_default);
	switch (ca->cm_ca_type) {
	case cm_ca_internal_self:
		cm_store_file_write_str(fp, cm_store_ca_field_type,
					"INTERNAL:SELF");
		cm_store_file_write_str(fp, cm_store_ca_field_internal_serial,
					ca->cm_ca_internal_serial);
		cm_store_file_write_str(fp, cm_store_ca_field_internal_lifetime,
					ca->cm_ca_internal_lifetime);
		if (ca->cm_ca_internal_force_issue_time) {
			cm_store_file_write_int(fp, cm_store_ca_field_internal_issue_time,
						ca->cm_ca_internal_issue_time);
		}
		break;
	case cm_ca_external:
		cm_store_file_write_str(fp, cm_store_ca_field_type,
					"EXTERNAL");
		cm_store_file_write_str(fp, cm_store_ca_field_external_helper,
					ca->cm_ca_external_helper);
		break;
	}
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

int
cm_store_ca_delete(struct cm_store_ca *ca)
{
	int ret;
	const char *filename;

	if (ca->cm_store_private != NULL) {
		filename = (const char *) ca->cm_store_private;
		ret = remove(ca->cm_store_private);
		if (ret == 0) {
			cm_log(3, "Removed file \"%s\".\n", filename);
			talloc_free(ca->cm_store_private);
			ca->cm_store_private = NULL;
		} else {
			cm_log(1, "Failed to remove file \"%s\": %s.\n",
			       filename, strerror(errno));
		}
	} else {
		cm_log(3, "No file to remove for \"%s\".\n", ca->cm_id);
		ret = 0;
	}
	return 0;
}

int
cm_store_ca_save(struct cm_store_ca *ca)
{
	FILE *fp;
	char timestamp[15], path[PATH_MAX];
	int i, fd, give_up;
	const char *directory;

	if (ca->cm_store_private == NULL) {
		cm_store_timestamp_from_time(time(NULL), timestamp);
		directory = getenv(CM_STORE_CAS_DIRECTORY_ENV);
		if ((directory == NULL) || (strlen(directory) == 0)) {
			directory = CM_STORE_CAS_DIRECTORY;
		}
		snprintf(path, sizeof(path), "%s/%s", directory, timestamp);
		fd = open(path,
			  O_WRONLY | O_CREAT | O_EXCL,
			  S_IRUSR | S_IWUSR);
		if ((fd == -1) && (errno == ENOENT)) {
			cm_store_create_containing_dir(path, S_IRWXU);
			fd = open(path,
				  O_WRONLY | O_CREAT | O_EXCL,
				  S_IRUSR | S_IWUSR);
		}
		if (fd == -1) {
			switch (errno) {
			case ENOENT:
			case EPERM:
			case EACCES:
				break;
			default:
				for (give_up = 0, i = 1;
				     !give_up && (i < 1024);
				     i++) {
					snprintf(path, sizeof(path), "%s/%s-%d",
						 directory, timestamp, i);
					fd = open(path,
						  O_WRONLY | O_CREAT | O_EXCL,
						  S_IRUSR | S_IWUSR);
					if (fd != -1) {
						break;
					}
					switch (errno) {
					case ENOENT:
					case EPERM:
					case EACCES:
						give_up++;
						break;
					}
				}
				break;
			}
		}
		if (fd == -1) {
			return -1;
		}
		close(fd);
		ca->cm_store_private = talloc_strdup(ca, path);
	}

	snprintf(path, sizeof(path), "%s.tmp",
		 (const char *) ca->cm_store_private);
	fp = fopen(path, "w");
	if (fp != NULL) {
		if (cm_store_ca_write(fp, ca) == 0) {
			fclose(fp);
			rename(path, (const char *) ca->cm_store_private);
		} else {
			fclose(fp);
			remove(path);
		}
		return 0;
	} else {
		cm_log(1, "Error opening \"%s\" for writing: %s.\n", path,
		       strerror(errno));
		return -1;
	}
}

struct cm_store_ca **
cm_store_get_all_cas(void *parent)
{
	struct cm_store_ca **ret;
	unsigned int i;
	int j, k;
	const char *directory;
	char path[PATH_MAX + 1], *p;
	FILE *fp;
	glob_t globs;

	directory = getenv(CM_STORE_CAS_DIRECTORY_ENV);
	if ((directory == NULL) || (strlen(directory) == 0)) {
		directory = CM_STORE_CAS_DIRECTORY;
	}
	snprintf(path, sizeof(path), "%s/*", directory);
	memset(&globs, 0, sizeof(globs));
	ret = NULL;
	if (glob(path, 0, NULL, &globs) != 0) {
		globs.gl_pathc = 0;
	}
	ret = talloc_array_ptrtype(parent, ret, globs.gl_pathc + 3);
	if (ret != NULL) {
		for (i = 0, j = 0; i < globs.gl_pathc; i++) {
			p = globs.gl_pathv[i];
			if (cm_store_should_ignore_file(p)) {
				continue;
			}
			fp = fopen(globs.gl_pathv[i], "r");
			if (fp != NULL) {
				ret[j] = cm_store_ca_read(ret,
							  globs.gl_pathv[i],
							  fp);
				if (ret[j] != NULL) {
					/* Check for duplicate names. */
					for (k = 0; k < j; k++) {
						if (strcmp(ret[k]->cm_id,
							   ret[j]->cm_id) == 0) {
							cm_store_ca_delete(ret[j]);
							talloc_free(ret[j]);
							ret[j] = NULL;
							break;
						}
					}
					if (k == j) {
						j++;
					}
				}
				fclose(fp);
			}
		}
		/* Make sure we get at least one internal/self sign entry. */
		for (k = 0; k < j; k++) {
			if (ret[k]->cm_ca_type == cm_ca_internal_self) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_id = talloc_strdup(ret[j],
						      CM_SELF_SIGN_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_internal_self;
			ret[j]->cm_ca_internal_serial = talloc_strdup(ret[j],
								      CM_DEFAULT_CERT_SERIAL);
			ret[j]->cm_ca_internal_lifetime = talloc_strdup(ret[j],
									CM_DEFAULT_CERT_LIFETIME);
			j++;
		}
#ifdef WITH_IPA
		/* Make sure we get at least one IPA entry. */
		for (k = 0; k < j; k++) {
			if ((ret[k]->cm_ca_type == cm_ca_external) &&
			    (strcmp(ret[k]->cm_id, CM_IPA_CA_NAME) == 0)) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_id = talloc_strdup(ret[j], CM_IPA_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_external;
			ret[j]->cm_ca_external_helper = talloc_strdup(ret[j],
								      CM_IPA_HELPER_PATH);
			j++;
		}
#endif
		ret[j] = NULL;
	}
	if (globs.gl_pathc > 0) {
		globfree(&globs);
	}
	return ret;
}
