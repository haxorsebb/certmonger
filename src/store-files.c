/*
 * Copyright (C) 2009,2010,2011,2012 Red Hat, Inc.
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

#include "env.h"
#include "store.h"
#include "store-int.h"
#include "submit-e.h"
#include "log.h"
#include "tm.h"

static unsigned long long cm_entry_name_last, cm_ca_name_last;

enum cm_store_file_field {
	cm_store_file_field_invalid = 0,
	cm_store_file_field_id,

	cm_store_entry_field_key_type,
	cm_store_entry_field_key_gen_type,
	cm_store_entry_field_key_size,
	cm_store_entry_field_key_gen_size,

	cm_store_entry_field_key_storage_type,
	cm_store_entry_field_key_storage_location,
	cm_store_entry_field_key_token,
	cm_store_entry_field_key_nickname,
	cm_store_entry_field_key_pin,
	cm_store_entry_field_key_pin_file,
	cm_store_entry_field_key_pubkey,

	cm_store_entry_field_cert_storage_type,
	cm_store_entry_field_cert_storage_location,
	cm_store_entry_field_cert_token,
	cm_store_entry_field_cert_nickname,

	cm_store_entry_field_cert_issuer,
	cm_store_entry_field_cert_serial,
	cm_store_entry_field_cert_subject,
	cm_store_entry_field_cert_spki,
	cm_store_entry_field_cert_not_before,
	cm_store_entry_field_cert_not_after,
	cm_store_entry_field_cert_hostname,
	cm_store_entry_field_cert_email,
	cm_store_entry_field_cert_principal,
	cm_store_entry_field_cert_ku,
	cm_store_entry_field_cert_eku,
	cm_store_entry_field_cert_profile,

	cm_store_entry_field_last_expiration_check,
	cm_store_entry_field_last_need_notify_check,
	cm_store_entry_field_last_need_enroll_check,

	cm_store_entry_field_template_subject,
	cm_store_entry_field_template_hostname,
	cm_store_entry_field_template_email,
	cm_store_entry_field_template_principal,
	cm_store_entry_field_template_ku,
	cm_store_entry_field_template_eku,

	cm_store_entry_field_challenge_password,

	cm_store_entry_field_csr,
	cm_store_entry_field_spkac,

	cm_store_entry_field_state,

	cm_store_entry_field_autorenew,
	cm_store_entry_field_monitor,

	cm_store_entry_field_ca_nickname,
	cm_store_entry_field_ca_profile,

	cm_store_entry_field_submitted,
	cm_store_entry_field_ca_cookie,
	cm_store_entry_field_ca_error,

	cm_store_entry_field_cert,

	cm_store_entry_field_pre_certsave_command,
	cm_store_entry_field_pre_certsave_uid,
	cm_store_entry_field_post_certsave_command,
	cm_store_entry_field_post_certsave_uid,

	cm_store_ca_field_known_issuer_names,
	cm_store_ca_field_is_default,

	cm_store_ca_field_type,
	cm_store_ca_field_internal_serial,
	cm_store_ca_field_internal_issue_time,
	cm_store_ca_field_external_helper,

	cm_store_file_field_invalid_high,
};
static struct cm_store_file_field_list {
	enum cm_store_file_field field;
	const char *name;
} cm_store_file_field_list[] = {
	{cm_store_file_field_id, "id"}, /* ipa-client-install assumes that we'll
					 * never rename this, so now we can't */
	{cm_store_entry_field_key_type, "key_type"},
	{cm_store_entry_field_key_gen_type, "key_gen_type"},
	{cm_store_entry_field_key_size, "key_size"},
	{cm_store_entry_field_key_gen_size, "key_gen_size"},

	{cm_store_entry_field_key_storage_type, "key_storage_type"},
	{cm_store_entry_field_key_storage_location, "key_storage_location"},
	{cm_store_entry_field_key_token, "key_token"},
	{cm_store_entry_field_key_nickname, "key_nickname"},
	{cm_store_entry_field_key_pin, "key_pin"},
	{cm_store_entry_field_key_pin_file, "key_pin_file"},
	{cm_store_entry_field_key_pubkey, "key_pubkey"},

	{cm_store_entry_field_cert_storage_type, "cert_storage_type"},
	{cm_store_entry_field_cert_storage_location, "cert_storage_location"},
	{cm_store_entry_field_cert_token, "cert_token"},
	{cm_store_entry_field_cert_nickname, "cert_nickname"},

	{cm_store_entry_field_cert_issuer, "cert_issuer"},
	{cm_store_entry_field_cert_serial, "cert_serial"},
	{cm_store_entry_field_cert_subject, "cert_subject"},
	{cm_store_entry_field_cert_spki, "cert_spki"},
	{cm_store_entry_field_cert_not_before, "cert_not_before"}, /* right */
	{cm_store_entry_field_cert_not_before, "cert_issued"}, /* so wrong */
	{cm_store_entry_field_cert_not_after, "cert_not_after"}, /* right */
	{cm_store_entry_field_cert_not_after, "cert_expiration"}, /* wrong */
	{cm_store_entry_field_cert_hostname, "cert_hostname"},
	{cm_store_entry_field_cert_email, "cert_email"},
	{cm_store_entry_field_cert_principal, "cert_principal"},
	{cm_store_entry_field_cert_ku, "cert_ku"},
	{cm_store_entry_field_cert_eku, "cert_eku"},
	{cm_store_entry_field_cert_profile, "cert_profile"},

	{cm_store_entry_field_last_expiration_check, "last_expiration_check"},
	{cm_store_entry_field_last_need_notify_check, "last_need_notify_check"},
	{cm_store_entry_field_last_need_enroll_check, "last_need_enroll_check"},

	{cm_store_entry_field_template_subject, "template_subject"},
	{cm_store_entry_field_template_hostname, "template_hostname"},
	{cm_store_entry_field_template_email, "template_email"},
	{cm_store_entry_field_template_principal, "template_principal"},
	{cm_store_entry_field_template_ku, "template_ku"},
	{cm_store_entry_field_template_eku, "template_eku"},

	{cm_store_entry_field_challenge_password, "challenge_password"},

	{cm_store_entry_field_csr, "csr"},
	{cm_store_entry_field_spkac, "spkac"},
	{cm_store_entry_field_state, "state"},

	{cm_store_entry_field_autorenew, "autorenew"},
	{cm_store_entry_field_monitor, "monitor"},

	{cm_store_entry_field_ca_nickname, "ca_name"},
	{cm_store_entry_field_ca_profile, "ca_profile"},

	{cm_store_entry_field_submitted, "submitted"},
	{cm_store_entry_field_ca_cookie, "ca_cookie"},
	{cm_store_entry_field_ca_error, "ca_error"},

	{cm_store_entry_field_cert, "cert"},
	{cm_store_entry_field_pre_certsave_command, "pre_certsave_command"},
	{cm_store_entry_field_pre_certsave_uid, "pre_certsave_uid"},
	{cm_store_entry_field_post_certsave_command, "post_certsave_command"},
	{cm_store_entry_field_post_certsave_uid, "post_certsave_uid"},

	{cm_store_ca_field_known_issuer_names, "ca_issuer_names"},
	{cm_store_ca_field_is_default, "ca_is_default"},

	{cm_store_ca_field_type, "ca_type"},
	{cm_store_ca_field_internal_serial, "ca_internal_serial"},
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
	if ((p == NULL) || (strlen(p) == 0)) {
		if (p != NULL) {
			talloc_free(p);
		}
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

char *
cm_store_entry_next_busname(void *parent)
{
	return talloc_asprintf(parent, "Request%llu", ++cm_entry_name_last);
}

static struct cm_store_entry *
cm_store_entry_read(void *parent, const char *filename, FILE *fp)
{
	struct cm_store_entry *ret;
	char **s, *p;
	int i;
	enum cm_store_file_field field;
	ret = talloc_ptrtype(parent, ret);
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		s = cm_store_file_read_lines(ret, fp);
		ret->cm_busname = cm_store_entry_next_busname(ret);
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
			case cm_store_ca_field_internal_issue_time:
			case cm_store_ca_field_external_helper:
				break;
			case cm_store_file_field_id:
				ret->cm_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_key_type:
				if (strcasecmp(s[i], "RSA") == 0) {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_rsa;
				} else {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_unspecified;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_gen_type:
				if (strcasecmp(s[i], "RSA") == 0) {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_rsa;
				} else {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_unspecified;
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
				if (ret->cm_key_storage_location != NULL) {
					p = cm_store_canonicalize_directory(ret,
									    ret->cm_key_storage_location);
					talloc_free(ret->cm_key_storage_location);
					ret->cm_key_storage_location = p;
				}
				break;
			case cm_store_entry_field_key_token:
				ret->cm_key_token = free_if_empty(p);
				break;
			case cm_store_entry_field_key_nickname:
				ret->cm_key_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_key_pin:
				ret->cm_key_pin = free_if_empty(p);
				if (ret->cm_key_pin_file != NULL) {
					ret->cm_key_pin = NULL;
				}
				break;
			case cm_store_entry_field_key_pin_file:
				ret->cm_key_pin_file = free_if_empty(p);
				if (ret->cm_key_pin_file != NULL) {
					ret->cm_key_pin = NULL;
				}
				break;
			case cm_store_entry_field_key_pubkey:
				ret->cm_key_pubkey = free_if_empty(p);
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
				if (ret->cm_cert_storage_location != NULL) {
					p = cm_store_canonicalize_directory(ret,
									    ret->cm_cert_storage_location);
					talloc_free(ret->cm_cert_storage_location);
					ret->cm_cert_storage_location = p;
				}
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
			case cm_store_entry_field_cert_not_before:
				ret->cm_cert_not_before =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_not_after:
				ret->cm_cert_not_after =
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
			case cm_store_entry_field_cert_profile:
				ret->cm_cert_profile = free_if_empty(p);
				break;
			case cm_store_entry_field_last_expiration_check:
				/* backward compatibility before we split them
				 * into two settings */
				ret->cm_last_need_notify_check =
					cm_store_time_from_timestamp(p);
				ret->cm_last_need_enroll_check =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_last_need_notify_check:
				ret->cm_last_need_notify_check =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_last_need_enroll_check:
				ret->cm_last_need_enroll_check =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
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
			case cm_store_entry_field_challenge_password:
				ret->cm_challenge_password = free_if_empty(p);
				break;
			case cm_store_entry_field_csr:
				ret->cm_csr = free_if_empty(p);
				break;
			case cm_store_entry_field_spkac:
				ret->cm_spkac = free_if_empty(p);
				break;
			case cm_store_entry_field_state:
				ret->cm_state = cm_store_state_from_string(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_autorenew:
				ret->cm_autorenew = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_monitor:
				ret->cm_monitor = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_ca_nickname:
				ret->cm_ca_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_ca_profile:
				ret->cm_ca_profile = free_if_empty(p);
				break;
			case cm_store_entry_field_submitted:
				ret->cm_submitted =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_ca_cookie:
				ret->cm_ca_cookie = free_if_empty(p);
				break;
			case cm_store_entry_field_ca_error:
				ret->cm_ca_error = free_if_empty(p);
				break;
			case cm_store_entry_field_cert:
				ret->cm_cert = free_if_empty(p);
				break;
			case cm_store_entry_field_pre_certsave_command:
				ret->cm_pre_certsave_command  = free_if_empty(p);
				break;
			case cm_store_entry_field_pre_certsave_uid:
				ret->cm_pre_certsave_uid = free_if_empty(p);
				break;
			case cm_store_entry_field_post_certsave_command:
				ret->cm_post_certsave_command  = free_if_empty(p);
				break;
			case cm_store_entry_field_post_certsave_uid:
				ret->cm_post_certsave_uid = free_if_empty(p);
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
	if (filename != NULL) {
		fp = fopen(filename, "r");
		if (fp != NULL) {
			ret = cm_store_entry_read(parent, filename, fp);
			fclose(fp);
		} else {
			ret = NULL;
		}
	} else {
		ret = NULL;
	}
	return ret;
}

char *
cm_store_ca_next_busname(void *parent)
{
	return talloc_asprintf(parent, "CA%llu", ++cm_ca_name_last);
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
		ret->cm_busname = cm_store_ca_next_busname(ret);
		ret->cm_store_private = talloc_strdup(ret, filename);
		for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
			p = s[i];
			field = cm_store_file_field_of_line(p);
			switch (field) {
			case cm_store_file_field_invalid:
			case cm_store_file_field_invalid_high:
				break;
			case cm_store_entry_field_key_type:
			case cm_store_entry_field_key_gen_type:
			case cm_store_entry_field_key_size:
			case cm_store_entry_field_key_gen_size:
			case cm_store_entry_field_key_storage_type:
			case cm_store_entry_field_key_storage_location:
			case cm_store_entry_field_key_token:
			case cm_store_entry_field_key_nickname:
			case cm_store_entry_field_key_pin:
			case cm_store_entry_field_key_pin_file:
			case cm_store_entry_field_key_pubkey:
			case cm_store_entry_field_cert_storage_type:
			case cm_store_entry_field_cert_storage_location:
			case cm_store_entry_field_cert_token:
			case cm_store_entry_field_cert_nickname:
			case cm_store_entry_field_cert_issuer:
			case cm_store_entry_field_cert_serial:
			case cm_store_entry_field_cert_subject:
			case cm_store_entry_field_cert_spki:
			case cm_store_entry_field_cert_not_before:
			case cm_store_entry_field_cert_not_after:
			case cm_store_entry_field_cert_hostname:
			case cm_store_entry_field_cert_email:
			case cm_store_entry_field_cert_principal:
			case cm_store_entry_field_cert_ku:
			case cm_store_entry_field_cert_eku:
			case cm_store_entry_field_cert_profile:
			case cm_store_entry_field_last_expiration_check:
			case cm_store_entry_field_last_need_notify_check:
			case cm_store_entry_field_last_need_enroll_check:
			case cm_store_entry_field_template_subject:
			case cm_store_entry_field_template_hostname:
			case cm_store_entry_field_template_email:
			case cm_store_entry_field_template_principal:
			case cm_store_entry_field_template_ku:
			case cm_store_entry_field_template_eku:
			case cm_store_entry_field_challenge_password:
			case cm_store_entry_field_csr:
			case cm_store_entry_field_spkac:
			case cm_store_entry_field_state:
			case cm_store_entry_field_autorenew:
			case cm_store_entry_field_monitor:
			case cm_store_entry_field_ca_nickname:
			case cm_store_entry_field_ca_profile:
			case cm_store_entry_field_submitted:
			case cm_store_entry_field_ca_cookie:
			case cm_store_entry_field_ca_error:
			case cm_store_entry_field_cert:
			case cm_store_entry_field_pre_certsave_command:
			case cm_store_entry_field_pre_certsave_uid:
			case cm_store_entry_field_post_certsave_command:
			case cm_store_entry_field_post_certsave_uid:
				break;
			case cm_store_file_field_id:
				ret->cm_nickname = free_if_empty(p);
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
		if (ret->cm_ca_internal_serial == NULL) {
			ret->cm_ca_internal_serial = talloc_strdup(ret, CM_DEFAULT_CERT_SERIAL);
		}
	}
	return ret;
}

struct cm_store_ca *
cm_store_files_ca_read(void *parent, const char *filename)
{
	FILE *fp;
	struct cm_store_ca *ret;
	if (filename != NULL) {
		fp = fopen(filename, "r");
		if (fp != NULL) {
			ret = cm_store_ca_read(parent, filename, fp);
			fclose(fp);
		} else {
			ret = NULL;
		}
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
cm_store_file_write_str(FILE *fp, enum cm_store_file_field field, const char *s)
{
	const char *p, *q;
	if ((s == NULL) || (s[0] == '\0')) {
		return 0;
	}
	p = s;
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

	if (entry->cm_nickname == NULL) {
		p = cm_store_timestamp_from_time(cm_time(NULL), timestamp);
	} else {
		p = entry->cm_nickname;
	}
	cm_store_file_write_str(fp, cm_store_file_field_id, p);

	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_unspecified:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"UNSPECIFIED");
		break;
	case cm_key_rsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"RSA");
		break;
	}
	switch (entry->cm_key_type.cm_key_gen_algorithm) {
	case cm_key_unspecified:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"UNSPECIFIED");
		break;
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
	if (entry->cm_key_pin_file == NULL) {
		cm_store_file_write_str(fp, cm_store_entry_field_key_pin,
					entry->cm_key_pin);
	}
	cm_store_file_write_str(fp, cm_store_entry_field_key_pin_file,
				entry->cm_key_pin_file);
	cm_store_file_write_str(fp, cm_store_entry_field_key_pubkey,
				entry->cm_key_pubkey);

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
	if (entry->cm_cert_not_before != 0) {
		cm_store_file_write_str(fp, cm_store_entry_field_cert_not_before,
					cm_store_timestamp_from_time(entry->cm_cert_not_before,
								     timestamp));
	}
	if (entry->cm_cert_not_after != 0) {
		cm_store_file_write_str(fp, cm_store_entry_field_cert_not_after,
					cm_store_timestamp_from_time(entry->cm_cert_not_after,
								     timestamp));
	}
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
	cm_store_file_write_str(fp, cm_store_entry_field_cert_profile,
				entry->cm_cert_profile);

	cm_store_file_write_str(fp, cm_store_entry_field_last_need_notify_check,
				cm_store_timestamp_from_time(entry->cm_last_need_notify_check,
							     timestamp));
	cm_store_file_write_str(fp, cm_store_entry_field_last_need_enroll_check,
				cm_store_timestamp_from_time(entry->cm_last_need_enroll_check,
							     timestamp));
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

	cm_store_file_write_str(fp, cm_store_entry_field_challenge_password,
				entry->cm_challenge_password);

	cm_store_file_write_str(fp, cm_store_entry_field_csr, entry->cm_csr);
	cm_store_file_write_str(fp, cm_store_entry_field_spkac,
				entry->cm_spkac);

	cm_store_file_write_str(fp, cm_store_entry_field_state,
				cm_store_state_as_string(entry->cm_state));

	cm_store_file_write_int(fp, cm_store_entry_field_autorenew,
				entry->cm_autorenew);

	cm_store_file_write_int(fp, cm_store_entry_field_monitor,
				entry->cm_monitor);

	cm_store_file_write_str(fp, cm_store_entry_field_ca_nickname,
				entry->cm_ca_nickname);
	cm_store_file_write_str(fp, cm_store_entry_field_ca_profile,
				entry->cm_ca_profile);
	cm_store_file_write_str(fp, cm_store_entry_field_submitted,
				cm_store_timestamp_from_time(entry->cm_submitted,
							      timestamp));
	cm_store_file_write_str(fp, cm_store_entry_field_ca_cookie,
				entry->cm_ca_cookie);
	cm_store_file_write_str(fp, cm_store_entry_field_ca_error,
				entry->cm_ca_error);
	cm_store_file_write_str(fp, cm_store_entry_field_cert, entry->cm_cert);
	cm_store_file_write_str(fp, cm_store_entry_field_pre_certsave_command,
				entry->cm_pre_certsave_command);
	cm_store_file_write_str(fp, cm_store_entry_field_pre_certsave_uid,
				entry->cm_pre_certsave_uid);
	cm_store_file_write_str(fp, cm_store_entry_field_post_certsave_command,
				entry->cm_post_certsave_command);
	cm_store_file_write_str(fp, cm_store_entry_field_post_certsave_uid,
				entry->cm_post_certsave_uid);
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
		       entry->cm_nickname);
		ret = 0;
	}
	return 0;
}

static void
cm_store_create_containing_dir(const char *path, int mode)
{
	char dir[PATH_MAX];
	int i;
	if (strlen(path) >= sizeof(dir)) {
		return;
	}
	for (i = 0, dir[0] = '\0'; path[i] != '\0'; i++) {
		if ((i > 0) && (path[i] == '/')) {
			if (mkdir(dir, mode) == -1) {
				if (errno != EEXIST) {
					cm_log(1, "Failed to create \"%s\": "
					       "%s.\n", dir, strerror(errno));
					break;
				}
			} else {
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
	int i, fd = -1, give_up;
	const char *directory;

	if (entry->cm_store_private == NULL) {
		cm_store_timestamp_from_time(cm_time(NULL), timestamp);
		directory = cm_env_request_dir();
		if (directory != NULL) {
			snprintf(path, sizeof(path), "%s/%s",
				 directory, timestamp);
			fd = open(path,
				  O_WRONLY | O_CREAT | O_EXCL,
				  S_IRUSR | S_IWUSR);
			if ((fd == -1) && (errno == ENOENT)) {
				cm_store_create_containing_dir(path, S_IRWXU);
				fd = open(path,
					  O_WRONLY | O_CREAT | O_EXCL,
					  S_IRUSR | S_IWUSR);
			}
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

	directory = cm_env_request_dir();
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
							if (strcmp(ret[k]->cm_nickname,
								   ret[j]->cm_nickname) == 0) {
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

	if (ca->cm_nickname == NULL) {
		p = cm_store_timestamp_from_time(cm_time(NULL), timestamp);
	} else {
		p = ca->cm_nickname;
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
		cm_log(3, "No file to remove for \"%s\".\n", ca->cm_nickname);
		ret = 0;
	}
	return 0;
}

int
cm_store_ca_save(struct cm_store_ca *ca)
{
	FILE *fp;
	char timestamp[15], path[PATH_MAX];
	int i, fd = -1, give_up;
	const char *directory;

	if (ca->cm_store_private == NULL) {
		cm_store_timestamp_from_time(cm_time(NULL), timestamp);
		directory = cm_env_ca_dir();
		if (directory != NULL) {
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

	directory = cm_env_ca_dir();
	snprintf(path, sizeof(path), "%s/*", directory);
	memset(&globs, 0, sizeof(globs));
	ret = NULL;
	if (glob(path, 0, NULL, &globs) != 0) {
		globs.gl_pathc = 0;
	}
	ret = talloc_array_ptrtype(parent, ret, globs.gl_pathc + 5);
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
						if (strcmp(ret[k]->cm_nickname,
							   ret[j]->cm_nickname) == 0) {
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
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_SELF_SIGN_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_internal_self;
			ret[j]->cm_ca_internal_serial = talloc_strdup(ret[j],
								      CM_DEFAULT_CERT_SERIAL);
			j++;
		}
#ifdef WITH_IPA
		/* Make sure we get at least one IPA entry. */
		for (k = 0; k < j; k++) {
			if ((ret[k]->cm_ca_type == cm_ca_external) &&
			    (strcmp(ret[k]->cm_nickname,
				    CM_IPA_CA_NAME) == 0)) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_IPA_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_external;
			ret[j]->cm_ca_external_helper = talloc_strdup(ret[j],
								      CM_IPA_HELPER_PATH);
			j++;
		}
#endif
#ifdef WITH_CERTMASTER
		/* Make sure we get at least one certmaster entry. */
		for (k = 0; k < j; k++) {
			if ((ret[k]->cm_ca_type == cm_ca_external) &&
			    (strcmp(ret[k]->cm_nickname,
				    CM_CERTMASTER_CA_NAME) == 0)) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_CERTMASTER_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_external;
			ret[j]->cm_ca_external_helper = talloc_strdup(ret[j],
								      CM_CERTMASTER_HELPER_PATH);
			j++;
		}
#endif
		/* Make sure we get at least one dogtag entry. */
		for (k = 0; k < j; k++) {
			if ((ret[k]->cm_ca_type == cm_ca_external) &&
			    (strcmp(ret[k]->cm_nickname,
				    CM_DOGTAG_IPA_RENEW_AGENT_CA_NAME) == 0)) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_DOGTAG_IPA_RENEW_AGENT_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_external;
			ret[j]->cm_ca_external_helper = talloc_strdup(ret[j],
								      CM_DOGTAG_IPA_RENEW_AGENT_HELPER_PATH);
			j++;
		}
		ret[j] = NULL;
	}
	if (globs.gl_pathc > 0) {
		globfree(&globs);
	}
	return ret;
}

struct cm_store_entry *
cm_store_entry_dup(void *parent, struct cm_store_entry *entry)
{
	struct cm_store_entry *ret;

	ret = talloc_ptrtype(parent, ret);

	ret->cm_busname = cm_store_maybe_strdup(ret, entry->cm_busname);
	ret->cm_store_private =
		cm_store_maybe_strdup(ret, entry->cm_store_private);
	ret->cm_nickname = cm_store_maybe_strdup(ret, entry->cm_nickname);

	ret->cm_key_type = entry->cm_key_type;
	ret->cm_key_storage_type = entry->cm_key_storage_type;
	ret->cm_key_storage_location = cm_store_maybe_strdup(ret, entry->cm_key_storage_location);
	ret->cm_key_token = cm_store_maybe_strdup(ret, entry->cm_key_token);
	ret->cm_key_nickname = cm_store_maybe_strdup(ret, entry->cm_key_nickname);
	ret->cm_key_pin = cm_store_maybe_strdup(ret, entry->cm_key_pin);
	ret->cm_key_pin_file = cm_store_maybe_strdup(ret, entry->cm_key_pin_file);
	if (ret->cm_key_pin_file != NULL) {
		ret->cm_key_pin = NULL;
	}
	ret->cm_key_pubkey = cm_store_maybe_strdup(ret, entry->cm_key_pubkey);

	ret->cm_cert_storage_type = entry->cm_cert_storage_type;
	ret->cm_cert_storage_location = cm_store_maybe_strdup(ret, entry->cm_cert_storage_location);
	ret->cm_cert_token = cm_store_maybe_strdup(ret, entry->cm_cert_token);
	ret->cm_cert_nickname = cm_store_maybe_strdup(ret, entry->cm_cert_nickname);

	ret->cm_cert_issuer = cm_store_maybe_strdup(ret, entry->cm_cert_issuer);
	ret->cm_cert_serial = cm_store_maybe_strdup(ret, entry->cm_cert_serial);
	ret->cm_cert_subject = cm_store_maybe_strdup(ret, entry->cm_cert_subject);
	ret->cm_cert_spki = cm_store_maybe_strdup(ret, entry->cm_cert_spki);
	ret->cm_cert_not_before = entry->cm_cert_not_before;
	ret->cm_cert_not_after = entry->cm_cert_not_after;
	ret->cm_cert_hostname = cm_store_maybe_strdupv(ret, entry->cm_cert_hostname);
	ret->cm_cert_email = cm_store_maybe_strdupv(ret, entry->cm_cert_email);
	ret->cm_cert_principal = cm_store_maybe_strdupv(ret, entry->cm_cert_principal);
	ret->cm_cert_ku = cm_store_maybe_strdup(ret, entry->cm_cert_ku);
	ret->cm_cert_eku = cm_store_maybe_strdup(ret, entry->cm_cert_eku);
	ret->cm_cert_profile = cm_store_maybe_strdup(ret,
						     entry->cm_cert_profile);

	ret->cm_last_need_notify_check = entry->cm_last_need_notify_check;
	ret->cm_last_need_enroll_check = entry->cm_last_need_enroll_check;
	ret->cm_notification_method = entry->cm_notification_method;
	ret->cm_notification_destination = cm_store_maybe_strdup(ret, entry->cm_notification_destination);

	ret->cm_template_subject = cm_store_maybe_strdup(ret, entry->cm_template_subject);
	ret->cm_template_hostname = cm_store_maybe_strdupv(ret, entry->cm_template_hostname);
	ret->cm_template_email = cm_store_maybe_strdupv(ret, entry->cm_template_email);
	ret->cm_template_principal = cm_store_maybe_strdupv(ret, entry->cm_template_principal);
	ret->cm_template_ku = cm_store_maybe_strdup(ret, entry->cm_template_ku);
	ret->cm_template_eku = cm_store_maybe_strdup(ret, entry->cm_template_eku);

	ret->cm_challenge_password = cm_store_maybe_strdup(ret, entry->cm_challenge_password);
	ret->cm_csr = cm_store_maybe_strdup(ret, entry->cm_csr);
	ret->cm_spkac = cm_store_maybe_strdup(ret, entry->cm_spkac);
	ret->cm_state = entry->cm_state;
	ret->cm_autorenew = entry->cm_autorenew;
	ret->cm_monitor = entry->cm_monitor;
	ret->cm_ca_nickname = cm_store_maybe_strdup(ret, entry->cm_ca_nickname);
	ret->cm_ca_profile = cm_store_maybe_strdup(ret, entry->cm_ca_profile);
	ret->cm_submitted = entry->cm_submitted;
	ret->cm_ca_cookie = cm_store_maybe_strdup(ret, entry->cm_ca_cookie);
	ret->cm_ca_error = cm_store_maybe_strdup(ret, entry->cm_ca_error);
	ret->cm_cert = cm_store_maybe_strdup(ret, entry->cm_cert);
	ret->cm_pre_certsave_command = cm_store_maybe_strdup(ret, entry->cm_pre_certsave_command);
	ret->cm_pre_certsave_uid = cm_store_maybe_strdup(ret, entry->cm_pre_certsave_uid);
	ret->cm_post_certsave_command = cm_store_maybe_strdup(ret, entry->cm_post_certsave_command);
	ret->cm_post_certsave_uid = cm_store_maybe_strdup(ret, entry->cm_post_certsave_uid);

	return ret;
}

struct cm_store_ca *
cm_store_ca_dup(void *parent, struct cm_store_ca *ca)
{
	struct cm_store_ca *ret;

	ret = talloc_ptrtype(parent, ret);
	ret->cm_busname = cm_store_maybe_strdup(ret, ca->cm_busname);
	ret->cm_store_private =
		cm_store_maybe_strdup(ret, ca->cm_store_private);
	ret->cm_nickname = cm_store_maybe_strdup(ret, ca->cm_nickname);
	ret->cm_ca_known_issuer_names =
		cm_store_maybe_strdupv(ret, ca->cm_ca_known_issuer_names);
	ret->cm_ca_is_default = ca->cm_ca_is_default;
	ret->cm_ca_type = ca->cm_ca_type;
	ret->cm_ca_internal_serial =
		cm_store_maybe_strdup(ret, ca->cm_ca_internal_serial);
	ret->cm_ca_internal_force_issue_time =
		ca->cm_ca_internal_force_issue_time;
	ret->cm_ca_internal_issue_time = ca->cm_ca_internal_issue_time;
	ret->cm_ca_external_helper =
		cm_store_maybe_strdup(ret, ca->cm_ca_external_helper);
	return ret;
}
