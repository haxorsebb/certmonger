#include "config.h"

#include <sys/types.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "store.h"
#include "store-int.h"

static time_t
cm_store_time_from_timestamp(const char *timestamp)
{
	struct tm stamp;
	char buf[5];
	time_t t;
	memset(&stamp, 0, sizeof(stamp));
	memcpy(buf, timestamp, 4);
	buf[4] = '\0';
	stamp.tm_year = atoi(buf) - 1900;
	memcpy(buf, timestamp + 4, 2);
	buf[2] = '\0';
	stamp.tm_mon = atoi(buf) - 1;
	memcpy(buf, timestamp + 6, 2);
	buf[2] = '\0';
	stamp.tm_mday = atoi(buf);
	memcpy(buf, timestamp + 8, 2);
	buf[2] = '\0';
	stamp.tm_hour = atoi(buf);
	memcpy(buf, timestamp + 10, 2);
	buf[2] = '\0';
	stamp.tm_min = atoi(buf);
	memcpy(buf, timestamp + 12, 2);
	buf[2] = '\0';
	stamp.tm_sec = atoi(buf);
	t = timegm(&stamp);
	return 0;
}

static char **
cm_store_file_read_lines(FILE *fp)
{
	char buf[LINE_MAX], *s, *t, **lines, **tlines;
	int n_lines;
	s = NULL;
	lines = NULL;
	n_lines = 0;
	while (fgets(buf, sizeof(buf), fp) == buf) {
		switch (buf[0]) {
		case '=':
			if (s != NULL) {
				tlines = malloc((n_lines + 2) * sizeof(*lines));
				if (tlines != NULL) {
					if (n_lines > 0) {
						memcpy(tlines, lines,
						       n_lines *
						       sizeof(*lines));
					}
					tlines[n_lines++] = s;
					tlines[n_lines] = NULL;
					free(lines);
					lines = tlines;
				}
			}
			s = strdup(buf) + 1;
			break;
		case ' ':
			t = malloc(strlen(s) + strlen(buf) + 1);
			if (t != NULL) {
				sprintf(t, "%s%s", s, buf + 1);
				free(s);
				s = t;
			}
			break;
		case '#':
		case ';':
		default:
			break;
		}
	}
	if (s != NULL) {
		tlines = malloc((n_lines + 2) * sizeof(*lines));
		if (tlines != NULL) {
			if (n_lines > 0) {
				memcpy(tlines, lines, n_lines * sizeof(*lines));
			}
			tlines[n_lines++] = s;
			tlines[n_lines] = NULL;
			free(lines);
			lines = tlines;
		}
	}
	return lines;
}

static struct cm_store_entry *
cm_store_file_read(FILE *fp)
{
	struct cm_store_entry *ret;
	char **s, *p;
	int i, j;
	ret = malloc(sizeof(*ret));
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		s = cm_store_file_read_lines(fp);
		i = 0;
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_id = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_key_type_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			if (strcasecmp(s[i], "rsa") == 0) {
				ret->cm_key_type.cm_key_algorithm = cm_key_rsa;
			} else {
				ret->cm_key_type.cm_key_algorithm = cm_key_rsa;
			}
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_key_type.cm_key_size = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_key_storage_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			if (strcasecmp(s[i], "FILE") == 0) {
				ret->cm_key_storage_type = cm_key_storage_file;
			} else {
				ret->cm_key_storage_type = cm_key_storage_file;
			}
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_key_storage_location = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_storage_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			if (strcasecmp(s[i], "file") == 0) {
				ret->cm_cert_storage_type = cm_cert_storage_file;
			} else {
				ret->cm_cert_storage_type = cm_cert_storage_file;
			}
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_storage_location = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_nickname = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_issuer = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_serial = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_subject = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_spki = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_expiration = cm_store_time_from_timestamp(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_email = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_principal = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_ku = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_eku = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_ttls_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_n_ttls = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_ttls = malloc(sizeof(*ret->cm_ttls) * ret->cm_n_ttls);
			if (ret->cm_ttls != NULL) {
				p = s[i];
				for (j = 0; j < ret->cm_n_ttls; j++) {
					ret->cm_ttls[j] = strtol(p, &p, 10);
					p += strcspn(p, "0123456789");
				}
			}
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_notification_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			if (strcasecmp(s[i], "syslog") == 0) {
				ret->cm_notification_method = cm_notification_syslog;
			} else
			if (strcasecmp(s[i], "email") == 0) {
				ret->cm_notification_method = cm_notification_email;
			} else {
				ret->cm_notification_method = cm_notification_syslog;
			}
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_notification_destination = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_template_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_template_subject = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_template_email = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_template_principal = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_template_ku = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_template_eku = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_csr = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_state = cm_store_state_from_string(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_autorenew_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_autorenew = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_monitor_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_monitor = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_ca_default = atoi(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			if (strcasecmp(s[i], "files") == 0) {
				ret->cm_ca_type = cm_ca_files;
			} else {
				ret->cm_ca_type = cm_ca_files;
			}
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_ca_location = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_submitted = cm_store_time_from_timestamp(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_ca_cookie = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert = s[i];
			i++;
		}
		while ((s != NULL) && (s[i] != NULL)) {
			free(s[i++]);
		}
		free(s);
	}
	return ret;
}

int
cm_store_entry_save(struct cm_store_entry *entry)
{
	return -1;
}

struct cm_store_entry *
cm_store_get_defaults(void)
{
	return NULL;
}

struct cm_store_entry **
cm_store_get_all_entries(void)
{
	struct cm_store_entry **ret;
	unsigned int i;
	int j;
	const char *directory;
	char path[PATH_MAX + 1];
	FILE *fp;
	glob_t globs;

	directory = getenv(CM_FILE_STORE_DIRECTORY_ENV);
	if ((directory == NULL) || (strlen(directory) == 0)) {
		directory = CM_FILE_STORE_DIRECTORY;
	}
	snprintf(path, sizeof(path), "%s/*", directory);
	memset(&globs, 0, sizeof(globs));
	ret = NULL;
	if (glob(path, 0, NULL, &globs) == 0) {
		ret = malloc(sizeof(*ret) * (globs.gl_pathc + 1));
		if (ret != NULL) {
			for (i = 0, j = 0; i < globs.gl_pathc; i++) {
				fp = fopen(globs.gl_pathv[i], "r");
				if (fp != NULL) {
					ret[j] = cm_store_file_read(fp);
					if (ret[j] != NULL) {
						j++;
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
