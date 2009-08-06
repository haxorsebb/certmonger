#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

static char *
cm_store_timestamp_from_time(time_t when, char timestamp[15])
{
	struct tm tm;
	if (gmtime_r(&when, &tm) == &tm) {
		sprintf(timestamp, "%04d%02d%02d%02d%02d%02d",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	} else {
		strcpy(timestamp, "19700101000000");
	}
	return timestamp;
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
cm_store_file_read(const char *filename, FILE *fp)
{
	struct cm_store_entry *ret;
	char **s, *p;
	int i, j;
	ret = malloc(sizeof(*ret));
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		s = cm_store_file_read_lines(fp);
		i = 0;
		ret->cm_store_private = strdup(filename);
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
			ret->cm_cert_issuer = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_serial = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_subject = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_spki = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_expiration = cm_store_time_from_timestamp(s[i]);
			free(s[i]);
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_email = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_principal = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_ku = s[i];
			i++;
		}
		if ((s != NULL) && (s[i] != NULL)) {
			ret->cm_cert_eku = s[i];
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

static int
cm_store_file_write_int(FILE *fp, long value)
{
	fprintf(fp, "=%ld\n", value);
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write_ints(FILE *fp, int n, int *values)
{
	int i;
	fprintf(fp, "=");
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
}

static int
cm_store_file_write_longs(FILE *fp, int n, long *values)
{
	int i;
	fprintf(fp, "=");
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
cm_store_file_write_str(FILE *fp, const char *s)
{
	const char *p, *q;
	p = s;
	q = p + strcspn(s, "\n");
	fprintf(fp, "=%.*s\n", (int) (q - p), p);
	while (*q != '\0') {
		p = q + 1;
		q = p + strcspn(s, "\n");
		fprintf(fp, " %.*s\n", (int) (q - p), p);
	}
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write(FILE *fp, struct cm_store_entry *entry)
{
	char timestamp[15];

	cm_store_file_write_int(fp, entry->cm_key_type_default);
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_rsa:
		cm_store_file_write_str(fp, "RSA");
		break;
	}
	cm_store_file_write_int(fp, entry->cm_key_type.cm_key_size);

	cm_store_file_write_int(fp, entry->cm_key_storage_default);
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_file:
		cm_store_file_write_str(fp, "FILE");
		break;
	}
	cm_store_file_write_str(fp, entry->cm_key_storage_location);

	cm_store_file_write_int(fp, entry->cm_cert_storage_default);
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		cm_store_file_write_str(fp, "FILE");
		break;
	}
	cm_store_file_write_str(fp, entry->cm_cert_storage_location);

	cm_store_file_write_str(fp, entry->cm_cert_nickname);
	cm_store_file_write_str(fp, entry->cm_cert_issuer);
	cm_store_file_write_str(fp, entry->cm_cert_serial);
	cm_store_file_write_str(fp, entry->cm_cert_subject);
	cm_store_file_write_str(fp, entry->cm_cert_spki);
	cm_store_file_write_str(fp,
				cm_store_timestamp_from_time(entry->cm_cert_expiration,
							     timestamp));
	cm_store_file_write_str(fp, entry->cm_cert_email);
	cm_store_file_write_str(fp, entry->cm_cert_principal);
	cm_store_file_write_str(fp, entry->cm_cert_ku);
	cm_store_file_write_str(fp, entry->cm_cert_eku);

	cm_store_file_write_int(fp, entry->cm_ttls_default);
	if (sizeof(entry->cm_ttls[0]) == sizeof(int)) {
		cm_store_file_write_ints(fp, entry->cm_n_ttls,
					 (int *) entry->cm_ttls);
	} else
	if (sizeof(entry->cm_ttls[0]) == sizeof(long)) {
		cm_store_file_write_longs(fp, entry->cm_n_ttls,
					  (long *) entry->cm_ttls);
	} else {
		abort();
	}
	
	cm_store_file_write_int(fp, entry->cm_notification_default);
	switch (entry->cm_notification_method) {
	case cm_notification_syslog:
		cm_store_file_write_str(fp, "SYSLOG");
		break;
	case cm_notification_email:
		cm_store_file_write_str(fp, "EMAIL");
		break;
	}
	cm_store_file_write_str(fp, entry->cm_notification_destination);

	cm_store_file_write_int(fp, entry->cm_template_default);
	cm_store_file_write_str(fp, entry->cm_template_subject);
	cm_store_file_write_str(fp, entry->cm_template_email);
	cm_store_file_write_str(fp, entry->cm_template_principal);
	cm_store_file_write_str(fp, entry->cm_template_ku);
	cm_store_file_write_str(fp, entry->cm_template_eku);

	cm_store_file_write_str(fp, entry->cm_csr);

	cm_store_file_write_str(fp, cm_store_state_as_string(entry->cm_state));

	cm_store_file_write_int(fp, entry->cm_autorenew_default);
	cm_store_file_write_int(fp, entry->cm_autorenew);

	cm_store_file_write_int(fp, entry->cm_monitor_default);
	cm_store_file_write_int(fp, entry->cm_monitor);

	cm_store_file_write_int(fp, entry->cm_ca_default);
	switch (entry->cm_ca_type) {
	case cm_ca_files:
		cm_store_file_write_str(fp, "FILES");
		break;
	}
	cm_store_file_write_str(fp, entry->cm_ca_location);
	cm_store_file_write_str(fp,
				cm_store_timestamp_from_time(entry->cm_submitted,
							     timestamp));
	cm_store_file_write_str(fp, entry->cm_ca_cookie);
	cm_store_file_write_str(fp, entry->cm_cert);
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

int
cm_store_entry_save(struct cm_store_entry *entry)
{
	FILE *fp;
	char timestamp[15], path[PATH_MAX];
	int i, fd;
	const char *directory;

	if (entry->cm_store_private == NULL) {
		cm_store_timestamp_from_time(time(NULL), timestamp);
		directory = getenv(CM_FILE_STORE_DIRECTORY_ENV);
		if ((directory == NULL) || (strlen(directory) == 0)) {
			directory = CM_FILE_STORE_DIRECTORY;
		}
		snprintf(path, sizeof(path), "%s/%s", directory, timestamp);
		fd = open(path,
			  O_WRONLY | O_CREAT | O_EXCL,
			  S_IRUSR | S_IWUSR);
		if (fd == -1) {
			for (i = 1; i < 1024; i++) {
				snprintf(path, sizeof(path), "%s/%s-%d",
					 directory, timestamp, i);
				fd = open(path,
					  O_WRONLY | O_CREAT | O_EXCL,
					  S_IRUSR | S_IWUSR);
				if (fd != -1) {
					break;
				}
			}
		}
		if (fd == -1) {
			return -1;
		}
		close(fd);
		entry->cm_store_private = strdup(path);
	}

	snprintf(path, sizeof(path), "%s.tmp",
		 (const char *) entry->cm_store_private);
	fp = fopen(path, "w");
	if (fp != NULL) {
		if (cm_store_file_write(fp, entry) == 0) {
			fclose(fp);
			rename(path, (const char *) entry->cm_store_private);
		} else {
			fclose(fp);
			remove(path);
		}
		return 0;
	} else {
		return -1;
	}
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
					ret[j] = cm_store_file_read(globs.gl_pathv[i], fp);
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
