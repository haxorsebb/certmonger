/*
 * Copyright (C) 2009,2011,2012,2014 Red Hat, Inc.
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
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include "log.h"
#include "notify.h"
#include "prefs.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "tm.h"

struct cm_notify_state {
	struct cm_subproc_state *subproc;
};

struct cm_notify_details {
	enum cm_notify_event event;
};

/* Fire off the proper notification. */
static int
cm_notify_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
	       void *userdata)
{
	struct cm_notify_details *details = userdata;
	enum cm_notification_method method;
	const char *dest, *p, *q, *message = NULL, *error;
	char *tok, t[15], **argv;
	int facility, level;
	struct {
		const char *name;
		int value;
	} facilities[] = {
		{"auth", LOG_AUTH},
		{"authpriv", LOG_AUTHPRIV},
		{"cron", LOG_CRON},
		{"daemon", LOG_DAEMON},
		{"ftp", LOG_FTP},
		{"kern", LOG_KERN},
		{"local0", LOG_LOCAL0},
		{"local1", LOG_LOCAL1},
		{"local2", LOG_LOCAL2},
		{"local3", LOG_LOCAL3},
		{"local4", LOG_LOCAL4},
		{"local5", LOG_LOCAL5},
		{"local6", LOG_LOCAL6},
		{"local7", LOG_LOCAL7},
		{"lpr", LOG_LPR},
		{"mail", LOG_MAIL},
		{"news", LOG_NEWS},
		{"user", LOG_USER},
		{"uucp", LOG_UUCP},
	},
	levels[] = {
		{"emerg", LOG_EMERG},
		{"alert", LOG_ALERT},
		{"crit", LOG_CRIT},
		{"err", LOG_ERR},
		{"warning", LOG_WARNING},
		{"notice", LOG_NOTICE},
		{"info", LOG_INFO},
		{"debug", LOG_DEBUG},
	};
	unsigned int i;
	switch (details->event) {
	case cm_notify_event_unknown:
		message = talloc_asprintf(entry, "Something "
					  "happened with certiifcate "
					  "named \"%s\" "
					  "in token \"%s\" "
					  "in database \"%s\".",
					  entry->cm_cert_nickname,
					  entry->cm_cert_token,
					  entry->cm_cert_storage_location);
		break;
	case cm_notify_event_validity_ending:
		if (entry->cm_cert_not_after > cm_time(NULL)) {
			switch (entry->cm_cert_storage_type) {
			case cm_cert_storage_nssdb:
				if (entry->cm_cert_token != NULL) {
					message = talloc_asprintf(entry, "Certificate "
								  "named \"%s\" "
								  "in token \"%s\" "
								  "in database \"%s\" "
								  "will not be valid "
								  "after %s.",
								  entry->cm_cert_nickname,
								  entry->cm_cert_token,
								  entry->cm_cert_storage_location,
								  cm_store_timestamp_from_time(entry->cm_cert_not_after, t));
				} else {
					message = talloc_asprintf(entry, "Certificate "
								  "named \"%s\" "
								  "in database \"%s\" "
								  "will expire at "
								  "%s.",
								  entry->cm_cert_nickname,
								  entry->cm_cert_storage_location,
								  cm_store_timestamp_from_time(entry->cm_cert_not_after, t));
				}
				break;
			case cm_cert_storage_file:
				message = talloc_asprintf(entry, "Certificate "
							  "in file \"%s\" will not be "
							  "valid after %s.",
							  entry->cm_cert_storage_location,
							  cm_store_timestamp_from_time(entry->cm_cert_not_after, t));
				break;
			}
		} else {
			switch (entry->cm_cert_storage_type) {
			case cm_cert_storage_nssdb:
				if (entry->cm_cert_token != NULL) {
					message = talloc_asprintf(entry, "Certificate "
								  "named \"%s\" "
								  "in token \"%s\" "
								  "in database \"%s\" "
								  "is no longer valid.",
								  entry->cm_cert_nickname,
								  entry->cm_cert_token,
								  entry->cm_cert_storage_location);
				} else {
					message = talloc_asprintf(entry, "Certificate "
								  "named \"%s\" "
								  "in database \"%s\" "
								  "is no longer valid.",
								  entry->cm_cert_nickname,
								  entry->cm_cert_storage_location);
				}
				break;
			case cm_cert_storage_file:
				message = talloc_asprintf(entry, "Certificate "
							  "in file \"%s\" is no longer "
							  "valid.",
							  entry->cm_cert_storage_location);
				break;
			}
		}
		break;
	case cm_notify_event_rejected:
		switch (entry->cm_cert_storage_type) {
		case cm_cert_storage_nssdb:
			if (entry->cm_cert_token != NULL) {
				message = talloc_asprintf(entry, "Request for "
							  "certificate to be "
							  "named \"%s\" "
							  "in token \"%s\" "
							  "in database \"%s\" "
							  "rejected by CA.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_token,
							  entry->cm_cert_storage_location);
			} else {
				message = talloc_asprintf(entry, "Request for "
							  "certificate to be "
							  "named \"%s\" "
							  "in database \"%s\" "
							  "rejected by CA.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_storage_location);
			}
			break;
		case cm_cert_storage_file:
			message = talloc_asprintf(entry, "Request for certificate to be "
						  "stored in file \"%s\" rejected by CA.",
						  entry->cm_cert_storage_location);
			break;
		}
		break;
	case cm_notify_event_issued_not_saved:
		switch (entry->cm_cert_storage_type) {
		case cm_cert_storage_nssdb:
			if (entry->cm_cert_token != NULL) {
				message = talloc_asprintf(entry, "Certificate "
							  "named \"%s\" "
							  "in token \"%s\" "
							  "in database \"%s\" "
							  "issued by CA but not saved.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_token,
							  entry->cm_cert_storage_location);
			} else {
				message = talloc_asprintf(entry, "Certificate "
							  "named \"%s\" "
							  "in database \"%s\" "
							  "issued by CA but not saved.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_storage_location);
			}
			break;
		case cm_cert_storage_file:
			message = talloc_asprintf(entry, "Certificate "
						  "in file \"%s\" "
						  "issued by CA but not saved.",
						  entry->cm_cert_storage_location);
			break;
		}
		break;
	case cm_notify_event_issued_and_saved:
		switch (entry->cm_cert_storage_type) {
		case cm_cert_storage_nssdb:
			if (entry->cm_cert_token != NULL) {
				message = talloc_asprintf(entry, "Certificate "
							  "named \"%s\" "
							  "in token \"%s\" "
							  "in database \"%s\" "
							  "issued by CA and saved.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_token,
							  entry->cm_cert_storage_location);
			} else {
				message = talloc_asprintf(entry, "Certificate "
							  "named \"%s\" "
							  "in database \"%s\" "
							  "issued by CA and saved.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_storage_location);
			}
			break;
		case cm_cert_storage_file:
			message = talloc_asprintf(entry, "Certificate "
						  "in file \"%s\" "
						  "issued by CA and saved.",
						  entry->cm_cert_storage_location);
			break;
		}
		break;
	case cm_notify_event_issued_ca_not_saved:
		switch (entry->cm_cert_storage_type) {
		case cm_cert_storage_nssdb:
			if (entry->cm_cert_token != NULL) {
				message = talloc_asprintf(entry, "Certificate "
							  "named \"%s\" "
							  "in token \"%s\" "
							  "in database \"%s\" "
							  "issued by CA and "
							  "saved, but the CA "
							  "certificate was "
							  "not saved.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_token,
							  entry->cm_cert_storage_location);
			} else {
				message = talloc_asprintf(entry, "Certificate "
							  "named \"%s\" "
							  "in database \"%s\" "
							  "issued by CA and "
							  "saved, but the CA "
							  "certificate was "
							  "not saved.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_storage_location);
			}
			break;
		case cm_cert_storage_file:
			message = talloc_asprintf(entry, "Certificate "
						  "in file \"%s\" "
						  "issued by CA and saved, "
						  "but the CA certificate was "
						  "not saved.",
						  entry->cm_cert_storage_location);
			break;
		}
		break;
	case cm_notify_event_ca_not_saved:
		switch (entry->cm_cert_storage_type) {
		case cm_cert_storage_nssdb:
			if (entry->cm_cert_token != NULL) {
				message = talloc_asprintf(entry, "CA certificate "
							  "for certificate "
							  "named \"%s\" "
							  "in token \"%s\" "
							  "in database \"%s\" "
							  "(CA \"%s\") not saved.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_token,
							  entry->cm_cert_storage_location,
							  entry->cm_ca_nickname);
			} else {
				message = talloc_asprintf(entry, "CA certificate "
							  "for certificate "
							  "named \"%s\" "
							  "in database \"%s\" "
							  "(CA \"%s\") not saved.",
							  entry->cm_cert_nickname,
							  entry->cm_cert_storage_location,
							  entry->cm_ca_nickname);
			}
			break;
		case cm_cert_storage_file:
			message = talloc_asprintf(entry, "CA certificate "
						  "for certificate "
						  "in file \"%s\" "
						  "(CA \"%s\") not saved.",
						  entry->cm_cert_storage_location,
						  entry->cm_ca_nickname);
			break;
		}
		break;
	}
	method = entry->cm_notification_method;
	if (method == cm_notification_unspecified) {
		method = cm_prefs_notification_method();
	}
	dest = entry->cm_notification_destination;
	if (dest == NULL) {
		dest = cm_prefs_notification_destination();
	}
	switch (method) {
	case cm_notification_none:
		/* do nothing! */
		break;
	case cm_notification_unspecified:
		abort();
		break;
	case cm_notification_stdout:
		sleep(5);
		/* XXX that was SO wrong, but it makes the output of the test
		 * suite consistent when we mix the parent printing the current
		 * state and this process also outputting the warning */
		printf("%s\n", message);
		fflush(NULL);
		break;
	case cm_notification_syslog:
		facility = LOG_USER;
		level = LOG_NOTICE;
		for (p = dest; *p != '\0'; p = q) {
			q = p + strcspn(p, ".,:/|");
			tok = talloc_strndup(entry, p, q - p);
			if (tok == NULL) {
				continue;
			}
			for (i = 0;
			     i < sizeof(facilities) / sizeof(facilities[0]);
			     i++) {
				if (strcasecmp(facilities[i].name, tok) == 0) {
					facility = facilities[i].value;
				}
			}
			for (i = 0;
			     i < sizeof(levels) / sizeof(levels[0]);
			     i++) {
				if (strcasecmp(levels[i].name, tok) == 0) {
					level = levels[i].value;
				}
			}
			q += strspn(q, ".,:/|");
		}
		cm_log(4, "0x%02x %s\n", facility | level, message);
		syslog(facility | level, "%s", message);
		break;
	case cm_notification_email:
		execlp("mail", "mail", "-s", message, dest, NULL);
		break;
	case cm_notification_command:
		argv = cm_subproc_parse_args(entry, dest, &error);
		if (argv == NULL) {
			if (error != NULL) {
				cm_log(0, "Error parsing \"%s\": %s.\n",
				       dest, error);
			} else {
				cm_log(0, "Error parsing \"%s\".\n", dest);
			}
			return -1;
		}
		cm_log(1, "Running notification helper \"%s\".\n", argv[0]);
		cm_subproc_mark_most_cloexec(-1, -1, -1);
		setenv(CM_NOTIFICATION_ENV, message, 1);
		if (execvp(argv[0], argv) == -1) {
			cm_log(0, "Error execvp()ing command \"%s\" (\"%s\"): %s.\n",
			       argv[0], entry->cm_post_certsave_command,
			       strerror(errno));
			return -1;
		}
	}
	return 0;
}

/* Start notifying the user that the certificate will expire soon. */
struct cm_notify_state *
cm_notify_start(struct cm_store_entry *entry, enum cm_notify_event event)
{
	struct cm_notify_state *state;
	struct cm_notify_details details;

	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		memset(&details, 0, sizeof(details));
		details.event = event;
		state->subproc = cm_subproc_start(cm_notify_main, state,
						  NULL, entry, &details);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_notify_get_fd(struct cm_notify_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Check if our child process has exited. */
int
cm_notify_ready(struct cm_notify_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Clean up after notification. */
void
cm_notify_done(struct cm_notify_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}
