#include "config.h"

#include <sys/types.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include "cm.h"
#include "store.h"
#include "store-int.h"

static void help(const char *cmd, const char *category);

static int
request(const char *argv0, int argc, char **argv)
{
	struct cm_store_entry *entry;
	char cn_template[LINE_MAX];
	const char *ca = NULL;
	const char *dbdir = NULL, *token = NULL, *nickname = NULL;
	const char *keyfile = NULL, *certfile = NULL;
	const char *subject = NULL, *service = NULL, *usage = NULL;
	int keygen = 0, keysize = 0, track_exp = 0, auto_renew = 0, c;
	while ((c = getopt(argc, argv, "c:gG:d:n:k:f:S:s:t:u:er")) != -1) {
		switch (c) {
		case 'c':
			ca = optarg;
			break;
		case 'g':
			keygen++;
			break;
		case 'G':
			keysize = atoi(optarg);
			break;
		case 'd':
			dbdir = optarg;
			break;
		case 'n':
			nickname = optarg;
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'f':
			certfile = optarg;
			break;
		case 'S':
			subject = optarg;
			break;
		case 's':
			service = optarg;
			break;
		case 't':
			token = optarg;
			break;
		case 'u':
			usage = optarg;
			break;
		case 'e':
			track_exp++;
			break;
		case 'r':
			auto_renew++;
			break;
		default:
			help(argv0, "request");
			return 1;
		}
	}
	entry = cm_store_entry_new(NULL);
	if (entry != NULL) {
		entry->cm_key_type_default = 1;
		entry->cm_key_type.cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
		if (keysize != 0) {
			entry->cm_key_type_default = 0;
			entry->cm_key_type.cm_key_algorithm =
				CM_DEFAULT_PUBKEY_TYPE;
			entry->cm_key_type.cm_key_size = keysize;
		}
		if (((keyfile != NULL) && (certfile == NULL)) ||
		    ((keyfile == NULL) && (certfile != NULL))) {
			printf("Filename for key or certificate specified "
			       "without the other.\n");
			return 1;
		}
		if (keyfile != NULL) {
			entry->cm_key_storage_default = 0;
			entry->cm_key_storage_type = cm_key_storage_file;
			entry->cm_key_storage_location = talloc_strdup(entry,
								       keyfile);
		} else
		if ((dbdir != NULL) && (nickname != NULL)) {
			entry->cm_key_storage_default = 0;
			entry->cm_key_storage_type = cm_key_storage_nssdb;
			entry->cm_key_storage_location = talloc_strdup(entry,
								       dbdir);
			entry->cm_key_token = talloc_strdup(entry, token);
			entry->cm_key_nickname = talloc_strdup(entry, nickname);
		} else {
			entry->cm_key_storage_default = 0;
			entry->cm_key_storage_type = CM_DEFAULT_KEY_STORAGE_TYPE;
			entry->cm_key_storage_location = talloc_strdup(entry, CM_DEFAULT_KEY_STORAGE_LOCATION);
			if (CM_DEFAULT_KEY_TOKEN != NULL) {
				entry->cm_key_token = talloc_strdup(entry, CM_DEFAULT_KEY_TOKEN);
			}
			if (CM_DEFAULT_KEY_NICKNAME != NULL) {
				entry->cm_key_nickname = talloc_strdup(entry, CM_DEFAULT_KEY_NICKNAME);
			}
		}
		entry->cm_state = keygen ? CM_NEED_KEY_PAIR : CM_NEED_CSR;
		if (certfile != NULL) {
			entry->cm_cert_storage_default = 0;
			entry->cm_cert_storage_type = cm_cert_storage_file;
			entry->cm_cert_storage_location = talloc_strdup(entry,
									certfile);
		} else
		if ((dbdir != NULL) && (nickname != NULL)) {
			entry->cm_cert_storage_default = 0;
			entry->cm_cert_storage_type = cm_cert_storage_nssdb;
			entry->cm_cert_storage_location = talloc_strdup(entry, dbdir);
			entry->cm_cert_token = talloc_strdup(entry, token);
			entry->cm_cert_nickname = talloc_strdup(entry, nickname);
		} else {
			entry->cm_cert_storage_default = 0;
			entry->cm_cert_storage_type = CM_DEFAULT_CERT_STORAGE_TYPE;
			entry->cm_cert_storage_location = talloc_strdup(entry, CM_DEFAULT_CERT_STORAGE_LOCATION);
			if (CM_DEFAULT_CERT_TOKEN != NULL) {
				entry->cm_cert_token = talloc_strdup(entry, CM_DEFAULT_CERT_TOKEN);
			}
			if (CM_DEFAULT_CERT_NICKNAME != NULL) {
				entry->cm_cert_nickname = talloc_strdup(entry, CM_DEFAULT_CERT_NICKNAME);
			}
			return 1;
		}
		entry->cm_notification_default = 1;
		if (subject != NULL) {
			entry->cm_template_subject = talloc_strdup(entry,
								   subject);
		} else {
			memset(cn_template, '\0', sizeof(cn_template));
			strcpy(cn_template, "CN=");
			if (gethostname(cn_template + 3,
					sizeof(cn_template) - 3 - 1) != 0) {
				strcpy(cn_template, "CN=localhost");
			}
			entry->cm_template_subject = talloc_strdup(entry,
								   cn_template);
		}
		if (ca == NULL) {
			entry->cm_ca_type = cm_ca_dummy;
		}
		if (track_exp) {
			entry->cm_monitor = 1;
			entry->cm_monitor_default = 0;
		} else {
			entry->cm_monitor_default = 1;
		}
		if (auto_renew) {
			entry->cm_autorenew = 1;
			entry->cm_autorenew_default = 0;
		} else {
			entry->cm_autorenew_default = 1;
		}
		if (cm_store_entry_save(entry) == 0) {
			printf("Request added.\n");
			talloc_free(entry);
			return 0;
		} else {
			printf("Error adding request.\n");
			talloc_free(entry);
			return 1;
		}
	} else {
		printf("Error creating template request.\n");
		talloc_free(entry);
		return 1;
	}
}

static int
start_tracking(const char *argv0, int argc, char **argv)
{
	return 0;
}

static int
stop_tracking(const char *argv0, int argc, char **argv)
{
	return 0;
}

static int
list(const char *argv0, int argc, char **argv)
{
	struct cm_store_entry **entries;
	const char *key_storage = NULL, *cert_storage = NULL;
	char token[LINE_MAX], nickname[LINE_MAX], ca[LINE_MAX];
	int requests_only = 0, tracking_only = 0, c, i;
	while ((c = getopt(argc, argv, "rt")) != -1) {
		switch (c) {
		case 'r':
			requests_only++;
			break;
		case 't':
			tracking_only++;
			break;
		default:
			help(argv0, "list");
			return 1;
		}
	}
	entries = cm_store_get_all_entries(NULL);
	for (i = 0; (entries != NULL) && (entries[i] != NULL); i++) {
		switch (entries[i]->cm_state) {
		case CM_INVALID:
			printf("'%s' is in an invalid state!\n",
			       entries[i]->cm_id);
			continue;
			break;
		case CM_NEED_KEY_PAIR:
		case CM_GENERATING_KEY_PAIR:
		case CM_HAVE_KEY_PAIR:
		case CM_NEED_CSR:
		case CM_GENERATING_CSR:
		case CM_HAVE_CSR:
		case CM_NEED_TO_SUBMIT:
		case CM_SUBMITTING:
		case CM_HAVE_SUBMITTED:
		case CM_NEED_CA_STATUS:
		case CM_POLLING_CA_STATUS:
		case CM_RETRIEVING_CERT:
		case CM_NEED_TO_SAVE_CERT:
		case CM_SAVING_CERT:
		case CM_SAVED_CERT:
		case CM_NEED_GUIDANCE:
			if (tracking_only) {
				continue;
			}
			break;
		case CM_MONITORING:
		case CM_NOTIFYING:
			if (requests_only) {
				continue;
			}
			break;
		}
		switch (entries[i]->cm_key_storage_type) {
		case cm_key_storage_file:
			key_storage = "file";
			break;
		case cm_key_storage_nssdb:
			key_storage = "nssdb";
			break;
		}
		switch (entries[i]->cm_cert_storage_type) {
		case cm_cert_storage_file:
			cert_storage = "file";
			break;
		case cm_cert_storage_nssdb:
			cert_storage = "nssdb";
			break;
		}
		printf("Request '%s'\n", entries[i]->cm_id);
		strcpy(ca, "(unknown)");
		switch (entries[i]->cm_ca_type) {
		case cm_ca_dummy:
			strcpy(ca, "dummy(local)");
			break;
		}
		printf("           CA: %s\n", ca);
		printf("        state: %s\n",
		       cm_store_state_as_string(entries[i]->cm_state));
		if (entries[i]->cm_key_token != NULL) {
			sprintf(token, ",token='%s'",
				entries[i]->cm_key_token);
		} else {
			strcpy(token, "");
		}
		if (entries[i]->cm_key_nickname != NULL) {
			sprintf(nickname, ",nickname='%s'",
				entries[i]->cm_key_nickname);
		} else {
			strcpy(nickname, "");
		}
		printf("     key pair: type=%s,location='%s'%s%s\n",
		       key_storage, entries[i]->cm_key_storage_location,
		       token, nickname);
		if (entries[i]->cm_cert_token != NULL) {
			sprintf(token, ",token='%s'",
				entries[i]->cm_cert_token);
		} else {
			strcpy(token, "");
		}
		if (entries[i]->cm_cert_nickname != NULL) {
			sprintf(nickname, ",nickname='%s'",
				entries[i]->cm_cert_nickname);
		} else {
			strcpy(nickname, "");
		}
		printf("  certificate: type=%s,location='%s'%s%s\n",
		       cert_storage, entries[i]->cm_cert_storage_location,
		       token, nickname);
		printf("      monitor: %s\n",
		       entries[i]->cm_monitor ? "yes" : "no");
		printf("   auto-renew: %s\n",
		       entries[i]->cm_autorenew ? "yes" : "no");
	}
	talloc_free(entries);
	return 0;
}

static struct {
	const char *verb;
	int (*fn)(const char *, int, char **);
} verbs[] = {
	{"request", request},
	{"start-tracking", start_tracking},
	{"stop-tracking", stop_tracking},
	{"list", list},
};

static void
help(const char *cmd, const char *category)
{
	unsigned int i;
	struct {
		const char *category;
		const char *msg;
	} msgs[] = {
	{NULL,
	"%s - client certificate enrollment tool\n"
	"Example command-line invocations:\n",},
	{"request",
	"%s request [options]\n"
	"* If the client knows or wants to override where the CA is:\n"
	"  -c		location of CA\n"
	"* If we need to generate a key (i.e., if the one to use is not found):\n"
	"  -g		generate a new key\n"
	"  -G size	size of new key\n"
	"* Whether we generate a key or not:\n"
	"  -d DIR	NSS database for key and cert\n"
	"  -n NAME	nickname for NSS-based storage (only valid with -d)\n"
	"  -k FILE	PEM file for private key\n"
	"  -f FILE	PEM file for certificate (only valid with -k)\n"
	"* Whether or not to track expiration:\n"
	"  -e		track-expiration\n"
	"  -r		attempt to renew as expiration nears\n"
	"* Optional stuff:\n"
	"  -S NAME	requested subject name (default: CN=<hostname>)\n"
	"  -u USAGE	requested usage / eku\n"
	"  -s name	requested service name part (used to derive principal name)\n",},
	{"start-tracking",
	"%s start-tracking\n"
	"* General options:\n"
	"  -d DIR	NSS database for key and cert\n"
	"  -n NAME	nickname for NSS-based storage (only valid with -d)\n"
	"  -k FILE	PEM file for private key\n"
	"  -f FILE	PEM file for certificate (only valid with -k)\n"
	"* If the client knows or wants to override where the CA is:\n"
	"  -c		location of CA\n",},
	{"stop-tracking",
	"%s stop-tracking\n"
	"* General options:\n"
	"  -s NUM	serial number of certificate\n"
	"  -I NAME	issuer of certificate\n"
	"  -S KEYID	subject key identifier for certificate\n"
	"* In case the serial number corresponds to more than one certificate, and the\n"
	"  key identifier is not known:\n"
	"  -d DIR	NSS database for key and cert\n"
	"  -n NAME	nickname for NSS-based storage (only valid with -d)\n"
	"  -k FILE	PEM file for private key\n"
	"  -f FILE	PEM file for certificate (only valid with -k)\n"
	"* If the client knows or wants to override where the CA is:\n"
	"  -c		location of CA\n",},
	{"list",
	"%s list\n"
	"* General options:\n"
	"  -r		list only information about outstanding requests\n"
	"  -t		list only information about tracked certificates\n"}};
	for (i = 0; i < sizeof(msgs) / sizeof(msgs[0]); i++) {
		if ((category != NULL) && (msgs[i].category != NULL) &&
		    (strcmp(category, msgs[i].category) != 0)) {
			continue;
		}
		if (i > 0) {
			printf("\n");
		}
		printf(msgs[i].msg, cmd);
	}
}

int
main(int argc, char **argv)
{
	const char *verb, *p;
	unsigned int i;
	p = argv[0];
	if (strchr(p, '/') != NULL) {
		p = strrchr(p, '/') + 1;
	}
	if (argc > 1) {
		verb = argv[1];
		for (i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
			if (strcmp(verbs[i].verb, verb) == 0) {
				return (*verbs[i].fn)(p, argc - 1, argv + 1);
			}
		}
		fprintf(stderr, "%s: unrecognized command\n", verb);
		return 1;
	} else {
		help(p, NULL);
		return 1;
	}
}
