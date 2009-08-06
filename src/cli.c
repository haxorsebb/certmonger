#include "config.h"

#include <sys/types.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cm.h"
#include "store.h"
#include "store-int.h"

static void help(const char *cmd);

static int
request(int argc, char **argv)
{
	struct cm_store_entry *entry;
	const char *ca = NULL;
	const char *dbdir = NULL, *nickname = NULL;
	const char *keyfile = NULL, *certfile = NULL;
	const char *subject = NULL, *service = NULL, *usage = NULL;
	int keygen = 0, keysize = 0, track_exp = 0, auto_renew = 0, c;
	while ((c = getopt(argc, argv, "c:gG:d:n:k:f:S:s:u:er")) != -1) {
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
			help("request");
			return 1;
		}
	}
	entry = cm_store_entry_new();
	if (entry != NULL) {
		entry->cm_key_type_default = 1;
		if (keyfile != NULL) {
			entry->cm_key_storage_default = 0;
			entry->cm_key_storage_type = cm_key_storage_file;
			entry->cm_key_storage_location = strdup(keyfile);
		} else {
			printf("Don't know how to do non-file keys yet.\n");
			return 1;
		}
		entry->cm_state = keygen ? CM_NEED_KEY_PAIR : CM_NEED_CSR;
		if (certfile != NULL) {
			entry->cm_cert_storage_default = 0;
			entry->cm_cert_storage_type = cm_cert_storage_file;
			entry->cm_cert_storage_location = strdup(keyfile);
		} else {
			printf("Don't know how to do non-file keys yet.\n");
			return 1;
		}
		entry->cm_notification_default = 1;
		if (cm_store_entry_save(entry) == 0) {
			printf("Request added.\n");
			cm_store_entry_free(entry);
			return 0;
		} else {
			printf("Error adding request.\n");
			cm_store_entry_free(entry);
			return 1;
		}
	} else {
		printf("Error creating template request.\n");
		cm_store_entry_free(entry);
		return 1;
	}
}

static int
start_tracking(int argc, char **argv)
{
	return 0;
}

static int
stop_tracking(int argc, char **argv)
{
	return 0;
}

static int
list(int argc, char **argv)
{
	struct cm_store_entry **entries;
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
			help("request");
			return 1;
		}
	}
	entries = cm_store_get_all_entries();
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
		case CM_NEED_GUIDANCE:
			if (tracking_only) {
				continue;
			}
			break;
		case CM_MONITORING:
			if (requests_only) {
				continue;
			}
			break;
		}
		printf("'%s': %s\n",
		       entries[i]->cm_id,
		       cm_store_state_as_string(entries[i]->cm_state));
	}
	return 0;
}

static struct {
	const char *verb;
	int (*fn)(int, char **);
} verbs[] = {
	{"request", request},
	{"start-tracking", start_tracking},
	{"stop-tracking", stop_tracking},
	{"list", list},
};

static void
help(const char *cmd)
{
	unsigned int i;
	const char *msgs[] = {
	"%s - client certificate enrollment tool\n"
	"Example command-line invocations:\n",
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
	"  -S NAME	requested subject name (default: cn=<fqdn>)\n"
	"  -u USAGE	requested usage / eku\n"
	"  -s name	requested service name part (used to derive principal name)\n",
	"%s start-tracking\n"
	"* General options:\n"
	"  -d DIR	NSS database for key and cert\n"
	"  -n NAME	nickname for NSS-based storage (only valid with -d)\n"
	"  -k FILE	PEM file for private key\n"
	"  -f FILE	PEM file for certificate (only valid with -k)\n"
	"* If the client knows or wants to override where the CA is:\n"
	"  -c		location of CA\n",
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
	"  -c		location of CA\n",
	"%s list\n"
	"* General options:\n"
	"  -r		list only information about outstanding requests\n"
	"  -t		list only information about tracked certificates\n"};
	for (i = 0; i < sizeof(msgs) / sizeof(msgs[0]); i++) {
		if (i > 0) {
			printf("\n");
		}
		printf(msgs[i], cmd);
	}
}

int
main(int argc, char **argv)
{
	const char *verb, *p;
	unsigned int i;
	if (argc > 1) {
		verb = argv[1];
		for (i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
			if (strcmp(verbs[i].verb, verb) == 0) {
				return (*verbs[i].fn)(argc - 1, argv + 1);
			}
		}
		fprintf(stderr, "%s: unrecognized command\n", verb);
		return 1;
	} else {
		p = argv[0];
		if (strchr(p, '/') != NULL) {
			p = strrchr(p, '/') + 1;
		}
		help(p);
		return 1;
	}
}
