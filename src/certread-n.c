#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>
#include <prerror.h>

#include <talloc.h>

#include "certread.h"
#include "certread-int.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_certread_state {
	struct cm_certread_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, count, status;
};

static int
cm_certread_atoi_n(const char *p, int n)
{
	char s[n + 1];
	memcpy(s, p, n);
	s[n] = '\0';
	return atoi(s);
}

static void
cm_certread_n_main(int fd, struct cm_store_entry *entry)
{
	int status = 1;
	unsigned int i;
	const char *token, *p;
	struct tm tm;
	PLArenaPool *arena;
	SECStatus error;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	PK11SlotInfo *slot;
	CERTCertList *certs;
	CERTCertListNode *node;
	CERTCertificate *cert;
	CK_MECHANISM_TYPE mech;
	FILE *fp;
	/* Open the status descriptor for stdio. */
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		cm_log(1, "Unable to initialize I/O.\n");
		_exit(1);
	}
	/* Open the database. */
	error = NSS_InitReadWrite(entry->cm_cert_storage_location);
	if (error != SECSuccess) {
		cm_log(1, "Unable to open NSS database.\n");
		_exit(1);
	}
	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Error opening database '%s'.\n",
		       entry->cm_cert_storage_location);
		if (NSS_Shutdown() != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(ENOMEM);
	}
	/* Find the tokens that we might use for cert storage. */
	mech = 0;
	slotlist = PK11_GetAllTokens(mech, PR_FALSE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		cm_log(1, "Error locating slot used for cert storage.\n");
		if (NSS_Shutdown() != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}
	/* Walk the list looking for the requested slot, or the first one if
	 * none was requested. */
	slot = NULL;
	for (sle = slotlist->head;
	     ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		token = PK11_GetTokenName(sle->slot);
		if (token != NULL) {
			cm_log(3, "Found token '%s'.\n", token);
		}
		if ((entry->cm_cert_token == NULL) ||
		    (strlen(entry->cm_cert_token) == 0) ||
		    (strcmp(entry->cm_cert_token, token) == 0)) {
			slot = sle->slot;
			break;
		}
		if (sle == slotlist->tail) {
			break;
		}
	}
	if (slot == NULL) {
		cm_log(1, "Error locating slot used for cert storage.\n");
		PK11_FreeSlotList(slotlist);
		if (NSS_Shutdown() != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}

	/* Walk the list of certificates in the slot, looking for one which
	 * matches the specified nickname. */
	certs = PK11_ListCertsInSlot(slot);
	if (certs == NULL) {
		cm_log(1, "Token contains no certificates!\n");
		PK11_FreeSlotList(slotlist);
		if (NSS_Shutdown() != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}
	cert = NULL;
	for (i = 1, node = CERT_LIST_HEAD(certs);
	     !CERT_LIST_EMPTY(certs) &&
	     !CERT_LIST_END(node, certs);
	     node = CERT_LIST_NEXT(node)) {
		if (strcmp(node->cert->nickname,
			   entry->cm_cert_nickname) == 0) {
			cm_log(3, "Located the certificate.\n");
			cert = node->cert;
			break;
		}
	}
	if (cert != NULL) {
		fprintf(fp, " %s\n", cert->issuerName);
		for (i = 0; i < cert->serialNumber.len; i++) {
			fprintf(fp, "%s%02x", (i > 0) ? ":" : " ",
				cert->serialNumber.data[i] & 0xff);
		}
		fprintf(fp, "\n %s\n", cert->subjectName);
		for (i = 0; i < cert->subjectID.len; i++) {
			fprintf(fp, "%s%02x", (i > 0) ? ":" : " ",
				cert->subjectID.data[i] & 0xff);
		}
		memset(&tm, 0, sizeof(tm));
		p = (const char *) cert->validity.notAfter.data;
		switch (cert->validity.notAfter.len) {
		case 13:
			tm.tm_year = cm_certread_atoi_n(p, 2);
			if (tm.tm_year < 50) {
				tm.tm_year += 100;
			}
			p += 2;
			break;
		case 15:
			tm.tm_year = cm_certread_atoi_n(p, 4) - 1900;
			p += 4;
			break;
		default:
			p = NULL;
			break;
		}
		if (p != NULL) {
			tm.tm_mon = cm_certread_atoi_n(p, 2) - 1;
			p += 2;
			tm.tm_mday = cm_certread_atoi_n(p, 2);
			p += 2;
			tm.tm_hour = cm_certread_atoi_n(p, 2);
			p += 2;
			tm.tm_min = cm_certread_atoi_n(p, 2);
			p += 2;
			tm.tm_sec = cm_certread_atoi_n(p, 2);
			p += 2;
		}
		fprintf(fp, "\n %lu\n", (unsigned long) timegm(&tm));
	}
	CERT_DestroyCertList(certs);
	PK11_FreeSlotList(slotlist);
	if (NSS_Shutdown() != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	fclose(fp);
	if (status != 0) {
		_exit(status);
	}
}

/* Check if something changed, for example we finished reading the data we need
 * from the cert. */
static int
cm_certread_n_ready(struct cm_store_entry *entry,
		    struct cm_certread_state *state)
{
	ssize_t i, remainder;
	int status;
	do {
		remainder = (sizeof(state->msg) - state->count) - 1;
		i = read(state->fd, state->msg + state->count, remainder);
		switch (i) {
		case -1:
		case 0:
			break;
		default:
			state->count += i;
			break;
		}
	} while (i > 0);
	if ((i == -1) && ((errno == EAGAIN) || (errno == EINTR))) {
		status = -1;
	} else {
		state->msg[state->count] = '\0';
		close(state->fd);
		state->fd = -1;
		waitpid(state->pid, &state->status, 0);
		state->pid = -1;
		status = 0;
	}
	return status;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certread_n_get_fd(struct cm_store_entry *entry,
		     struct cm_certread_state *state)
{
	return state->fd;
}

/* Clean up after reading the certificate. */
static void
cm_certread_n_done(struct cm_store_entry *entry,
		   struct cm_certread_state *state)
{
	const char *p, *q;
	char *s;
	int i;
	if (state->count > 0) {
		p = state->msg;
		i = 0;
		while (*p != '\0') {
			/* Skip over the first character. */
			p++;
			/* Find the end of the line. */
			q = p + strcspn(p, "\r\n");
			/* Decide what to do with the data. */
			switch (i++) {
			case 0:
				talloc_free(entry->cm_cert_issuer);
				entry->cm_cert_issuer = talloc_strndup(entry, p,
								       q - p);
				break;
			case 1:
				talloc_free(entry->cm_cert_serial);
				entry->cm_cert_serial = talloc_strndup(entry, p,
								       q - p);
				break;
			case 2:
				talloc_free(entry->cm_cert_subject);
				entry->cm_cert_subject = talloc_strndup(entry,
									p,
								        q - p);
				break;
			case 3:
				talloc_free(entry->cm_cert_spki);
				entry->cm_cert_spki = talloc_strndup(entry, p,
								     q - p);
				break;
			case 4:
				s = talloc_strndup(entry, p, q - p);
				entry->cm_cert_expiration = atol(s);
				talloc_free(s);
				break;
			}
			/* Find the beginning of the next line. */
			p = q + strspn(q, "\r\n");
		}
	}
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Start reading the certificate from the configured location. */
struct cm_certread_state *
cm_certread_n_start(struct cm_store_entry *entry)
{
	int fds[2];
	long flags;
	struct cm_certread_state *state;
	if (entry->cm_cert_storage_type != cm_cert_storage_nssdb) {
		cm_log(1, "Wrong read method: can only read certificates "
		       "from an NSS database.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_certread_n_ready;
		state->pvt.get_fd= cm_certread_n_get_fd;
		state->pvt.done= cm_certread_n_done;
		state->fd = -1;
		if (pipe(fds) != -1) {
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(fds[0]);
				close(fds[1]);
				talloc_free(state);
				state = NULL;
				break;
			case 0:
				close(fds[0]);
				cm_certread_n_main(fds[1], entry);
				_exit(0);
				break;
			default:
				state->fd = fds[0];
				flags = fcntl(state->fd, F_GETFL);
				fcntl(state->fd, F_SETFL, flags | O_NONBLOCK);
				close(fds[1]);
				break;
			}
		}
	}
	return state;
}
