#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>
#include <prerror.h>

#include <talloc.h>

#include "certsave.h"
#include "certsave-int.h"
#include "log.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"

struct cm_certsave_state {
	struct cm_certsave_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, status;
};

static void
cm_certsave_n_main(struct cm_store_entry *entry)
{
	int status = 1;
	PLArenaPool *arena;
	SECStatus error;
	SECItem *item;
	char *p, *q;
	CERTCertDBHandle *certdb;
	/* Open the database. */
	error = NSS_InitReadWrite(entry->cm_cert_storage_location);
	if (error != SECSuccess) {
		cm_log(1, "Unable to open NSS database.\n");
	} else {
		/* Allocate a memory pool. */
		arena = PORT_NewArena(sizeof(double));
		if (arena == NULL) {
			cm_log(1, "Error opening database '%s'.\n",
			       entry->cm_key_storage_location);
			NSS_Shutdown();
			_exit(ENOMEM);
		}
		certdb = CERT_GetDefaultCertDB();
		if (certdb != NULL) {
			/* Handle the base64 decode. */
			p = entry->cm_cert;
			q = NULL;
			while (strncmp(p, "-----BEGIN ", 11) == 0) {
				p += strcspn(p, "\r\n");
				p += strspn(p, "\r\n");
			}
			q = strstr(p, "-----END");
			if ((p == NULL) || (q == NULL)) {
				cm_log(1, "Unable to parse certificate.\n");
				_exit(1);
			}
			/* Handle the base64 decode. */
			item = NSSBase64_DecodeBuffer(arena, NULL, p, q - p);
			if (item == NULL) {
				cm_log(1, "Unable to decode certificate "
				       "into buffer.\n");
				_exit(1);
			}
			error = CERT_ImportCerts(certdb,
						 certUsageUserCertImport,
						 1, &item, NULL, PR_TRUE,
						 PR_FALSE,
						 entry->cm_cert_nickname);
			if (error == SECSuccess) {
				status = 0;
			} else {
				cm_log(1, "Error importing certificate "
				       "into NSSDB: %s.\n",
				       PR_ErrorToString(error,
							PR_LANGUAGE_I_DEFAULT));
			}
		} else {
			cm_log(1, "Error getting handle to default NSS DB.\n");
		}
		if (NSS_Shutdown() != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
	}
	if (status != 0) {
		_exit(status);
	}
}

/* Check if something changed, for example we finished saving the cert. */
static int
cm_certsave_n_ready(struct cm_store_entry *entry,
		    struct cm_certsave_state *state)
{
	ssize_t i, remainder;
	char *p;
	p = state->msg;
	remainder = sizeof(state->msg) - 1;
	while ((i = read(state->fd, p, remainder)) > 0) {
		p += i;
		remainder -= i;
	}
	*p = '\0';
	close(state->fd);
	state->fd = -1;
	waitpid(state->pid, &state->status, 0);
	state->pid = -1;
	return 0;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certsave_n_get_fd(struct cm_store_entry *entry,
		     struct cm_certsave_state *state)
{
	return state->fd;
}

/* Check if we saved the certificate -- the child exited with status 0. */
static int
cm_certsave_n_saved(struct cm_store_entry *entry,
		    struct cm_certsave_state *state)
{
	if (state->pid == -1) {
		if (!WIFEXITED(state->status) ||
		    (WEXITSTATUS(state->status) != 0)) {
			return -1;
		}
		return 0;
	}
	return -1;
}

/* Clean up after saving the certificate. */
static void
cm_certsave_n_done(struct cm_store_entry *entry,
		   struct cm_certsave_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Start writing the certificate from the entry to the configured location. */
struct cm_certsave_state *
cm_certsave_n_start(struct cm_store_entry *entry)
{
	int fds[2];
	long flags;
	struct cm_certsave_state *state;
	if (entry->cm_cert_storage_type != cm_cert_storage_nssdb) {
		cm_log(1, "Wrong save method: can only save certificates "
		       "files an NSS database.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_certsave_n_ready;
		state->pvt.get_fd= cm_certsave_n_get_fd;
		state->pvt.saved= cm_certsave_n_saved;
		state->pvt.done= cm_certsave_n_done;
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
				cm_certsave_n_main(entry);
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
