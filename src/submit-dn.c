#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <nss.h>
#include <cert.h>
#include <certt.h>
#include <pk11pub.h>

#include "log.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"

struct cm_submit_state {
	char msg[0x10000];
	pid_t pid;
	int fd, status;
};

static void
cm_submit_main(int fd, struct cm_store_entry *entry)
{
	FILE *pem;
	int status;
	long error;
	char buf[LINE_MAX];

	status = -1;
	if (status == 0) {
		pem = fdopen(fd, "w");
		if (pem == NULL) {
			status = -1;
		}
	}
	if (status != 0) {
		_exit(status);
	}
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_start(struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_submit_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		cm_log(1, "Wrong submission method: only keys stored "
		       "in an NSS database can be used.\n");
		return NULL;
	}
	if (entry->cm_cert_storage_type != cm_cert_storage_nssdb) {
		cm_log(1, "Wrong submission method: only certificates stored "
		       "in an NSS database can be used.\n");
		return NULL;
	}
	state = malloc(sizeof(*state));
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->fd = -1;
		if (pipe(fds) != -1) {
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(fds[0]);
				close(fds[1]);
				free(state);
				state = NULL;
				break;
			case 0:
				close(fds[0]);
				cm_submit_main(fds[1], entry);
				_exit(0);
				break;
			default:
				state->fd = fds[0];
				close(fds[1]);
				break;
			}
		}
	}
	return state;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_submit_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return state->fd;
}

/* Check if the CSR was received by the CA yet. */
int
cm_submit_sent(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return 0;
}

/* Save CA-specific identifier for our submitted request. */
int
cm_submit_save_ca_cookie(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	free(entry->cm_ca_cookie);
	entry->cm_ca_cookie = strdup(entry->cm_key_storage_location);
	if (entry->cm_ca_cookie == NULL) {
		cm_log(1, "Out of memory.\n");
		return ENOMEM;
	}
	return 0;
}

/* Pick up after a CSR has been "submitted", in case we haven't yet gotten a
 * decision about it. */
struct cm_submit_state *
cm_submit_resume(struct cm_store_entry *entry)
{
	struct cm_submit_state *state;
	state = cm_submit_start(entry);
	cm_submit_save_ca_cookie(entry, state);
	return state;
}

/* Check if an attempt to get status has succeeded. */
int
cm_submit_status_ready(struct cm_store_entry *entry,
		       struct cm_submit_state *state)
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
	free(entry->cm_cert);
	entry->cm_cert = strdup(state->msg);
	return 0;
}

/* Check if the certificate was issued. */
int
cm_submit_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if ((strstr(state->msg, "-----BEGIN CERTIFICATE-----") != NULL) &&
	    (strstr(state->msg, "-----END CERTIFICATE-----") != NULL)) {
		return 0;
	}
	return -1;
}

/* Check if we need to make another request to actually retrieve the cert. */
int
cm_submit_needs_retrieval(struct cm_store_entry *entry,
			  struct cm_submit_state *state)
{
	return -1; /* already have data, no additional retrieval step needed */
}

/* Save the certificate to the location specified in the entry. */
int
cm_submit_save_cert(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return -1;
}

/* Done talking to the CA. */
void
cm_submit_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}
