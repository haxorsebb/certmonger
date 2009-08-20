#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <talloc.h>

#include "certsave.h"
#include "certsave-int.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_certsave_state {
	struct cm_certsave_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, count, status;
};

static void
cm_certsave_o_main(struct cm_store_entry *entry)
{
	int status = -1;
	BIO *bio;
	FILE *pem;
	X509 *cert;
	bio = BIO_new_mem_buf(entry->cm_cert, strlen(entry->cm_cert));
	if (bio != NULL) {
		cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (cert != NULL) {
			pem = fopen(entry->cm_cert_storage_location, "w");
			if (pem != NULL) {
				if (PEM_write_X509(pem, cert) == 0) {
					cm_log(1, "Error saving cert.\n");
				} else {
					status = 0;
				}
				fclose(pem);
			}
			X509_free(cert);
		}
		BIO_free(bio);
	}
	if (status != 0) {
		_exit(status);
	}
}
/* Check if something changed, for example we finished saving the cert. */
static int
cm_certsave_o_ready(struct cm_store_entry *entry,
		    struct cm_certsave_state *state)
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

/* Check if we saved the certificate -- the child exited with status 0. */
static int
cm_certsave_o_saved(struct cm_store_entry *entry,
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

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certsave_o_get_fd(struct cm_store_entry *entry,
		     struct cm_certsave_state *state)
{
	return state->fd;
}

/* Clean up after saving the certificate. */
static void
cm_certsave_o_done(struct cm_store_entry *entry,
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
cm_certsave_o_start(struct cm_store_entry *entry)
{
	int fds[2];
	long flags;
	struct cm_certsave_state *state;
	if (entry->cm_cert_storage_type != cm_cert_storage_file) {
		cm_log(1, "Wrong save method: can only save certificates "
		       "to files.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_certsave_o_ready;
		state->pvt.get_fd= cm_certsave_o_get_fd;
		state->pvt.saved= cm_certsave_o_saved;
		state->pvt.done= cm_certsave_o_done;
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
				cm_certsave_o_main(entry);
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
