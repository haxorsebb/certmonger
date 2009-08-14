#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "log.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"

struct cm_certsave_state {
	char msg[0x10000];
	pid_t pid;
	int fd, status;
};

static void
cm_certsave_main(struct cm_store_entry *entry)
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

/* Start writing the certificate from the entry to the configured location. */
struct cm_certsave_state *
cm_certsave_start(struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_certsave_state *state;
	if (entry->cm_cert_storage_type != cm_cert_storage_file) {
		cm_log(1, "Wrong save method: can only save certificates "
		       "to files.\n");
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
				cm_certsave_main(entry);
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

/* Check if something changed, for example we finished saving the cert. */
int
cm_certsave_ready(struct cm_store_entry *entry, struct cm_certsave_state *state)
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

/* Check if we saved the certificate -- the child exited with status 0. */
int
cm_certsave_saved(struct cm_store_entry *entry, struct cm_certsave_state *state)
{
	if (state->pid == -1) {
		if (!WIFEXITED(state->status) ||
		    (WEXITSTATUS(state->status) != 0)) {
			return 0;
		}
		entry->cm_csr = strdup(state->msg);
		if (entry->cm_csr == NULL) {
			return ENOMEM;
		}
	}
	return -1;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_certsave_get_fd(struct cm_store_entry *entry,
		   struct cm_certsave_state *state)
{
	return state->fd;
}

/* Clean up after saving the certificate. */
void
cm_certsave_done(struct cm_store_entry *entry, struct cm_certsave_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}
