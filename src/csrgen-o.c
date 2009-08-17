#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "csrgen.h"
#include "csrgen-int.h"
#include "keygen.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_csrgen_state {
	struct cm_csrgen_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, count, status;
};

static void
cm_csrgen_o_main(int fd, struct cm_store_entry *entry)
{
	FILE *keyfp, *status;
	X509 *x;
	X509_REQ *req;
	RSA *rsa;
	EVP_PKEY *pkey;
	char buf[LINE_MAX], *p, *q, *s;
	long error;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(1);
	}
	keyfp = fopen(entry->cm_key_storage_location, "r");
	if (keyfp == NULL) {
		fprintf(status, "Error opening key file \"%s\" for reading.\n",
			entry->cm_key_storage_location);
		cm_log(1, "Error opening key file \"%s\" for reading.\n",
		       entry->cm_key_storage_location);
		_exit(2);
	}
	OpenSSL_add_ssl_algorithms();
	ERR_load_crypto_strings();
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		fprintf(status, "Internal error generating CSR.\n");
		cm_log(1, "Internal error generating CSR.\n");
		_exit(2);
	}
	rsa = PEM_read_RSAPrivateKey(keyfp, NULL, NULL, NULL);
	if (rsa != NULL) {
		EVP_PKEY_assign_RSA(pkey, rsa); /* pkey owns rsa now */
		x = X509_new();
		if (x != NULL) {
			if (entry->cm_template_subject != NULL) {
				/* This isn't really correct, but it will
				 * probably do for now. */
				p = entry->cm_template_subject;
				q = p + strcspn(p, ",");
				while (*p != '\0') {
					if ((s = memchr(p, '=', q - p)) != NULL) {
						*s = '\0';
						X509_NAME_add_entry_by_txt(x->cert_info->subject,
									   p, MBSTRING_UTF8,
									   (unsigned char *) (s + 1), q - s - 1,
									   -1, 0);
						*s = '=';
					} else {
						X509_NAME_add_entry_by_txt(x->cert_info->subject,
									   "CN", MBSTRING_UTF8,
									   (unsigned char *) p, q - p,
									   -1, 0);
					}
					p = q + strspn(q, ",");
					q = p + strcspn(p, ",");
				}
			}
			X509_set_pubkey(x, pkey);
			req = X509_to_X509_REQ(x, pkey, EVP_sha256());
			if (req != NULL) {
				PEM_write_X509_REQ_NEW(status, req);
			} else {
				fprintf(status,
					"Error converting template certificate "
					"into a CSR.\n");
				cm_log(1,
				       "Error converting template certificate "
				       "into a CSR.\n");
				while ((error = ERR_get_error()) != 0) {
					ERR_error_string_n(error, buf,
							   sizeof(buf));
					cm_log(1, "%s\n", buf);
				}
				_exit(2);
			}
		} else {
			fprintf(status,
				"Error creating template certificate.\n");
			cm_log(1, "Error creating template certificate.\n");
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(2);
		}
	} else {
		error = errno;
		fprintf(status, "Error reading private key '%s': %s.\n",
		        entry->cm_key_storage_location, strerror(error));
		cm_log(1, "Error reading private key '%s': %s.\n",
		       entry->cm_key_storage_location, strerror(error));
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		_exit(2);
	}
	while ((error = ERR_get_error()) != 0) {
		ERR_error_string_n(error, buf, sizeof(buf));
		cm_log(1, "%s\n", buf);
	}
	fflush(status);
	fclose(status);
	fclose(keyfp);
}

/* Check if a CSR is ready. */
static int
cm_csrgen_o_ready(struct cm_store_entry *entry, struct cm_csrgen_state *state)
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
cm_csrgen_o_get_fd(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	return state->fd;
}

/* Save the CSR to the entry. */
static int
cm_csrgen_o_save_csr(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state)
{
	free(entry->cm_csr);
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
	return 0;
}

/* Clean up after CSR generation. */
static void
cm_csrgen_o_done(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}

/* Start CSR generation using template information in the entry. */
struct cm_csrgen_state *
cm_csrgen_o_start(struct cm_store_entry *entry)
{
	int fds[2];
	long flags;
	struct cm_csrgen_state *state;
	state = malloc(sizeof(*state));
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = &cm_csrgen_o_ready;
		state->pvt.get_fd = &cm_csrgen_o_get_fd;
		state->pvt.save_csr = &cm_csrgen_o_save_csr;
		state->pvt.done = &cm_csrgen_o_done;
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
				cm_csrgen_o_main(fds[1], entry);
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
