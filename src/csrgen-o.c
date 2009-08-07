#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "keygen.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_csrgen_state {
	char msg[0x10000];
	pid_t pid;
	int fd, status;
};

static void
cm_csrgen_main(int fd, struct cm_store_entry *entry)
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
									   s + 1, q - s - 1,
									   -1, 0);
						*s = '=';
					} else {
						X509_NAME_add_entry_by_txt(x->cert_info->subject,
									   "CN", MBSTRING_UTF8,
									   p, q - p,
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

/* Start CSR generation using template information in the entry. */
struct cm_csrgen_state *
cm_csrgen_start(struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_csrgen_state *state;
	state = malloc(sizeof(*state));
	if (state != NULL) {
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
				cm_csrgen_main(fds[1], entry);
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

/* Check if a CSR is ready. */
int
cm_csrgen_ready(struct cm_store_entry *entry, struct cm_csrgen_state *state)
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
int
cm_csrgen_get_fd(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	return state->fd;
}

/* Save the CSR to the entry. */
int
cm_csrgen_save_csr(struct cm_store_entry *entry, struct cm_csrgen_state *state)
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
void
cm_csrgen_done(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}
