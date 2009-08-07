#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "keygen.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_keygen_state {
	char msg[0x10000];
	pid_t pid;
	int fd, status;
};

static void
cm_keygen_main(int fd, struct cm_store_entry *entry)
{
	FILE *fp, *status;
	RSA *rsa;
	EVP_PKEY *pkey;
	char buf[LINE_MAX];
	long error;
	enum cm_key_algorithm cm_key_algorithm;
	int cm_key_size;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(1);
	}
	if (entry->cm_key_type_default) {
		cm_key_algorithm = cm_key_rsa; /* XXX */
		cm_key_size = 2048; /* XXX */
	} else {
		cm_key_algorithm = entry->cm_key_type.cm_key_algorithm;
		cm_key_size = entry->cm_key_type.cm_key_size;
	}
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		OpenSSL_add_ssl_algorithms();
		ERR_load_crypto_strings();
		pkey = EVP_PKEY_new();
		if (pkey == NULL) {
			fprintf(status, "Internal error generating key.\n");
			_exit(2);
		}
		rsa = RSA_generate_key(cm_key_size, 65537, NULL, NULL);
		if (rsa == NULL) {
			fprintf(status, "Error generating key.\n");
			cm_log(1, "Error generating key.\n");
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(2);
		}
		EVP_PKEY_assign_RSA(pkey, rsa);
		fp = fopen(entry->cm_key_storage_location, "w");
		if (fp == NULL) {
			fprintf(status,
				"Error opening key file \"%s\" for writing.\n",
				entry->cm_key_storage_location);
			cm_log(1,
			       "Error opening key file \"%s\" for writing.\n",
			       entry->cm_key_storage_location);
			_exit(2);
		}
		if (PEM_write_PrivateKey(fp, pkey, NULL,
					 NULL, 0, NULL, NULL) == 0) {
			cm_log(1, "Error storing key.\n");
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(2);
		}
		fclose(fp);
		break;
	default:
		fprintf(status, "Unknown key type.\n");
		cm_log(1, "Unknown key type.\n");
		_exit(2);
		break;
	}
}

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *
cm_keygen_start(struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_keygen_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_file) {
		return NULL;
	}
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
				cm_keygen_main(fds[1], entry);
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

/* Check if the keypair is ready. */
int
cm_keygen_ready(struct cm_store_entry *entry, struct cm_keygen_state *state)
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
cm_keygen_get_fd(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	return state->fd;
}

/* Tell us if the keypair was saved to the location specified in the entry. */
int
cm_keygen_saved_keypair(struct cm_store_entry *entry,
		        struct cm_keygen_state *state)
{

	if (WIFEXITED(state->status) && (WEXITSTATUS(state->status) == 0)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
void
cm_keygen_done(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}
