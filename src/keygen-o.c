/*
 * Copyright (C) 2009 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <talloc.h>

#include "keygen.h"
#include "keygen-int.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_keygen_state {
	struct cm_keygen_state_pvt pvt;
	char msg[0x10000];
	pid_t pid;
	int fd, count, status;
};

static void
cm_keygen_o_main(int fd, struct cm_store_entry *entry)
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
		cm_key_algorithm = CM_DEFAULT_PUBKEY_TYPE;
		cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
	} else {
		cm_key_algorithm = entry->cm_key_type.cm_key_algorithm;
		cm_key_size = entry->cm_key_type.cm_key_size;
		if (cm_key_size <= 0) {
			cm_key_size = CM_DEFAULT_PUBKEY_SIZE;
		}
	}
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		OpenSSL_add_ssl_algorithms();
		ERR_load_crypto_strings();
		pkey = EVP_PKEY_new();
		if (pkey == NULL) {
			fprintf(status, "Internal error generating key.\n");
			cm_log(1, "Internal error generating key.\n");
			_exit(2);
		}
		rsa = RSA_generate_key(cm_key_size, CM_DEFAULT_RSA_MODULUS,
				       NULL, NULL);
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
	fclose(status);
}

/* Check if the keypair is ready. */
static int
cm_keygen_o_ready(struct cm_store_entry *entry, struct cm_keygen_state *state)
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
cm_keygen_o_get_fd(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	return state->fd;
}

/* Tell us if the keypair was saved to the location specified in the entry. */
static int
cm_keygen_o_saved_keypair(struct cm_store_entry *entry,
		          struct cm_keygen_state *state)
{

	if (WIFEXITED(state->status) && (WEXITSTATUS(state->status) == 0)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
static void
cm_keygen_o_done(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *
cm_keygen_o_start(struct cm_store_entry *entry)
{
	int fds[2];
	long flags;
	struct cm_keygen_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_file) {
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_keygen_o_ready;
		state->pvt.get_fd = cm_keygen_o_get_fd;
		state->pvt.saved_keypair = cm_keygen_o_saved_keypair;
		state->pvt.done = cm_keygen_o_done;
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
				cm_keygen_o_main(fds[1], entry);
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
