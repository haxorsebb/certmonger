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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <talloc.h>

#include "keyiread.h"
#include "keyiread-int.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_keyiread_state {
	struct cm_keyiread_state_pvt pvt;
	char msg[0x1000];
	pid_t pid;
	int fd, count, status;
};

static void
cm_keyiread_o_main(int fd, struct cm_store_entry *entry)
{
	FILE *pem, *fp;
	EVP_PKEY *pkey;
	int status;
	char buf[LINE_MAX];
	const char *alg;
	int size;
	long error;

	OpenSSL_add_ssl_algorithms();
	ERR_load_crypto_strings();
	status = 1;
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		cm_log(1, "Unable to initialize I/O.\n");
		_exit(1);
	}
	pem = fopen(entry->cm_key_storage_location, "r");
	if (pem != NULL) {
		pkey = PEM_read_PrivateKey(pem, NULL, NULL, NULL);
		if (pkey != NULL) {
			status = 0;
		} else {
			cm_log(1, "Internal error reading key from \"%s\".\n",
			       entry->cm_key_storage_location);
		}
		fclose(pem);
	} else {
		cm_log(1, "Error opening '%s': %s.\n",
		       entry->cm_key_storage_location, strerror(errno));
		pkey = NULL;
	}
	if (status == 0) {
		alg = "";
		size = 0;
		if (pkey != NULL) {
			cm_log(3, "Key is of type %d.\n",
			       EVP_PKEY_type(pkey->type));
			switch (EVP_PKEY_type(pkey->type)) {
			case EVP_PKEY_RSA:
				alg = "RSA";
				break;
			case EVP_PKEY_DSA:
				alg = "DSA";
				break;
			default:
				alg = "";
				break;
			}
			size = EVP_PKEY_bits(pkey);
			cm_log(3, "Key size is %d.\n", size);
		}
		fprintf(fp, "%s/%d\n", alg, size);
		status = 0;
	} else {
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
	}
	fclose(fp);
	if (status != 0) {
		_exit(status);
	}
}

/* Check if something changed, for example we finished reading the data we need
 * from the key file. */
static int
cm_keyiread_o_ready(struct cm_store_entry *entry,
		    struct cm_keyiread_state *state)
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
cm_keyiread_o_get_fd(struct cm_store_entry *entry,
		     struct cm_keyiread_state *state)
{
	return state->fd;
}

/* Clean up after reading the keyiificate. */
static void
cm_keyiread_o_done(struct cm_store_entry *entry,
		   struct cm_keyiread_state *state)
{
	if (state->count > 0) {
		cm_keyiread_read_data_from_buffer(entry, state->msg);
	}
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	talloc_free(state);
}

/* Start reading the keyiificate from the configured location. */
struct cm_keyiread_state *
cm_keyiread_o_start(struct cm_store_entry *entry)
{
	int fds[2];
	long flags;
	struct cm_keyiread_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_file) {
		cm_log(1, "Wrong read method: can only read keys "
		       "from a file.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_keyiread_o_ready;
		state->pvt.get_fd= cm_keyiread_o_get_fd;
		state->pvt.done= cm_keyiread_o_done;
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
				cm_keyiread_o_main(fds[1], entry);
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
