/*
 * Copyright (C) 2009,2010,2011,2014 Red Hat, Inc.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include <krb5.h>

#include <talloc.h>

#include "certread.h"
#include "certread-int.h"
#include "log.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "util-o.h"

struct cm_certread_state {
	struct cm_certread_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};

static int
cm_certread_o_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	FILE *pem, *fp;
	X509 *cert;
	int status, len;
	char buf[LINE_MAX];
	unsigned char *der;
	long error;

	if (entry->cm_cert_storage_location == NULL) {
		cm_log(1, "Error reading certificate: no location "
		       "specified.\n");
		_exit(1);
	}

	util_o_init();
	ERR_load_crypto_strings();
	status = CM_SUB_STATUS_INTERNAL_ERROR;
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		cm_log(1, "Unable to initialize I/O.\n");
		_exit(1);
	}
	pem = fopen(entry->cm_cert_storage_location, "r");
	if (pem != NULL) {
		cert = PEM_read_X509(pem, NULL, NULL, NULL);
		if (cert != NULL) {
			status = 0;
		} else {
			cm_log(1, "Internal error reading cert from \"%s\".\n",
			       entry->cm_cert_storage_location);
		}
		fclose(pem);
	} else {
		if (errno != ENOENT) {
			cm_log(1, "Error opening cert file '%s' "
			       "for reading: %s.\n",
			       entry->cm_cert_storage_location,
			       strerror(errno));
		}
		cert = NULL;
	}
	if (status == 0) {
		der = NULL;
		len = i2d_X509(cert, &der);
		cm_certread_n_parse(entry, der, len);
		cm_certread_write_data_to_pipe(entry, fp);
	} else {
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
	}
	fclose(fp);
	_exit(0);
}

/* Check if something changed, for example we finished reading the data we need
 * from the cert. */
static int
cm_certread_o_ready(struct cm_certread_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certread_o_get_fd(struct cm_certread_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Clean up after reading the certificate. */
static void
cm_certread_o_done(struct cm_certread_state *state)
{
	if (state->subproc != NULL) {
		cm_certread_read_data_from_buffer(state->entry,
						  cm_subproc_get_msg(state->subproc,
								     NULL));
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start reading the certificate from the configured location. */
struct cm_certread_state *
cm_certread_o_start(struct cm_store_entry *entry)
{
	struct cm_certread_state *state;
	if (entry->cm_cert_storage_type != cm_cert_storage_file) {
		cm_log(1, "Wrong read method: can only read certificates "
		       "from a file.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_certread_o_ready;
		state->pvt.get_fd= cm_certread_o_get_fd;
		state->pvt.done= cm_certread_o_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_certread_o_main, state,
						  NULL, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
