/*
 * Copyright (C) 2012 Red Hat, Inc.
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
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <talloc.h>

#include "tlslayer.h"
#include "tlslayer-int.h"

struct cm_tls_o_pvt {
	SSL_CTX *cm_ctx;
	BIO *cm_bio, *cm_sbio;
};

static int
cm_tls_o_fd(struct cm_tls_connection *conn, void *data)
{
	return -1;
}

static ssize_t
cm_tls_o_write(struct cm_tls_connection *conn, void *data,
	       const void *buf, size_t count)
{
	struct cm_tls_o_pvt *pvt = (struct cm_tls_o_pvt *) data;
	return BIO_write(pvt->cm_sbio, buf, count);
}

static ssize_t
cm_tls_o_read(struct cm_tls_connection *conn, void *data,
	      void *buf, size_t count)
{
	struct cm_tls_o_pvt *pvt = (struct cm_tls_o_pvt *) data;
	return BIO_read(pvt->cm_sbio, buf, count);
}

static void
cm_tls_o_close(struct cm_tls_connection *conn, void *data)
{
	struct cm_tls_o_pvt *pvt = (struct cm_tls_o_pvt *) data;
	BIO_ssl_shutdown(pvt->cm_sbio);
	talloc_free(conn);
}

struct cm_tls_connection *
cm_tls_o(const char *hostport,
	 const char *trusted_ca_file,
	 const char *trusted_ca_db,
	 const char *client_db,
	 const char *client_nickname)
{
	struct cm_tls_connection *ret;
	struct cm_tls_o_pvt *pvt;

	ret = talloc_ptrtype(NULL, ret);
	if (ret == NULL) {
		return NULL;
	}
	memset(ret, 0, sizeof(*ret));
	pvt = talloc_ptrtype(ret, pvt);
	if (pvt == NULL) {
		talloc_free(ret);
		return NULL;
	}
	memset(pvt, 0, sizeof(*pvt));
	pvt->cm_ctx = SSL_CTX_new(SSLv23_client_method());
	pvt->cm_bio = BIO_new_connect(strdup(hostport));
	pvt->cm_sbio = BIO_new_ssl(pvt->cm_ctx, 1);
	BIO_push(pvt->cm_sbio, pvt->cm_bio);
	if (BIO_do_connect(pvt->cm_sbio) != 1) {
		return NULL;
	}
	ret->pvt = pvt;
	ret->pvt_ops.cm_fd = &cm_tls_o_fd;
	ret->pvt_ops.cm_read = &cm_tls_o_read;
	ret->pvt_ops.cm_write = &cm_tls_o_write;
	ret->pvt_ops.cm_close = &cm_tls_o_close;
	return ret;
}
