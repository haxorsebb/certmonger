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
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <talloc.h>

#include <nspr4/nspr.h>
#include <nspr4/prnetdb.h>
#include <nss3/nss.h>
#include <nss3/ssl.h>

#include "tlslayer.h"
#include "tlslayer-int.h"

struct cm_tls_n_pvt {
	PRFileDesc *sfd, *model, *fd;
	char *client_db, *client_nickname;
};

static int
cm_tls_n_fd(struct cm_tls_connection *conn, void *data)
{
	return -1;
}

static ssize_t
cm_tls_n_write(struct cm_tls_connection *conn, void *data,
	       const void *buf, size_t count)
{
	return -1;
}

static ssize_t
cm_tls_n_read(struct cm_tls_connection *conn, void *data,
	      void *buf, size_t count)
{
	return -1;
}

static void
cm_tls_n_close(struct cm_tls_connection *conn, void *data)
{
	struct cm_tls_n_pvt *pvt = (struct cm_tls_n_pvt *) data;
	PR_Close(pvt->sfd);
	PR_Close(pvt->model);
	PR_Close(pvt->fd);
	talloc_free(conn);
}

static SECStatus 
cm_tls_n_bad_cert(void *arg, PRFileDesc *fd)
{
	fprintf(stderr, "Server certificate failed to verify: %s.\n", 
		PR_ErrorToName(PORT_GetError()));
	return SECFailure;
}

static SECStatus
cm_tls_n_get_client_creds(void *arg, PRFileDesc *socket,
			  CERTDistNames *cas,
			  CERTCertificate **client_cert, 
			  SECKEYPrivateKey **client_key)
{
	*client_cert = NULL;
	*client_key = NULL;
	return SECFailure;
}

struct cm_tls_connection *
cm_tls_n(const char *hostport,
	 const char *trusted_ca_file,
	 const char *trusted_ca_db,
	 const char *client_db,
	 const char *client_nickname)
{
	struct cm_tls_connection *ret;
	struct cm_tls_n_pvt *pvt;
	char buf[LINE_MAX], *hp, *service;
	PRHostEnt host;
	PRNetAddr addr;
	PRIntn i;
	PRUint16 port;

	if (trusted_ca_db != NULL) {
		NSS_InitContext(trusted_ca_db,
				NULL, NULL, NULL, NULL, 0);
	} else {
		NSS_InitContext(CM_DEFAULT_CERT_STORAGE_LOCATION,
				NULL, NULL, NULL, NULL, NSS_INIT_NOCERTDB);
	}
	ret = talloc_ptrtype(NULL, ret);
	if (ret == NULL) {
		return NULL;
	}
	pvt = talloc_ptrtype(ret, pvt);
	if (pvt == NULL) {
		talloc_free(ret);
		return NULL;
	}
	hp = talloc_strdup(ret, hostport);
	if (hp == NULL) {
		talloc_free(ret);
		return NULL;
	}
	service = strrchr(hp, ':');
	port = 80;
	if (service != NULL) {
		if (strspn(service + 1, "0123456789") == strlen(service + 1)) {
			*service++ = '\0';
			port = atoi(service);
		} else {
			service = NULL;
		}
	}
	pvt->client_db = talloc_strdup(pvt, client_db);
	pvt->client_nickname = talloc_strdup(pvt, client_nickname);
	pvt->fd = PR_NewTCPSocket();
	memset(&host, 0, sizeof(host));
	PR_GetHostByName(hp, buf, sizeof(buf), &host);
	memset(&addr, 0, sizeof(addr));
	for (i = PR_EnumerateHostEnt(0, &host, port, &addr);
	     i != 0;
	     i = PR_EnumerateHostEnt(i, &host, port, &addr)) {
		if (PR_Connect(pvt->fd, &addr,
			       PR_INTERVAL_NO_TIMEOUT) == PR_SUCCESS) {
			break;
		}
	}
	if (i == 0) {
		fprintf(stderr, "PR_Connect\n");
		PR_Close(pvt->fd);
		talloc_free(ret);
		return NULL;
	}
	pvt->model = SSL_ImportFD(NULL, PR_NewTCPSocket());
	if (pvt->model == NULL) {
		fprintf(stderr, "SSL_ImportFD: %d\n", PORT_GetError());
		PR_Close(pvt->model);
		PR_Close(pvt->fd);
		talloc_free(ret);
		return NULL;
	}
#if 0
	if (SSL_OptionSet(pvt->model, SSL_SECURITY, 1) < 0) {
		fprintf(stderr, "SSL_OptionSet(SSL_SECURITY): %d\n",
			PORT_GetError());
		PR_Close(pvt->model);
		PR_Close(pvt->fd);
		talloc_free(ret);
		return NULL;
	}
#endif
	if (SSL_SetURL(pvt->model, hp) != SECSuccess) {
		fprintf(stderr, "SSL_SetURL: %d\n", PORT_GetError());
		PR_Close(pvt->model);
		PR_Close(pvt->fd);
		talloc_free(ret);
		return NULL;
	}
        SSL_BadCertHook(pvt->model, &cm_tls_n_bad_cert, NULL);
	SSL_GetClientAuthDataHook(pvt->model,
				  &cm_tls_n_get_client_creds,
				  pvt);
	pvt->sfd = SSL_ImportFD(pvt->model, pvt->fd);
	if (SSL_ResetHandshake(pvt->sfd, 0) != SECSuccess) {
		fprintf(stderr, "SSL_ResetHandshake: %d\n", PORT_GetError());
		PR_Close(pvt->sfd);
		PR_Close(pvt->model);
		PR_Close(pvt->fd);
		talloc_free(ret);
		return NULL;
	}
	if (SSL_ForceHandshake(pvt->sfd) != SECSuccess) {
		fprintf(stderr, "SSL_ForceHandshake: %s\n",
			PR_ErrorToName(PORT_GetError()));
		PR_Close(pvt->sfd);
		PR_Close(pvt->model);
		PR_Close(pvt->fd);
		talloc_free(ret);
		return NULL;
	}
	ret->pvt = pvt;
	ret->pvt_ops.cm_fd = &cm_tls_n_fd;
	ret->pvt_ops.cm_read = &cm_tls_n_read;
	ret->pvt_ops.cm_write = &cm_tls_n_write;
	ret->pvt_ops.cm_close = &cm_tls_n_close;
	return ret;
}
