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
#include <sys/socket.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include "tlslayer.h"
#include "tlslayer-int.h"

#ifdef CM_TLSLAYER_MAIN
static int
cm_tls_null_fd(struct cm_tls_connection *conn, void *pvt)
{
	return *(int *) pvt;
}

static ssize_t
cm_tls_null_write(struct cm_tls_connection *conn, void *pvt, const void *buf, size_t count)
{
	return write(*(int *) pvt, buf, count);
}

static ssize_t
cm_tls_null_read(struct cm_tls_connection *conn, void *pvt, void *buf, size_t count)
{
	return read(*(int *) pvt, buf, count);
}

static void
cm_tls_null_close(struct cm_tls_connection *conn, void *pvt)
{
	close(*(int *)pvt);
	talloc_free(conn);
}

static struct cm_tls_connection *
cm_tls_null(const char *hostport)
{
	static struct cm_tls_connection *ret;
	struct addrinfo *res, *r;
	int *pvt, sd;
	char *hp, *service;

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
	hp = talloc_strdup(ret, hostport);
	if (hp == NULL) {
		talloc_free(ret);
		return NULL;
	}
	service = strrchr(hp, ':');
	if (service != NULL) {
		if (strspn(service + 1, "0123456789") == strlen(service + 1)) {
			*service++ = '\0';
		} else {
			service = NULL;
		}
	}
	res = NULL;
	if (getaddrinfo(hp, service, NULL, &res) != 0) {
		talloc_free(ret);
		return NULL;
	}
	for (r = res; r != NULL; r = r->ai_next) {
		sd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (sd == -1) {
			continue;
		}
		if (connect(sd, r->ai_addr, r->ai_addrlen) != 0) {
			close(sd);
			sd = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(res);
	*pvt = sd;
	ret->pvt = pvt;
	ret->pvt_ops.cm_fd = &cm_tls_null_fd;
	ret->pvt_ops.cm_read = &cm_tls_null_read;
	ret->pvt_ops.cm_write = &cm_tls_null_write;
	ret->pvt_ops.cm_close = &cm_tls_null_close;
	return ret;
}
#else
static struct cm_tls_connection *
cm_tls_null(const char *hostport)
{
	return NULL;
}
#endif

struct cm_tls_connection *
cm_tls_connect(const char *hostport,
	       const char *trusted_ca_file,
	       const char *trusted_ca_dir,
	       const char *trusted_ca_db,
	       const char *client_cert_file,
	       const char *client_key_file,
	       const char *client_db,
	       const char *client_nickname)
{
	if (!trusted_ca_db && !trusted_ca_dir && !trusted_ca_file &&
	    !client_cert_file && !client_key_file &&
	    !client_db && !client_nickname) {
		fprintf(stderr, "The googles! They do nothing!\n");
		return cm_tls_null(hostport);
	} else
	if (!trusted_ca_dir && !client_cert_file && !client_key_file) {
		fprintf(stderr, "NSS!\n");
		return cm_tls_n(hostport,
				trusted_ca_file,
				trusted_ca_db,
				client_db,
				client_nickname);
#ifdef HAVE_OPENSSL
	} else
	if (!trusted_ca_db && !client_db && !client_nickname) {
		fprintf(stderr, "OpenSSL!\n");
		return cm_tls_o(hostport,
				trusted_ca_file,
				trusted_ca_dir,
				client_cert_file,
				client_key_file);
#endif
	} else {
		return NULL;
	}
}

int
cm_tls_fd(struct cm_tls_connection *conn)
{
	return conn->pvt_ops.cm_fd(conn, conn->pvt);
}

ssize_t
cm_tls_write(struct cm_tls_connection *conn, const void *buf, size_t count)
{
	return conn->pvt_ops.cm_write(conn, conn->pvt, buf, count);
}

ssize_t
cm_tls_read(struct cm_tls_connection *conn, void *buf, size_t count)
{
	return conn->pvt_ops.cm_read(conn, conn->pvt, buf, count);
}

void
cm_tls_close(struct cm_tls_connection *conn)
{
	conn->pvt_ops.cm_close(conn, conn->pvt);
}

#ifdef CM_TLSLAYER_MAIN
int
main(int argc, char **argv)
{
	struct cm_tls_connection *conn;
	const char *hostport = NULL;
	const char *trusted_ca_file = NULL, *trusted_ca_dir = NULL;
	const char *trusted_ca_db = NULL;
	const char *client_cert_file = NULL, *client_key_file = NULL;
	const char *client_db = NULL, *client_nickname = NULL;
	int c;

	while ((c = getopt(argc, argv, "c:C:D:f:k:d:n:")) != -1) {
		switch (c) {
		case 'c':
			trusted_ca_file = optarg;
			break;
		case 'C':
			trusted_ca_dir = optarg;
			break;
		case 'D':
			trusted_ca_db = optarg;
			break;
		case 'f':
			client_cert_file = optarg;
			break;
		case 'k':
			client_key_file = optarg;
			break;
		case 'd':
			client_db = optarg;
			break;
		case 'n':
			client_nickname = optarg;
			break;
		default:
			fprintf(stderr, "Usage: tlslayer\n"
				"\t[-c cafile] [-C capath] [-D cadb]\n"
				"\t[-f clientcert] [-k clientkey]\n"
				"\t[-d clientdb] [-n clientnick]\n"
				"\thostname:port\n");
			return 1;
			break;
		}
	}
	if (optind > argc - 1) {
		fprintf(stderr, "No hostname:port specified.\n");
		fprintf(stderr, "Usage: tlslayer\n"
			"\t[-c cafile] [-C capath] [-D cadb]\n"
			"\t[-f clientcert] [-k clientkey]\n"
			"\t[-d clientdb] [-n clientnick]\n"
			"\thostname:port\n");
		return 2;
	}
	hostport = argv[optind];

	conn = cm_tls_connect(hostport,
			      trusted_ca_file,
			      trusted_ca_dir,
			      trusted_ca_db,
			      client_cert_file,
			      client_key_file,
			      client_db,
			      client_nickname);
	if (conn == NULL) {
		fprintf(stderr, "Error establishing connection.\n");
		return 2;
	}

	cm_tls_close(conn);
	return 0;
}
#endif
