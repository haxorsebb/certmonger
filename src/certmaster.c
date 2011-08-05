/*
 * Copyright (C) 2009,2010,2011 Red Hat, Inc.
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
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include <xmlrpc-c/client.h>
#include <xmlrpc-c/transport.h>

#include <krb5.h>

#include "log.h"
#include "submit-e.h"
#include "submit-u.h"
#include "submit-x.h"
#include "util.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

int
main(int argc, char **argv)
{
	int i, c;
	const char *host = NULL, *port = NULL, *cainfo = NULL, *capath = NULL;
	char *csr, *p, uri[LINE_MAX], *s1, *s2, *config;
	struct cm_submit_x_context *ctx;
	struct stat st;

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif

	cm_log_set_method(cm_log_stderr);
	while ((c = getopt(argc, argv, "h:C:c:")) != -1) {
		switch (c) {
		case 'h':
			host = optarg;
			break;
		case 'C':
			capath = optarg;
			break;
		case 'c':
			cainfo = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-h serverHost] "
				"[-c cafile] [-C capath] [csrfile]\n",
				strchr(argv[0], '/') ?
				strrchr(argv[0], '/') + 1 :
				argv[0]);
			return CM_STATUS_UNCONFIGURED;
			break;
		}
	}

	if (host == NULL) {
		/* Okay, we have to figure out what the master name is. */
		if (stat("/var/run/certmaster.pid", &st) == 0) {
			/* Guess that it's us if we have the service running. */
			config = read_config_file("/etc/certmaster/"
						  "certmaster.conf");
			host = "localhost";
			if (config != NULL) {
				port = get_config_entry(config,
							"main", "listen_port");
			}
		} else {
			/* Hope the minion is configured. */
			config = read_config_file("/etc/certmaster/"
						  "minion.conf");
			if (config != NULL) {
				host = get_config_entry(config,
							"main", "certmaster");
				port = get_config_entry(config,
							"main",
							"certmaster_port");
			}
		}
	}
	if (host == NULL) {
		printf(_("Unable to determine hostname of CA.\n"));
		fprintf(stderr,
			"Usage: %s [-h serverHost] "
			"[-c cafile] [-C capath] [csrfile]\n",
			strchr(argv[0], '/') ?
			strrchr(argv[0], '/') + 1 :
			argv[0]);
		return CM_STATUS_UNCONFIGURED;
	}

	/* Read the CSR from the environment, or from the command-line. */
	csr = getenv(CM_SUBMIT_CSR_ENV);
	if (csr == NULL) {
		csr = cm_submit_u_from_file((optind < argc) ?
					    argv[optind++] : NULL);
	}
	if ((csr == NULL) || (strlen(csr) == 0)) {
		printf(_("Unable to read signing request.\n"));
		fprintf(stderr,
			"Usage: %s [-h serverHost] "
			"[-c cafile] [-C capath] [csrfile]\n",
			strchr(argv[0], '/') ?
			strrchr(argv[0], '/') + 1 :
			argv[0]);
		return CM_STATUS_UNCONFIGURED;
	}

	/* Clean up the CSR -- make sure it's not a "NEW" request.  certmaster
	 * rewrites the incoming request to its cache previously-received
	 * requests, and in doing so uses a different PEM header than the one
	 * we default to using.  So turn any "NEW CERTIFICATE REQUEST" notes
	 * into "CERTIFICATE REQUEST" before sending them. */
	while ((p = strstr(csr, "NEW CERTIFICATE REQUEST")) != NULL) {
		memmove(p, p + 4, strlen(p + 4) + 1);
	}

	/* Initialize for XML-RPC. */
	snprintf(uri, sizeof(uri), "http%s://%s%s%s/",
		 ((cainfo != NULL) || (capath != NULL)) ? "s" : "",
		 host,
		 ((port != NULL) && (strlen(port) > 0)) ? ":" : "",
		 port ? port : "");
	ctx = cm_submit_x_init(NULL, uri, "wait_for_cert", cainfo, capath,
			       cm_submit_x_negotiate_off,
			       cm_submit_x_delegate_off);
	if (ctx == NULL) {
		fprintf(stderr, "Error setting up for XMLRPC.\n");
		printf(_("Error setting up for XMLRPC.\n"));
		return CM_STATUS_UNCONFIGURED;
	}

	/* Add the CSR as the sole argument. */
	cm_submit_x_add_arg_s(ctx, csr);

	/* Submit the request. */
	fprintf(stderr, "Submitting request to \"%s\".\n", uri);
	cm_submit_x_run(ctx);

	/* Check the results. */
	if (cm_submit_x_has_results(ctx) == 0) {
		if (cm_submit_x_get_bss(ctx, &i, &s1, &s2) == 0) {
			if (i) {
				printf("%s", s1);
				return CM_STATUS_ISSUED;
			} else {
				printf("SUBMITTED COOKIE\n");
				return CM_STATUS_WAIT;
			}
		} else {
			printf(_("Error parsing server response.\n"));
			return CM_STATUS_UNREACHABLE;
		}
	} else {
		printf(_("Server error.\n"));
		return CM_STATUS_UNREACHABLE;
	}
}
