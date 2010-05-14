/*
 * Copyright (C) 2010 Red Hat, Inc.
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
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include "submit-e.h"
#include "submit-h.h"
#include "submit-x.h"
#include "submit-u.h"
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
	int i, c, ret;
	void *tctx;
	char *csr, *p, *dogtagconfig, hostname[LINE_MAX];
	const char *config, *conftag, *host, *host_uri, *submit_uri, *poll_uri;
	const char *op, *method, *uri, *identifier, *args, *cookie;
	struct cm_submit_h_context *ctx;

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif
	tctx = talloc_init(NULL);

	config = NULL;
	conftag = NULL;
	host = NULL;
	host_uri = NULL;
	submit_uri = NULL;
	poll_uri = NULL;
	identifier = NULL;
	while ((c = getopt(argc, argv, "c:C:h:H:i:S:P:")) != -1) {
		switch (c) {
		case 'c':
			config = optarg;
			break;
		case 'C':
			conftag = optarg;
			break;
		case 'h':
			host = optarg;
			break;
		case 'H':
			host_uri = optarg;
			break;
		case 'i':
			identifier = optarg;
			break;
		case 'S':
			submit_uri = optarg;
			break;
		case 'P':
			poll_uri = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-c configFile] "
				"[-C configSection] "
				"[-h serverHost] "
				"[-H serverBaseUri] "
				"[-S profileSubmitUri] "
				"[-P checkRequestUri] "
				"[csrfile]\n",
				strchr(argv[0], '/') ?
				strrchr(argv[0], '/') + 1 :
				argv[0]);
			return CM_STATUS_UNCONFIGURED;
			break;
		}
	}

	/* Try to read our configuration. */
	if (config != NULL) {
		dogtagconfig = read_config_file(config);
	} else {
		dogtagconfig = NULL;
	}
	if (conftag == NULL) {
		conftag = "dogtag";
	}
	if (host == NULL) {
		if (dogtagconfig != NULL) {
			host = get_config_entry(dogtagconfig,
						conftag, "server");
		}
	}
	if (identifier == NULL) {
		if (dogtagconfig != NULL) {
			identifier = get_config_entry(dogtagconfig,
						      conftag, "contact");
		}
		if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
			strcpy(hostname, "localhost");
		}
		identifier = talloc_asprintf(tctx, "%s(%s)",
					     PACKAGE_NAME, hostname);
	}
	ret = CM_STATUS_UNREACHABLE;

	/* Derive what we weren't explicitly given. */
	if (host_uri == NULL) {
		if (host == NULL) {
			printf(_("No host or host URI specified or configured.\n"));
			return CM_STATUS_UNCONFIGURED;
		}
		host_uri = talloc_asprintf(tctx, "http://%s/ca/ee/ca", host);
	}
	if (submit_uri == NULL) {
		if (host_uri == NULL) {
			printf(_("Unable to derive URI for profileSubmit.\n"));
			return CM_STATUS_UNCONFIGURED;
		}
		submit_uri = talloc_asprintf(tctx, "%s/profileSubmit",
					     host_uri);
	}
	if (poll_uri == NULL) {
		if (host_uri == NULL) {
			printf(_("Unable to derive URI for checkRequest.\n"));
			return CM_STATUS_UNCONFIGURED;
		}
		poll_uri = talloc_asprintf(tctx, "%s/checkRequest", host_uri);
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
			"Usage: %s [-c configFile] "
			"[-C configSection] "
			"[-h serverHost] "
			"[-H serverBaseUri] "
			"[-S profileSubmitUri] "
			"[-P checkRequestUri] "
			"[csrfile]\n",
			strchr(argv[0], '/') ?
			strrchr(argv[0], '/') + 1 :
			argv[0]);
		return CM_STATUS_UNCONFIGURED;
	}

	/* Change the CSR from the format we get it in to the one the server
	 * expects.  Dogtag just wants base64-encoded binary data, no
	 * whitepace. */
	p = strstr(csr, "-----BEGIN");
	if (p != NULL) {
		p += strcspn(p, "\n");
		if (*p == '\n') {
			p++;
		}
		memmove(csr, p, strlen(p) + 1);
	}
	p = strstr(csr, "\n-----END");
	if (p != NULL) {
		*p = '\0';
	}
	while ((p = strchr(csr, '\r')) != NULL) {
		memmove(p, p + 1, strlen(p));
	}
	while ((p = strchr(csr, '\n')) != NULL) {
		memmove(p, p + 1, strlen(p));
	}

	/* Initialize for HTTP. */
	op = getenv(CM_SUBMIT_OPERATION_ENV);
	if (op == NULL) {
		printf(_("%s is not set in environment.\n"),
		       CM_SUBMIT_OPERATION_ENV);
		return CM_STATUS_UNCONFIGURED;
	}

	method = NULL;
	uri = NULL;
	args = NULL;
	if (strcmp(op, "SUBMIT") == 0) {
		const char *profile;
		uri = submit_uri;
		if (dogtagconfig != NULL) {
			profile = get_config_entry(dogtagconfig,
						   conftag, "profile");
		}
		if (profile == NULL) {
			profile = "caServerCert";
		}
		args = talloc_asprintf("requestor_name=%s&"
				       "cert_request_type=pkcs10&"
				       "profileId=%s&"
				       "cert_request=%s&"
				       "xmlOutput=true",
				       identifier,
				       profile,
				       csr);
		method = "POST";
	} else
	if (strcmp(op, "POLL") == 0) {
		uri = poll_uri;
		cookie = getenv(CM_SUBMIT_COOKIE_ENV);
		if (cookie == NULL) {
			printf(_("%s is not set in environment.\n"),
			       CM_SUBMIT_COOKIE_ENV);
			return CM_STATUS_UNCONFIGURED;
		}
		args = talloc_strdup("requestId=%s&xml=true", cookie);
		method = "GET";
	} else {
		printf(_("%s is not set to a recognized value.\n"),
		       CM_SUBMIT_OPERATION_ENV);
		return CM_STATUS_UNCONFIGURED;
	}

	/* Get ready to submit the request. */
	ctx = cm_submit_h_init(tctx, method, uri, args);
	if (ctx == NULL) {
		fprintf(stderr, "Error setting up for contacting server.\n");
		printf(_("Error setting up for contacting server.\n"));
		return CM_STATUS_UNCONFIGURED;
	}

	/* ...and stop. XXX rewrite the rest of this */
	return CM_STATUS_UNREACHABLE;

	/* Submit the request. */
	fprintf(stderr, "Submitting request to \"%s\".\n", uri);
	cm_submit_h_run(ctx);

	/* Check the results. */
	i = cm_submit_h_result_code(ctx);
	if ((i != -1) && (i != 200)) {
		/* XXX - Do we need to interpret the actual result? */
		return CM_STATUS_UNREACHABLE;
	} else
	if (cm_submit_h_results(ctx) != NULL) {
		/* XXX - Actually parse the results. */
		printf("Results:%s\n", cm_submit_h_results(ctx));
		return CM_STATUS_REJECTED;
	} else {
		/* No useful response.  Try again, from scratch, later. */
		return CM_STATUS_UNREACHABLE;
	}
}
