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
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include <xmlrpc-c/client.h>
#include <xmlrpc-c/transport.h>

#include <krb5.h>

#include "submit-e.h"
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
	int i, c, ret, host_is_uri = 0;
	const char *host = NULL, *cainfo = NULL, *capath = NULL;
	const char *ktname = NULL, *kpname = NULL, *args[2];
	char *csr, *p, *q, uri[LINE_MAX], *s, *reqprinc = NULL, *ipaconfig;
	struct cm_submit_x_context *ctx;

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif

	reqprinc = getenv(CM_SUBMIT_REQ_PRINCIPAL_ENV);
	if (reqprinc != NULL) {
		/* If it's multi-valued, just use the first one. */
		reqprinc[strcspn(reqprinc, "\r\n")] = '\0';
	}

	while ((c = getopt(argc, argv, "h:H:C:c:t:k:P:")) != -1) {
		switch (c) {
		case 'h':
			host = optarg;
			host_is_uri = 0;
			break;
		case 'H':
			host = optarg;
			host_is_uri = 1;
			break;
		case 'C':
			capath = optarg;
			break;
		case 'c':
			cainfo = optarg;
			break;
		case 't':
			ktname = optarg;
			break;
		case 'k':
			kpname = optarg;
			break;
		case 'P':
			reqprinc = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-h serverHost] "
				"[-H serverUri] "
				"[-c cafile] "
				"[-C capath] "
				"[-t keytab] "
				"[-k submitterPrincipal] "
				"[-P principalOfRequest] "
				"[csrfile]\n",
				strchr(argv[0], '/') ?
				strrchr(argv[0], '/') + 1 :
				argv[0]);
			return CM_STATUS_UNCONFIGURED;
			break;
		}
	}
	if (cainfo == NULL) {
		cainfo = "/etc/ipa/ca.crt";
	}
	if (host == NULL) {
		ipaconfig = read_config_file("/etc/ipa/default.conf");
		if (ipaconfig != NULL) {
			host = get_config_entry(ipaconfig,
						"global",
						"xmlrpc_uri");
			host_is_uri = 1;
		}
	}
	if ((reqprinc == NULL) || (host == NULL)) {
		if (host == NULL) {
			if (host_is_uri) {
				printf(_("Unable to determine location of "
					 "CA's XMLRPC server.\n"));
			} else {
				printf(_("Unable to determine hostname of "
					 "CA.\n"));
			}
		}
		if (reqprinc == NULL) {
			printf(_("Unable to determine principal name for "
			         "signing request.\n"));
		}
		fprintf(stderr,
			"Usage: %s [-h serverHost] "
			"[-H serverUri] "
			"[-c cafile] "
			"[-C capath] "
			"[-t keytab] "
			"[-k submitterPrincipal] "
			"[-P principalOfRequest] "
			"[csrfile]\n",
			strchr(argv[0], '/') ?
			strrchr(argv[0], '/') + 1 :
			argv[0]);
		return CM_STATUS_UNCONFIGURED;
	}
	ret = CM_STATUS_UNREACHABLE;

	/* Read the CSR from the environment, or from the command-line. */
	csr = getenv(CM_SUBMIT_CSR_ENV);
	if (csr == NULL) {
		csr = cm_submit_x_from_file((optind < argc) ?
					    argv[optind++] : NULL);
	}
	if ((csr == NULL) || (strlen(csr) == 0)) {
		printf(_("Unable to read signing request.\n"));
		fprintf(stderr,
			"Usage: %s [-h serverHost] "
			"[-H serverUri] "
			"[-c cafile] "
			"[-C capath] "
			"[-t keytab] "
			"[-k submitterPrincipal] "
			"[-P principalOfRequest] "
			"[csrfile]\n",
			strchr(argv[0], '/') ?
			strrchr(argv[0], '/') + 1 :
			argv[0]);
		return CM_STATUS_UNCONFIGURED;
	}

	/* Change the CSR from the format we get it in to the one the server
	 * expects.  IPA just wants base64-encoded binary data, no whitepace. */
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

	/* Initialize for XML-RPC. */
	if (host_is_uri) {
		snprintf(uri, sizeof(uri), "%s", host);
	} else {
		snprintf(uri, sizeof(uri), "https://%s/ipa/xml", host);
	}
	ctx = cm_submit_x_init(NULL, uri, "cert_request", cainfo, capath, 1);
	if (ctx == NULL) {
		fprintf(stderr, "Error setting up for XMLRPC.\n");
		printf(_("Error setting up for XMLRPC.\n"));
		return CM_STATUS_UNCONFIGURED;
	}

	/* Setup a ccache. */
	if (cm_submit_x_make_ccache(ktname, kpname) != 0) {
		fprintf(stderr, "Error setting up ccache.\n");
		if (ktname == NULL) {
			if (kpname == NULL) {
				printf(_("Error setting up ccache for local "
					 "\"host\" service using "
					 "default keytab.\n"));
			} else {
				printf(_("Error setting up ccache for "
					 "\"%s\" using default keytab.\n"),
					 kpname);
			}
		} else {
			if (kpname == NULL) {
				printf(_("Error setting up ccache for local "
					 "\"host\" service using "
					 "keytab \"%s\".\n"), ktname);
			} else {
				printf(_("Error setting up ccache for "
					 "\"%s\" using keytab \"%s\".\n"),
					 kpname, ktname);
			}
		}
		return CM_STATUS_UNCONFIGURED;
	}

	/* Add the CSR as the sole unnamed argument. */
	args[0] = csr;
	args[1] = NULL;
	cm_submit_x_add_arg_as(ctx, args);
	/* Add the principal name named argument. */
	cm_submit_x_add_named_arg_s(ctx, "principal", reqprinc);
	/* Tell the server to add entries for a principal if one doesn't exist
	 * yet. */
	cm_submit_x_add_named_arg_b(ctx, "add", 1);

	/* Submit the request. */
	fprintf(stderr, "Submitting request to \"%s\".\n", uri);
	cm_submit_x_run(ctx);

	/* Check the results. */
	if (cm_submit_x_faulted(ctx) == 0) {
		i = cm_submit_x_fault_code(ctx);
		/* Interpret the error.  See errors.py to get the
		 * classifications. */
		switch (i / 1000) {
		case 2: /* authorization error - permanent */
		case 3: /* invocation error - permanent */
			printf("Server denied our request, giving up: "
			       "%d (%s).\n", i,
			       cm_submit_x_fault_text(ctx));
			return CM_STATUS_REJECTED;
			break;
		case 1: /* authentication error - transient? */
		case 4: /* execution error - transient? */
		case 5: /* generic error - transient? */
		default:
			printf("Server failed request, will retry: "
			       "%d (%s).\n", i,
			       cm_submit_x_fault_text(ctx));
			return CM_STATUS_UNREACHABLE;
			break;
		}
	} else
	if (cm_submit_x_has_results(ctx) == 0) {
		if (cm_submit_x_get_named_s(ctx, "certificate",
					    &s) == 0) {
			/* If we got a certificate, we're probably
			 * okay. */
			fprintf(stderr, "Certificate: \"%s\"\n", s);
			printf("-----BEGIN CERTIFICATE-----\n");
			for (p = s; *p != '\0'; p = q) {
				if (strlen(p) > 64) {
					q = p + 64;
				} else {
					q = p + strlen(p);
				}
				printf("%.*s\n", (int) (q - p), p);
			}
			printf("-----END CERTIFICATE-----\n");
			return CM_STATUS_ISSUED;
		} else {
			return CM_STATUS_REJECTED;
		}
	} else {
		/* No useful response, no fault.  Try again, from scratch,
		 * later. */
		return CM_STATUS_UNREACHABLE;
	}
}
