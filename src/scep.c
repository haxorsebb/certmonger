/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014,2015 Red Hat, Inc.
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
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <krb5.h>

#include <nss.h>
#include <cert.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include "log.h"
#include "prefs.h"
#include "store.h"
#include "submit-e.h"
#include "submit-h.h"
#include "submit-u.h"
#include "util.h"
#include "util-m.h"
#include "util-n.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

#define OP_GET_CA_CAPS "GetCACaps"
#define OP_GET_CA_CERT "GetCACert"
#define OP_GET_INITIAL_CERT "PKCSOperation"
#define OP_PKCSREQ "PKCSOperation"
enum known_ops {
	op_unset,
	op_get_ca_caps,
	op_get_ca_cert,
	op_get_initial_cert,
	op_pkcsreq,
};

static void
help(const char *cmd)
{
	fprintf(stderr,
		"Usage: %s -u URL [options] [-c|-C|-g|-p] [pkiMessage]\n"
		"Options:\n"
		"\t[-i CA identifier]\n"
		"\t[-c]\n"
		"\t[-C]\n"
		"\t[-g]\n"
		"\t[-p]\n"
		"\t[-r racert]\n"
		"\t[-v]\n",
		strchr(cmd, '/') ? strrchr(cmd, '/') + 1 : cmd);
}

int
main(int argc, char **argv)
{
	const char *url = NULL, *results = NULL;
	struct cm_submit_h_context *hctx;
	int c, verbose = 0, results_length = 0;
	NSSInitContext *nctx;
	enum known_ops op = op_unset;
	const char *es, *racert = NULL, *id = NULL, *message = NULL;
	const char *mode = NULL, *p, *q;
	unsigned char *u;
	void *ctx;
	char *params = "";
	PRBool missing_args = PR_FALSE;

	id = getenv(CM_SUBMIT_SCEP_CA_IDENTIFIER_ENV);
	racert = getenv(CM_SUBMIT_SCEP_RA_CERTIFICATE_ENV);

	if (getenv(CM_SUBMIT_OPERATION_ENV) != NULL) {
		mode = getenv(CM_SUBMIT_OPERATION_ENV);
		if (strcasecmp(mode, CM_OP_SUBMIT) == 0) {
			op = op_pkcsreq;
			message = getenv(CM_SUBMIT_SCEP_PKCSREQ_REKEY_ENV);
			if (message != NULL) {
				message = getenv(CM_SUBMIT_SCEP_PKCSREQ_ENV);
			}
		} else
		if (strcasecmp(mode, CM_OP_POLL) == 0) {
			op = op_get_initial_cert;
			message = getenv(CM_SUBMIT_SCEP_GETCERTINITIAL_REKEY_ENV);
			if (message != NULL) {
				message = getenv(CM_SUBMIT_SCEP_GETCERTINITIAL_ENV);
			}
		} else
		if (strcasecmp(mode, CM_OP_FETCH_SCEP_CA_CERTS) == 0) {
			op = op_get_ca_cert;
		} else
		if (strcasecmp(mode, CM_OP_FETCH_SCEP_CA_CAPS) == 0) {
			op = op_get_ca_caps;
		} else
		if ((strcasecmp(mode, CM_OP_FETCH_ENROLL_REQUIREMENTS) == 0) ||
		    (strcasecmp(mode, CM_OP_FETCH_RENEWAL_REQUIREMENTS) == 0)) {
			printf("%s\n", CM_SUBMIT_SCEP_RA_CERTIFICATE_ENV);
			printf("%s\n", CM_SUBMIT_SCEP_PKCSREQ_ENV);
			printf("%s\n", CM_SUBMIT_SCEP_PKCSREQ_REKEY_ENV);
			printf("%s\n", CM_SUBMIT_SCEP_GETCERTINITIAL_ENV);
			printf("%s\n", CM_SUBMIT_SCEP_GETCERTINITIAL_REKEY_ENV);
			return CM_SUBMIT_STATUS_ISSUED;
		} else
		if (strcasecmp(mode, CM_OP_IDENTIFY) == 0) {
			printf("SCEP (%s %s)\n", PACKAGE_NAME, PACKAGE_VERSION);
			return CM_SUBMIT_STATUS_ISSUED;
		} else {
			/* unsupported request */
			return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
		}
	}

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif

	while ((c = getopt(argc, argv, "u:i:vcCgpr:")) != -1) {
		switch (c) {
		case 'u':
			url = optarg;
			break;
		case 'i':
			id = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'c':
			op = op_get_ca_caps;
			break;
		case 'C':
			op = op_get_ca_cert;
			break;
		case 'g':
			op = op_get_initial_cert;
			break;
		case 'p':
			op = op_pkcsreq;
			break;
		case 'r':
			/* XXX - read RA cert from the named file */
			racert = NULL;
			break;
		default:
			help(argv[0]);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
			break;
		}
	}

	umask(S_IRWXG | S_IRWXO);

	nctx = NSS_InitContext(CM_DEFAULT_CERT_STORAGE_LOCATION,
			       NULL, NULL, NULL, NULL,
			       NSS_INIT_NOCERTDB |
			       NSS_INIT_READONLY |
			       NSS_INIT_NOROOTINIT |
			       NSS_INIT_NOMODDB);
	if (nctx == NULL) {
		cm_log(1, "Unable to initialize NSS.\n");
		_exit(1);
	}
	es = util_n_fips_hook();
	if (es != NULL) {
		cm_log(1, "Error putting NSS into FIPS mode: %s\n", es);
		_exit(1);
	}

	ctx = talloc_new(NULL);

	if (url == NULL) {
		printf(_("No SCEP URL (-u) given, and no default known.\n"));
		missing_args = TRUE;
	}
	if (op == op_unset) {
		printf(_("No SCEP operation (-c/-C/-g/-p) given, and no default known.\n"));
		missing_args = TRUE;
	}

	/* Format the HTTP request's parameters. */
	switch (op) {
	case op_unset:
		missing_args = TRUE;
		break;
	case op_get_ca_caps:
		if (id == NULL) {
			params = "operation=" OP_GET_CA_CAPS;
		} else {
			params = talloc_asprintf(ctx, "operation=" OP_GET_CA_CAPS "&message=%s", id);
		}
		break;
	case op_get_ca_cert:
		if (id == NULL) {
			params = "operation=" OP_GET_CA_CERT;
		} else {
			params = talloc_asprintf(ctx, "operation=" OP_GET_CA_CERT "&message=%s", id);
		}
		break;
	case op_get_initial_cert:
		if (racert == NULL) {
			printf(_("No RA certificate (-r) given, and no default known.\n"));
			missing_args = TRUE;
		} else {
			/* XXX - read a PKCS7 Signed Data message (pkiMessage) from either stdin or a named file. */
			if (message == NULL) {
				return CM_SUBMIT_STATUS_NEED_SCEP_MESSAGES;
			}
			params = talloc_asprintf(ctx, "operation=" OP_GET_INITIAL_CERT "&message=%s", message);
		}
		break;
	case op_pkcsreq:
		if (racert == NULL) {
			printf(_("No RA certificate (-r) given, and no default known.\n"));
			missing_args = TRUE;
		} else {
			/* XXX - read a PKCS7 Signed Data message (pkiMessage) from either stdin or a named file. */
			if (message == NULL) {
				return CM_SUBMIT_STATUS_NEED_SCEP_MESSAGES;
			}
			params = talloc_asprintf(ctx, "operation=" OP_PKCSREQ "&message=%s", message);
		}
		break;
	}

	/* Supply help output, if it's needed. */
	if (missing_args) {
		help(argv[0]);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if (NSS_ShutdownContext(nctx) != SECSuccess) {
		printf(_("Error shutting down NSS.\n"));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}

	/* Submit the request. */
	hctx = cm_submit_h_init(ctx, "GET", url, params, NULL, NULL,
				NULL, NULL, NULL, NULL, NULL,
				cm_submit_h_negotiate_off,
				cm_submit_h_delegate_off,
				cm_submit_h_clientauth_off,
				cm_submit_h_env_modify_off,
				verbose > 1 ?
				cm_submit_h_curl_verbose_on :
				cm_submit_h_curl_verbose_off);
	cm_submit_h_run(hctx);
	if (verbose > 0) {
		printf("%s \"%s?%s\"\n", "GET", url, params);
		printf("code = %d\n", cm_submit_h_result_code(hctx));
		printf("code_text = \"%s\"\n", cm_submit_h_result_code_text(hctx));
		syslog(LOG_DEBUG, "%s %s?%s\n", "GET", url, params);
	}
	results = cm_submit_h_results(hctx, &results_length);
	if (verbose > 0) {
		printf("results = \"%s\"\n", results);
		syslog(LOG_DEBUG, "%s", results);
	}

	/* Figure out what to output. */
	if (cm_submit_h_result_code(hctx) != 0) {
		if (cm_submit_h_result_code_text(hctx) != NULL) {
			printf(_("Error %d connecting to %s: %s.\n"),
			       cm_submit_h_result_code(hctx),
			       url,
			       cm_submit_h_result_code_text(hctx));
		} else {
			printf(_("Error %d connecting to %s.\n"),
			       cm_submit_h_result_code(hctx),
			       url);
		}
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	if (results == NULL) {
		printf(_("Internal error: no response to \"%s?%s\".\n"),
		       url, params);
		return CM_SUBMIT_STATUS_REJECTED;
	}
	switch (op) {
	case op_unset:
		return CM_SUBMIT_STATUS_UNREACHABLE;
		break;
	case op_get_ca_caps:
		printf("%s\n", results);
		return CM_SUBMIT_STATUS_ISSUED;
		break;
	case op_get_ca_cert:
		/* XXX - make sure it's either X.509 or Signed-Data, and if it's the latter, output just the RA's cert */
		u = talloc_memdup(NULL, results, results_length);
		p = cm_store_base64_from_bin(NULL, u, results_length);
		printf("-----BEGIN CERTIFICATE-----\n");
		while (*p != '\0') {
			if (strlen(p) > 72) {
				q = p + 72;
			} else {
				q = p + strlen(p);
			}
			printf("%.*s\n", (int) (q - p), p);
			p = q;
		}
		printf("-----END CERTIFICATE-----\n");
		return CM_SUBMIT_STATUS_ISSUED;
		break;
	case op_get_initial_cert:
		/* XXX - verify that the reply is Signed-Data (a CertRep pkiMessage), signed by the RA cert, with a nonce matching the message we sent, and output an Enveloped-Data wrapped in a ContentInfo, if there is one in the Signed-Data. */
		break;
	case op_pkcsreq:
		/* XXX - verify that the reply is Signed-Data (a CertRep pkiMessage), signed by the RA cert, with a nonce matching the message we sent, and output an Enveloped-Data wrapped in a ContentInfo, if there is one in the Signed-Data. */
		break;
	}
	return CM_SUBMIT_STATUS_UNCONFIGURED;
}
