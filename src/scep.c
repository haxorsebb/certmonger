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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include <popt.h>

#include "log.h"
#include "pkcs7.h"
#include "prefs.h"
#include "scep.h"
#include "store.h"
#include "submit-e.h"
#include "submit-h.h"
#include "submit-u.h"
#include "util.h"
#include "util-m.h"
#include "util-o.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

#define OP_GET_CA_CAPS "GetCACaps"
#define OP_GET_CA_CERT "GetCACert"
#define OP_GET_CA_CHAIN "GetCAChain"
#define OP_GET_INITIAL_CERT "PKIOperation"
#define OP_PKCSREQ "PKIOperation"
enum known_ops {
	op_unset,
	op_get_ca_caps,
	op_get_ca_certs,
	op_get_initial_cert,
	op_pkcsreq,
};

static int
cert_cmp(X509 *x, char *candidate)
{
	X509 *c;
	BIO *in;
	int ret = 1;

	in = BIO_new_mem_buf(candidate, -1);
	if (in != NULL) {
		c = PEM_read_bio_X509(in, NULL, NULL, NULL);
		BIO_free(in);
		if (c != NULL) {
			ret = X509_cmp(x, c);
			X509_free(c);
		}
	}
	return ret;
}

static int
cert_among(char *needle, char *candidate1, char *candidate2, char **haystack)
{
	X509 *n;
	BIO *in;
	int ret = 1, i;

	in = BIO_new_mem_buf(needle, -1);
	if (in != NULL) {
		n = PEM_read_bio_X509(in, NULL, NULL, NULL);
		BIO_free(in);
		if (candidate1 != NULL) {
			ret = cert_cmp(n, candidate1);
			if (ret == 0) {
				X509_free(n);
				return ret;
			}
		}
		if (candidate2 != NULL) {
			ret = cert_cmp(n, candidate2);
			if (ret == 0) {
				X509_free(n);
				return ret;
			}
		}
		for (i = 0; (haystack != NULL) && (haystack[i] != NULL); i++) {
			ret = cert_cmp(n, haystack[i]);
			if (ret == 0) {
				X509_free(n);
				return ret;
			}
		}
		if (n != NULL) {
			X509_free(n);
		}
	}
	return ret;
}

static int
check_capability(const char *list, size_t list_length, const char *capability)
{
	const char *p, *q, *r, *n;
	char *tmp;

	p = list;
	cm_log(1, "Checking server capabilities list for \"%s\"",
	       capability);
	while (p < list + list_length) {
		/* Skip any blank lines. */
		while ((p < list + list_length) &&
		       (strchr("\r\n", *p) != NULL)) {
			p++;
		}
		/* Find either the end of this line, or the buffer. */
		n = memchr(p, '\n', (list + list_length) - p);
		r = memchr(p, '\r', (list + list_length) - p);
		if (n == NULL) {
			q = r;
		} else
		if (r == NULL) {
			q = n;
		} else {
			if (r < n) {
				q = r;
			} else {
				q = n;
			}
		}
		if (q == NULL) {
			q = list + list_length;
		}
		if (q < p) {
			/* should never happen */
			break;
		}
		/* If the length is right, check for a match. */
		if (((size_t)(q - p)) == strlen(capability)) {
			tmp = malloc(q - p + 1);
			if (tmp != NULL) {
				memcpy(tmp, capability, q - p);
				tmp[q - p] = '\0';
				if (strcasecmp(tmp, capability) == 0) {
					free(tmp);
					cm_log(1, " found it.\n");
					return 1;
				}
				free(tmp);
			}
		}
		/* Prepare to move to the next line. */
		p = q;
	}
	/* Out of data, and no match. */
	cm_log(1, " not found.\n");
	return 0;
}

int
main(int argc, const char **argv)
{
	const char *url = NULL, *results = NULL, *results2 = NULL;
	struct cm_submit_h_context *hctx;
	int c, verbose = 0, results_length = 0, results_length2 = 0, i;
	int prefer_non_renewal = 0, can_renewal = 0;
	int response_code = 0, response_code2 = 0;
	enum known_ops op = op_unset;
	const char *id = NULL, *cainfo = NULL;
	char *message = NULL, *rekey_message = NULL;
	const char *mode = NULL, *content_type = NULL, *content_type2 = NULL;
	void *ctx;
	char *params = "", *params2 = NULL, *racert = NULL, *cacert = NULL;
	char **othercerts = NULL, *cert1 = NULL, *cert2 = NULL, *certs = NULL;
	char **racertp, **cacertp, *dracert = NULL, *dcacert = NULL;
	char buf[LINE_MAX] = "";
	const unsigned char **buffers = NULL;
	size_t n_buffers = 0, *lengths = NULL, j;
	const char *cacerts[3], **racerts;
	dbus_bool_t missing_args = FALSE;
	char *sent_tx, *tx, *msgtype, *pkistatus, *failinfo, *s, *tmp1, *tmp2;
	unsigned char *sent_nonce, *sender_nonce, *recipient_nonce, *payload;
	const unsigned char *u;
	size_t sent_nonce_length, sender_nonce_length, recipient_nonce_length;
	size_t payload_length;
	long error;
	PKCS7 *p7;
	poptContext pctx;
	struct poptOption popts[] = {
		{"url", 'u', POPT_ARG_STRING, &url, 0, "service location", "URL"},
		{"ca-identifier", 'i', POPT_ARG_STRING, &id, 0, "name to use when querying for capabilities", "IDENTIFIER"},
		{"retrieve-ca-capabilities", 'c', POPT_ARG_NONE, NULL, 'c', "make a GetCACaps request", NULL},
		{"retrieve-ca-certificates", 'C', POPT_ARG_NONE, NULL, 'C', "make GetCACert/GetCAChain requests", NULL},
		{"get-initial-cert", 'g', POPT_ARG_NONE, NULL, 'g', "send a PKIOperation pkiMessage", NULL},
		{"pki-message", 'p', POPT_ARG_NONE, NULL, 'p', "send a PKIOperation pkiMessage", NULL},
		{"racert", 'r', POPT_ARG_STRING, NULL, 'r', "the RA certificate, used for encrypting requests", "FILENAME"},
		{"cacert", 'R', POPT_ARG_STRING, NULL, 'R', "the CA certificate, used for verifying responses", "FILENAME"},
		{"other-certs", 'I', POPT_ARG_STRING, NULL, 'I', "additional certificates", "FILENAME"},
		{"non-renewal", 'n', POPT_ARG_NONE, &prefer_non_renewal, 0, "prefer to not use the SCEP Renewal feature", NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	util_o_init();
	ERR_load_crypto_strings();

	id = getenv(CM_SUBMIT_SCEP_CA_IDENTIFIER_ENV);
	if (id == NULL) {
		id = "0";
	}
	racert = getenv(CM_SUBMIT_SCEP_RA_CERTIFICATE_ENV);
	cacert = getenv(CM_SUBMIT_SCEP_CA_CERTIFICATE_ENV);
	certs = getenv(CM_SUBMIT_SCEP_CERTIFICATES_ENV);

	mode = getenv(CM_SUBMIT_OPERATION_ENV);
	if (mode != NULL) {
		if (strcasecmp(mode, CM_OP_SUBMIT) == 0) {
			op = op_pkcsreq;
			message = getenv(CM_SUBMIT_SCEP_PKCSREQ_REKEY_ENV);
			if (message == NULL) {
				message = getenv(CM_SUBMIT_SCEP_PKCSREQ_ENV);
			} else {
				rekey_message = getenv(CM_SUBMIT_SCEP_PKCSREQ_ENV);
			}
		} else
		if (strcasecmp(mode, CM_OP_POLL) == 0) {
			op = op_get_initial_cert;
			message = getenv(CM_SUBMIT_SCEP_PKCSREQ_REKEY_ENV);
			if (message == NULL) {
				message = getenv(CM_SUBMIT_SCEP_PKCSREQ_ENV);
			} else {
				rekey_message = getenv(CM_SUBMIT_SCEP_PKCSREQ_ENV);
			}
		} else
		if (strcasecmp(mode, CM_OP_FETCH_SCEP_CA_CERTS) == 0) {
			op = op_get_ca_certs;
		} else
		if (strcasecmp(mode, CM_OP_FETCH_SCEP_CA_CAPS) == 0) {
			op = op_get_ca_caps;
		} else
		if ((strcasecmp(mode, CM_OP_FETCH_ENROLL_REQUIREMENTS) == 0) ||
		    (strcasecmp(mode, CM_OP_FETCH_RENEWAL_REQUIREMENTS) == 0)) {
			printf("%s\n", CM_SUBMIT_SCEP_RA_CERTIFICATE_ENV);
			printf("%s\n", CM_SUBMIT_SCEP_CA_CERTIFICATE_ENV);
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

	pctx = poptGetContext(argv[0], argc, argv, popts, 0);
	if (pctx == NULL) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	poptSetOtherOptionHelp(pctx, "[options] [pkiMessage file]");
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'c':
			op = op_get_ca_caps;
			break;
		case 'C':
			op = op_get_ca_certs;
			break;
		case 'g':
			op = op_get_initial_cert;
			break;
		case 'p':
			op = op_pkcsreq;
			break;
		case 'r':
			racert = cm_submit_u_from_file(poptGetOptArg(pctx));
			break;
		case 'R':
			cainfo = poptGetOptArg(pctx);
			cacert = cm_submit_u_from_file(cainfo);
			break;
		case 'I':
			certs = cm_submit_u_from_file(poptGetOptArg(pctx));
			break;
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	umask(S_IRWXG | S_IRWXO);
	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(verbose);

	ctx = talloc_new(NULL);

	if (url == NULL) {
		printf(_("No SCEP URL (-u) given, and no default known.\n"));
		missing_args = TRUE;
	}
	if (op == op_unset) {
		printf(_("No SCEP operation (-c/-C/-g/-p) given, and no default known.\n"));
		missing_args = TRUE;
	}

	/* Format the first (or only) HTTP request's parameters. */
	switch (op) {
	case op_unset:
		missing_args = TRUE;
		break;
	case op_get_ca_caps:
		/* Only step: read capabilities for the daemon. */
		params = talloc_asprintf(ctx, "operation=" OP_GET_CA_CAPS "&message=%s", id);
		break;
	case op_get_ca_certs:
		/* First step: get the root certificate. */
		params = talloc_asprintf(ctx, "operation=" OP_GET_CA_CERT "&message=%s", id);
		break;
	case op_get_initial_cert:
		if ((racert == NULL) || (strlen(racert) == 0)) {
			printf(_("No RA certificate (-r) given, and no default known.\n"));
			missing_args = TRUE;
		} else {
			/* Check that we at least have a message to send. */
			if ((message == NULL) || (strlen(message) == 0)) {
				if (poptPeekArg(pctx) != NULL) {
					message = cm_submit_u_from_file(poptGetArg(pctx));
				}
			}
			if ((message == NULL) || (strlen(message) == 0)) {
				printf(_("Error reading request, expected PKCS7 data.\n"));
				return CM_SUBMIT_STATUS_NEED_SCEP_MESSAGES;
			}
			/* First step: read capabilities for our use. */
			params = talloc_asprintf(ctx, "operation=" OP_GET_CA_CAPS "&message=%s", id);
		}
		break;
	case op_pkcsreq:
		if ((racert == NULL) || (strlen(racert) == 0)) {
			printf(_("No RA certificate (-r) given, and no default known.\n"));
			missing_args = TRUE;
		} else {
			/* Check that we at least have a message to send. */
			if ((message == NULL) || (strlen(message) == 0)) {
				if (poptPeekArg(pctx) != NULL) {
					message = cm_submit_u_from_file(poptGetArg(pctx));
				}
			}
			if ((message == NULL) || (strlen(message) == 0)) {
				printf(_("Error reading request, expected PKCS7 data.\n"));
				return CM_SUBMIT_STATUS_NEED_SCEP_MESSAGES;
			}
			/* First step: read capabilities for our use. */
			params = talloc_asprintf(ctx, "operation=" OP_GET_CA_CAPS "&message=%s", id);
		}
		break;
	}

	/* Supply help output, if it's needed. */
	if (missing_args) {
		poptPrintUsage(pctx, stdout, 0);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	/* Check the rekey PKCSReq message, if we have one. */
	if ((rekey_message != NULL) && (strlen(rekey_message) != 0)) {
		tmp1 = cm_submit_u_base64_from_text(rekey_message);
		tmp2 = cm_store_base64_as_bin(ctx, tmp1, -1, &c);
		cm_pkcs7_verify_signed((unsigned char *) tmp2, c,
				       NULL, NULL, NID_pkcs7_data, ctx, NULL,
				       NULL, &msgtype, NULL, NULL,
				       NULL, NULL,
				       NULL, NULL, NULL, NULL);
		if ((msgtype == NULL) ||
		    ((strcmp(msgtype, SCEP_MSGTYPE_PKCSREQ) != 0) &&
		     (strcmp(msgtype, SCEP_MSGTYPE_GETCERTINITIAL) != 0))) {
			if (msgtype == NULL) {
				fprintf(stderr, _("Warning: request is neither "
						  "a PKCSReq nor a "
						  "GetInitialCert request.\n"));
			} else {
				fprintf(stderr, _("Warning: request type \"%s\""
						  "is neither a PKCSReq nor a "
						  "GetInitialCert request.\n"),
						  msgtype);
			}
		}
	}

	/* Now, check the regular single-key message, and pick up the
	 * transaction ID and nonce from it. */
	if ((message != NULL) && (strlen(message) != 0)) {
		tmp1 = cm_submit_u_base64_from_text(message);
		tmp2 = cm_store_base64_as_bin(ctx, tmp1, -1, &c);
		cm_pkcs7_verify_signed((unsigned char *) tmp2, c,
				       NULL, NULL, NID_pkcs7_data, ctx, NULL,
				       &sent_tx, &msgtype, NULL, NULL,
				       &sent_nonce, &sent_nonce_length,
				       NULL, NULL, NULL, NULL);
		if ((msgtype == NULL) ||
		    ((strcmp(msgtype, SCEP_MSGTYPE_PKCSREQ) != 0) &&
		     (strcmp(msgtype, SCEP_MSGTYPE_GETCERTINITIAL) != 0))) {
			if (msgtype == NULL) {
				fprintf(stderr, _("Warning: request is neither "
						  "a PKCSReq nor a "
						  "GetInitialCert request.\n"));
			} else {
				fprintf(stderr, _("Warning: request type \"%s\""
						  "is neither a PKCSReq nor a "
						  "GetInitialCert request.\n"),
						  msgtype);
			}
		}
		if (sent_tx == NULL) {
			fprintf(stderr, _("Warning: request is missing "
					  "transactionId.\n"));
		}
		if (sent_nonce == NULL) {
			fprintf(stderr, _("Warning: request is missing "
					  "senderNonce.\n"));
		}
	} else {
		sent_tx = NULL;
		sent_nonce = NULL;
		sent_nonce_length = 0;
	}

	/* Submit the first request. */
	hctx = cm_submit_h_init(ctx, "GET", url, params, NULL, NULL,
				cainfo, NULL, NULL, NULL, NULL,
				cm_submit_h_negotiate_off,
				cm_submit_h_delegate_off,
				cm_submit_h_clientauth_off,
				cm_submit_h_env_modify_off,
				verbose > 1 ?
				cm_submit_h_curl_verbose_on :
				cm_submit_h_curl_verbose_off);
	cm_submit_h_run(hctx);
	content_type = cm_submit_h_result_type(hctx);
	if (content_type == NULL) {
		content_type = "";
	}
	response_code = cm_submit_h_response_code(hctx);
	if (verbose > 0) {
		fprintf(stderr, "%s \"%s?%s\"\n", "GET", url, params);
		fprintf(stderr, "response_code = %d\n", response_code);
		fprintf(stderr, "content-type = \"%s\"\n", content_type);
		fprintf(stderr, "code = %d\n", cm_submit_h_result_code(hctx));
		fprintf(stderr, "code_text = \"%s\"\n", cm_submit_h_result_code_text(hctx));
		syslog(LOG_DEBUG, "%s %s?%s\n", "GET", url, params);
	}
	results = cm_submit_h_results(hctx, &results_length);
	if (verbose > 0) {
		fprintf(stderr, "results = \"%s\"\n",
			cm_store_base64_from_bin(ctx, (const unsigned char *) results,
						 results_length));
		syslog(LOG_DEBUG, "%s",
		       cm_store_base64_from_bin(ctx, (const unsigned char *) results,
						results_length));
	}

	/* Format a possible second HTTP request's parameters. */
	switch (op) {
	case op_unset:
		abort(); /* never reached */
		break;
	case op_get_ca_caps:
		/* nothing to do here */
		params2 = NULL;
		break;
	case op_get_ca_certs:
		/* Step two: request the chain. */
		params2 = talloc_asprintf(ctx, "operation=" OP_GET_CA_CHAIN "&message=%s", id);
		break;
	case op_get_initial_cert:
		/* Step two: actually poll.  If we have multiple messages which
		 * we can use, decide which one to use. */
		can_renewal = check_capability(results, results_length, "Renewal");
		if (can_renewal && !prefer_non_renewal && (rekey_message != NULL)) {
			tmp2 = rekey_message;
		} else {
			tmp2 = message;
		}
		if ((tmp2 == NULL) || (strlen(tmp2) == 0)) {
			printf(_("Error reading request, expected PKCS7 data.\n"));
			return CM_SUBMIT_STATUS_NEED_SCEP_MESSAGES;
		} else
		if (verbose > 0) {
			if (tmp2 == rekey_message) {
				fprintf(stderr, "Using rekeying message.\n");
			} else {
				fprintf(stderr, "Using non-rekeying message.\n");
			}
		}
		tmp1 = cm_submit_u_base64_from_text(tmp2);
		tmp2 = cm_submit_u_url_encode(tmp1);
		params2 = talloc_asprintf(ctx, "operation=" OP_GET_INITIAL_CERT "&message=%s", tmp2);
		break;
	case op_pkcsreq:
		/* Step two: actually request a certificate.  If we have
		 * multiple messages which we can use, decide which one to use
		 * to make the request. */
		can_renewal = check_capability(results, results_length, "Renewal");
		if (can_renewal && !prefer_non_renewal && (rekey_message != NULL)) {
			tmp2 = rekey_message;
		} else {
			tmp2 = message;
		}
		if ((tmp2 == NULL) || (strlen(tmp2) == 0)) {
			printf(_("Error reading request, expected PKCS7 data.\n"));
			return CM_SUBMIT_STATUS_NEED_SCEP_MESSAGES;
		} else
		if (verbose > 0) {
			if (tmp2 == rekey_message) {
				fprintf(stderr, "Using rekeying message.\n");
			} else {
				fprintf(stderr, "Using non-rekeying message.\n");
			}
		}
		tmp1 = cm_submit_u_base64_from_text(tmp2);
		tmp2 = cm_submit_u_url_encode(tmp1);
		params2 = talloc_asprintf(ctx, "operation=" OP_PKCSREQ "&message=%s", tmp2);
		break;
	}
	/* Submit a second HTTP request if we have one to make. */
	if (params2 != NULL) {
		hctx = cm_submit_h_init(ctx, "GET", url, params2, NULL, NULL,
					NULL, NULL, NULL, NULL, NULL,
					cm_submit_h_negotiate_off,
					cm_submit_h_delegate_off,
					cm_submit_h_clientauth_off,
					cm_submit_h_env_modify_off,
					verbose > 1 ?
					cm_submit_h_curl_verbose_on :
					cm_submit_h_curl_verbose_off);
		cm_submit_h_run(hctx);
		content_type2 = cm_submit_h_result_type(hctx);
		if (content_type2 == NULL) {
			content_type2 = "";
		}
		response_code2 = cm_submit_h_response_code(hctx);
		if (verbose > 0) {
			fprintf(stderr, "%s \"%s?%s\"\n", "GET", url, params2);
			fprintf(stderr, "response_code = %d\n", response_code2);
			fprintf(stderr, "content-type = \"%s\"\n", content_type2);
			fprintf(stderr, "code = %d\n", cm_submit_h_result_code(hctx));
			fprintf(stderr, "code_text = \"%s\"\n", cm_submit_h_result_code_text(hctx));
			syslog(LOG_DEBUG, "%s %s?%s\n", "GET", url, params2);
		}
		results2 = cm_submit_h_results(hctx, &results_length2);
		if (verbose > 0) {
			fprintf(stderr, "results = \"%s\"\n",
				cm_store_base64_from_bin(ctx, (const unsigned char *) results2,
							 results_length2));
			syslog(LOG_DEBUG, "%s",
			       cm_store_base64_from_bin(ctx, (const unsigned char *) results2,
							results_length2));
		}
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
	switch (op) {
	case op_unset:
		abort();
		break;
	case op_get_ca_caps:
	case op_get_ca_certs:
		if (response_code != 200) {
			printf(_("Got response code %d from %s, not 200.\n"),
			       response_code, url);
			if (response_code == 500) {
				/* The server might recover, right? */
				return CM_SUBMIT_STATUS_UNREACHABLE;
			} else {
				/* Maybe not? */
				return CM_SUBMIT_STATUS_REJECTED;
			}
		}
		if (results == NULL) {
			printf(_("Internal error: no response to \"%s?%s\".\n"),
			       url, params);
			return CM_SUBMIT_STATUS_REJECTED;
		}
		break;
	case op_get_initial_cert:
	case op_pkcsreq:
		/* ignore an error status */
		break;
	}

	switch (op) {
	case op_unset:
		abort(); /* never reached */
		break;
	case op_get_ca_caps:
		if (results_length > 1024) {
			/* This is a guess at a reasonable maximum size for a
			 * result that isn't just some random page being served
			 * up at the location we queried.  The spec says we
			 * can't make any assumptions about the content-type,
			 * so this is the best we can do to avoid trying to
			 * parse a pile of HTML as a capabilities list. */
			if (verbose > 0) {
				fprintf(stderr, "Result is surprisingly large, "
					"suppressing it.\n");
			}
			return CM_SUBMIT_STATUS_REJECTED;
		}
		printf("%s\n", results);
		return CM_SUBMIT_STATUS_ISSUED;
		break;
	case op_get_ca_certs:
		if ((strcasecmp(content_type,
				"application/x-x509-ca-cert") != 0) &&
		    (strcasecmp(content_type,
				"application/x-x509-ca-ra-cert") != 0)) {
			printf(_("Server reply was of unexpected MIME type "
				 "\"%s\".\n"), content_type);
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		if (racert == NULL) {
			racertp = &racert;
		} else {
			racertp = &dracert;
			buffers = talloc_realloc(ctx, buffers,
						 const unsigned char *,
						 n_buffers + 1);
			lengths = talloc_realloc(ctx, lengths, size_t,
						 n_buffers + 1);
			if ((buffers == NULL) || (lengths == NULL)) {
				fprintf(stderr, "Out of memory.\n");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			buffers[n_buffers] = (unsigned char *) racert;
			lengths[n_buffers] = strlen(racert);
			n_buffers++;
		}
		if (cacert == NULL) {
			cacertp = &cacert;
		} else {
			cacertp = &dcacert;
			buffers = talloc_realloc(ctx, buffers,
						 const unsigned char *,
						 n_buffers + 1);
			lengths = talloc_realloc(ctx, lengths, size_t,
						 n_buffers + 1);
			if ((buffers == NULL) || (lengths == NULL)) {
				fprintf(stderr, "Out of memory.\n");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			buffers[n_buffers] = (unsigned char *) cacert;
			lengths[n_buffers] = strlen(cacert);
			n_buffers++;
		}
		if (results != NULL) {
			buffers = talloc_realloc(ctx, buffers,
						 const unsigned char *,
						 n_buffers + 1);
			lengths = talloc_realloc(ctx, lengths, size_t,
						 n_buffers + 1);
			if ((buffers == NULL) || (lengths == NULL)) {
				fprintf(stderr, "Out of memory.\n");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			buffers[n_buffers] = (unsigned char *) results;
			lengths[n_buffers] = results_length;
			n_buffers++;
		}
		if (results2 != NULL) {
			buffers = talloc_realloc(ctx, buffers,
						 const unsigned char *,
						 n_buffers + 1);
			lengths = talloc_realloc(ctx, lengths, size_t,
						 n_buffers + 1);
			if ((buffers == NULL) || (lengths == NULL)) {
				fprintf(stderr, "Out of memory.\n");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			buffers[n_buffers] = (unsigned char *) results2;
			lengths[n_buffers] = results_length2;
			n_buffers++;
		}
		i = 1;
		/* If the server handed us one certificate back, then maybe
		 * it's Dogtag, which expects us to walk the list. */
		while ((strcmp(id, "0") == 0) &&
		       (strcasecmp(content_type,
			           "application/x-x509-ca-cert") == 0)) {
			if (i > 32) {
				if (verbose > 0) {
					fprintf(stderr, "Improbably long "
						"chain, or bug.\n");
				}
				break;
			}
			if (verbose > 0) {
				fprintf(stderr, "Asking for cert for ID "
					"\"%d\".\n", i);
			}
			params = talloc_asprintf(ctx, "operation="
						 OP_GET_CA_CERT
						 "&message=%d", i++);
			hctx = cm_submit_h_init(ctx, "GET", url, params,
						NULL, NULL, NULL, NULL,
						NULL, NULL, NULL,
						cm_submit_h_negotiate_off,
						cm_submit_h_delegate_off,
						cm_submit_h_clientauth_off,
						cm_submit_h_env_modify_off,
						verbose > 1 ?
						cm_submit_h_curl_verbose_on :
						cm_submit_h_curl_verbose_off);
			cm_submit_h_run(hctx);
			content_type2 = cm_submit_h_result_type(hctx);
			response_code2 = cm_submit_h_response_code(hctx);
			if (verbose > 0) {
				fprintf(stderr, "%s \"%s?%s\"\n", "GET", url, params2);
				fprintf(stderr, "response_code = %d\n", response_code2);
				fprintf(stderr, "content-type = \"%s\"\n", content_type2);
				fprintf(stderr, "code = %d\n", cm_submit_h_result_code(hctx));
				fprintf(stderr, "code_text = \"%s\"\n", cm_submit_h_result_code_text(hctx));
				syslog(LOG_DEBUG, "%s %s?%s\n", "GET", url, params2);
			}
			if (strcasecmp(content_type2,
				       "application/x-x509-ca-cert") != 0) {
				if (verbose > 0) {
					fprintf(stderr, "Content is not "
						"\"application/x-x509-ca-cert\""
						", done.\n");
				}
				break;
			}
			if (response_code2 != 200) {
				if (verbose > 0) {
					fprintf(stderr, "Response code "
						"is not 200, done.\n");
				}
				break;
			}
			results2 = cm_submit_h_results(hctx, &results_length2);
			if (verbose > 0) {
				fprintf(stderr, "results = \"%s\"\n", results2);
				syslog(LOG_DEBUG, "%s", results2);
			}
			if (results_length2 <= 0) {
				if (verbose > 0) {
					fprintf(stderr, "Content is empty, "
						"done.\n");
				}
				break;
			}
			for (j = 0; j < n_buffers; j++) {
				if ((results_length2 == (int) lengths[j]) &&
				    (memcmp(results2, buffers[j], lengths[j]) == 0)) {
					if (verbose > 0) {
						fprintf(stderr, "Content is "
							"a duplicate, done.\n");
					}
					break;
				}
			}
			if (j < n_buffers) {
				break;
			}
			buffers = talloc_realloc(ctx, buffers,
						 const unsigned char *,
						 n_buffers + 1);
			lengths = talloc_realloc(ctx, lengths, size_t,
						 n_buffers + 1);
			if ((buffers == NULL) || (lengths == NULL)) {
				fprintf(stderr, "Out of memory.\n");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			buffers[n_buffers] = (unsigned char *) results2;
			lengths[n_buffers] = results_length2;
			n_buffers++;
		}
		if (cm_pkcs7_parsev(CM_PKCS7_LEAF_PREFER_ENCRYPT, ctx,
				    racertp, cacertp, &othercerts,
				    NULL, NULL,
				    n_buffers, buffers, lengths) == 0) {
			if (racert != NULL) {
				printf("%s", racert);
				if (cacert != NULL) {
					printf("%s", cacert);
					if (othercerts != NULL) {
						for (c = 0;
						     othercerts[c] != NULL;
						     c++) {
							printf("%s",
							       othercerts[c]);
						}
					}
					if ((dracert != NULL) &&
					    (cert_among(dracert, racert, cacert, othercerts) != 0)) {
						printf("%s", dracert);
					}
					if ((dcacert != NULL) &&
					    (cert_among(dcacert, racert, cacert, othercerts) != 0)) {
						printf("%s", dcacert);
					}
				}
			}
			talloc_free(ctx);
			return CM_SUBMIT_STATUS_ISSUED;
		} else {
			talloc_free(ctx);
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		break;
	case op_get_initial_cert:
	case op_pkcsreq:
		if (strcasecmp(content_type2,
			       "application/x-pki-message") == 0) {
			memset(&cacerts, 0, sizeof(cacerts));
			cacerts[0] = cacert ? cacert : racert;
			cacerts[1] = cacert ? racert : NULL;
			cacerts[2] = NULL;
			racerts = NULL;
			if ((certs != NULL) &&
			    (cm_pkcs7_parse(0, ctx,
					    &cert1, &cert2, &othercerts,
					    NULL, NULL,
					    (const unsigned char *) certs,
					    strlen(certs), NULL) == 0)) {
				for (c = 0;
				     (othercerts != NULL) &&
				     (othercerts[c] != NULL);
				     c++) {
					continue;
				}
				racerts = talloc_array_ptrtype(ctx, racerts, c + 5);
				for (c = 0;
				     (othercerts != NULL) &&
				     (othercerts[c] != NULL);
				     c++) {
					racerts[c] = othercerts[c];
				}
				if (cacert != NULL) {
					racerts[c++] = cacert;
				}
				if (cert1 != NULL) {
					racerts[c++] = cert1;
				}
				if (cert2 != NULL) {
					racerts[c++] = cert2;
				}
				if (racert != NULL) {
					racerts[c++] = racert;
				}
				racerts[c++] = NULL;
			}
			ERR_clear_error();
			i = cm_pkcs7_verify_signed((unsigned char *) results2, results_length2,
						   cacerts, racerts,
						   NID_pkcs7_data, ctx, NULL,
						   &tx, &msgtype, &pkistatus, &failinfo,
						   &sender_nonce, &sender_nonce_length,
						   &recipient_nonce, &recipient_nonce_length,
						   &payload, &payload_length);
			if (i != 0) {
				printf(_("Error: failed to verify signature on "
					 "server response.\n"));
				while ((error = ERR_get_error()) != 0) {
					memset(buf, '\0', sizeof(buf));
					ERR_error_string_n(error, buf, sizeof(buf));
					cm_log(1, "%s\n", buf);
				}
				s = cm_store_base64_from_bin(ctx, (unsigned char *) results,
							     results_length);
				s = cm_submit_u_pem_from_base64("PKCS7", 0, s);
				fprintf(stderr, "%s", s);
				free(s);
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			if ((msgtype == NULL) ||
			    (strcmp(msgtype, SCEP_MSGTYPE_CERTREP) != 0)) {
				printf(_("Error: reply was not a CertRep (%s).\n"),
				       msgtype ? msgtype : "none");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			if (tx == NULL) {
				printf(_("Error: reply is missing transactionId.\n"));
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			if (sent_tx != NULL) {
				if (strcmp(sent_tx, tx) != 0) {
					printf(_("Error: reply contains a "
						 "different transactionId.\n"));
					return CM_SUBMIT_STATUS_UNREACHABLE;
				}
			}
			if (pkistatus == NULL) {
				printf(_("Error: reply is missing pkiStatus.\n"));
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			if (recipient_nonce == NULL) {
				printf(_("Error: reply is missing recipientNonce.\n"));
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			if ((recipient_nonce_length != sent_nonce_length) ||
			    (memcmp(recipient_nonce, sent_nonce,
				    sent_nonce_length) != 0)) {
				printf(_("Error: reply nonce doesn't match request.\n"));
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			if (sender_nonce == NULL) {
				printf(_("Error: reply is missing senderNonce.\n"));
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			if (strcmp(pkistatus, SCEP_PKISTATUS_PENDING) == 0) {
				s = cm_store_base64_from_bin(ctx, sender_nonce,
							     sender_nonce_length);
				printf("%s\n", s);
				return CM_SUBMIT_STATUS_WAIT;
			} else
			if (strcmp(pkistatus, SCEP_PKISTATUS_FAILURE) == 0) {
				if (failinfo == NULL) {
					printf(_("Unspecified failure at server.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_BAD_ALG) == 0) {
					printf(_("Unrecognized or unsupported algorithm identifier in client request.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_BAD_MESSAGE_CHECK) == 0) {
					printf(_("Integrity check of client request failed at server.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_BAD_REQUEST) == 0) {
					printf(_("Transaction either is not permitted or is not supported by server.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_BAD_TIME) == 0) {
					printf(_("Clock skew too great.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_UNSUPPORTED_EXT) == 0) {
					printf(_("Unsupported extension.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_MUST_ARCHIVE_KEYS) == 0) {
					printf(_("Must archive keys.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_BAD_IDENTITY) == 0) {
					printf(_("Bad identity.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_POP_REQUIRED) == 0) {
					printf(_("Proof of possession required.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_POP_FAILED) == 0) {
					printf(_("Proof of possession failed.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_NO_KEY_REUSE) == 0) {
					printf(_("No key reuse.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_INTERNAL_CA_ERROR) == 0) {
					printf(_("Internal CA error.\n"));
				} else
				if (strcmp(failinfo, SCEP_FAILINFO_TRY_LATER) == 0) {
					printf(_("Try later.\n"));
				} else {
					printf(_("Server returned failure code \"%s\".\n"),
					       failinfo);
				}
				return CM_SUBMIT_STATUS_REJECTED;
			} else
			if (strcmp(pkistatus, SCEP_PKISTATUS_SUCCESS) == 0) {
				u = payload;
				p7 = d2i_PKCS7(NULL, &u, payload_length);
				if (p7 == NULL) {
					printf(_("Error: couldn't parse signed-data.\n"));
					while ((error = ERR_get_error()) != 0) {
						memset(buf, '\0', sizeof(buf));
						ERR_error_string_n(error, buf, sizeof(buf));
						cm_log(1, "%s\n", buf);
					}
					s = cm_store_base64_from_bin(ctx,
								     (unsigned char *) results2,
								     results_length2);
					s = cm_submit_u_pem_from_base64("PKCS7", 0, s);
					fprintf(stderr, "Full reply:\n%s", s);
					free(s);
					return CM_SUBMIT_STATUS_UNREACHABLE;
				}
				if (!PKCS7_type_is_enveloped(p7)) {
					printf(_("Error: signed-data payload is not enveloped-data.\n"));
					while ((error = ERR_get_error()) != 0) {
						memset(buf, '\0', sizeof(buf));
						ERR_error_string_n(error, buf, sizeof(buf));
						cm_log(1, "%s\n", buf);
					}
					s = cm_store_base64_from_bin(ctx,
								     (unsigned char *) results2,
								     results_length2);
					s = cm_submit_u_pem_from_base64("PKCS7", 0, s);
					fprintf(stderr, "Full reply:\n%s", s);
					free(s);
					return CM_SUBMIT_STATUS_UNREACHABLE;
				}
				if (!PKCS7_type_is_enveloped(p7)) {
					printf(_("Error: signed-data payload is not enveloped-data.\n"));
					while ((error = ERR_get_error()) != 0) {
						memset(buf, '\0', sizeof(buf));
						ERR_error_string_n(error, buf, sizeof(buf));
						cm_log(1, "%s\n", buf);
					}
					s = cm_store_base64_from_bin(ctx,
								     (unsigned char *) results2,
								     results_length2);
					s = cm_submit_u_pem_from_base64("PKCS7", 0, s);
					fprintf(stderr, "Full reply:\n%s", s);
					free(s);
					return CM_SUBMIT_STATUS_UNREACHABLE;
				}
				if ((p7->d.enveloped == NULL) ||
				    (p7->d.enveloped->enc_data == NULL) ||
				    (p7->d.enveloped->enc_data->content_type == NULL) ||
				    (OBJ_obj2nid(p7->d.enveloped->enc_data->content_type) != NID_pkcs7_data)) {
					printf(_("Error: enveloped-data payload is not data.\n"));
					while ((error = ERR_get_error()) != 0) {
						memset(buf, '\0', sizeof(buf));
						ERR_error_string_n(error, buf, sizeof(buf));
						cm_log(1, "%s\n", buf);
					}
					s = cm_store_base64_from_bin(ctx,
								     (unsigned char *) results2,
								     results_length2);
					s = cm_submit_u_pem_from_base64("PKCS7", 0, s);
					fprintf(stderr, "Full reply:\n%s", s);
					free(s);
					return CM_SUBMIT_STATUS_UNREACHABLE;
				}
				s = cm_store_base64_from_bin(ctx, payload,
							     payload_length);
				s = cm_submit_u_pem_from_base64("PKCS7", 0, s);
				printf("%s", s);
				free(s);
				return CM_SUBMIT_STATUS_ISSUED;
			} else {
				printf(_("Error: pkiStatus \"%s\" not recognized.\n"),
				       pkistatus);
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
		} else {
			printf(_("Server reply was of unexpected MIME type "
				 "\"%s\".\n"), content_type);
			printf("Full reply:\n%.*s", results_length2, results2);
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		break;
	}
	return CM_SUBMIT_STATUS_UNCONFIGURED;
}
