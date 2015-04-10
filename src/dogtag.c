/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014 Red Hat, Inc.
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
#include "submit-d.h"
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

#ifdef DOGTAG_IPA_RENEW_AGENT
#include "dogtag-ipa.h"
#endif

static void
help(const char *cmd)
{
	fprintf(stderr,
		"Usage: %s -E EE-URL -A AGENT-URL [options]\n"
		"Options:\n"
		"\t[-d dbdir]\n"
		"\t[-n nickname]\n"
		"\t[-i cainfo]\n"
		"\t[-C capath]\n"
		"\t[-c certfile]\n"
		"\t[-k keyfile]\n"
		"\t[-p pinfile]\n"
		"\t[-P pin]\n"
		"\t[-s serial (hex)]\n"
		"\t[-D serial (decimal)]\n"
		"\t[-S state]\n"
		"\t[-T profile]\n"
		"\t[-O param=value]\n"
		"\t[-v]\n"
		"\t[-N | -R]\n"
		"\t[-V dogtag_version]\n"
		"\t[csrfile]\n",
		strchr(cmd, '/') ? strrchr(cmd, '/') + 1 : cmd);
}

static char *
statevar(const char *state, const char *what)
{
	const char *p;
	char *q;
	int len;

	p = state;
	len = strlen(what);
	while ((p != NULL) && (*p != '\0')) {
		if ((strncmp(p, what, len) == 0) && (p[len] == '=')) {
			p += (len + 1);
			len = strcspn(p, "&\r\n");
			q = malloc(len + 1);
			if (q != NULL) {
				memcpy(q, p, len);
				q[len] = '\0';
			}
			return q;
		}
		p += strcspn(p, "&");
		while (*p == '&') {
			p++;
		}
	}
	return NULL;
}

static char *
serial_hex_from_cert(const char *cert)
{
	CERTCertificate *c;
	char *ret = NULL, *pem;

	if ((cert != NULL) && (strlen(cert) > 0)) {
		pem = talloc_strdup(NULL, cert);
		if (pem != NULL) {
			c = CERT_DecodeCertFromPackage(pem, strlen(pem));
			if (c != NULL) {
				ret = cm_store_hex_from_bin(NULL,
							    c->serialNumber.data,
							    c->serialNumber.len);
				CERT_DestroyCertificate(c);
			}
		}
	}
	return ret;
}

int
main(int argc, char **argv)
{
	const char *eeurl = NULL, *agenturl = NULL, *url = NULL, *url2 = NULL;
	const char *ssldir = NULL, *cainfo = NULL, *capath = NULL;
	const char *sslcert = NULL, *sslkey = NULL;
	const char *sslpin = NULL, *sslpinfile = NULL;
	const char *csr = NULL, *serial = NULL, *template = NULL;
	struct {
		char *name;
		char *value;
	} *options = NULL;
	size_t num_options = 0, j;
	char *savedstate = NULL;
	char *p, *q, *params = NULL, *params2 = NULL;
	const char *lasturl = NULL, *lastparams = NULL;
	const char *tmp = NULL, *results = NULL;
	struct cm_submit_h_context *hctx;
	void *ctx;
	int c, verbose = 0, force_new = 0, force_renew = 0, i;
#ifdef DOGTAG_IPA_RENEW_AGENT
	const char *host = NULL, *dogtag_version = NULL;
	int eeport, agentport;
#endif
	enum { op_none, op_submit, op_check, op_approve, op_retrieve } op = op_none;
	dbus_bool_t can_agent, use_agent, missing_args = FALSE;
	struct dogtag_default **defaults;
	enum cm_external_status ret;
	NSSInitContext *nctx;
	const char *es;
	const char *mode = CM_OP_SUBMIT;

	if (getenv(CM_SUBMIT_OPERATION_ENV) != NULL) {
		mode = getenv(CM_SUBMIT_OPERATION_ENV);
	}
	if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
	    (strcasecmp(mode, CM_OP_POLL) == 0)) {
		/* fall through */
	} else
	if (strcasecmp(mode, CM_OP_IDENTIFY) == 0) {
#ifdef DOGTAG_IPA_RENEW_AGENT
		printf("Dogtag (IPA,renew,agent) (%s %s)\n", PACKAGE_NAME,
		       PACKAGE_VERSION);
#else
		printf("Dogtag (%s %s)\n", PACKAGE_NAME, PACKAGE_VERSION);
#endif
		return 0;
	} else {
		/* unsupported request */
		return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
	}

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif

	savedstate = getenv(CM_SUBMIT_COOKIE_ENV);

	while ((c = getopt(argc, argv, "E:A:d:n:i:C:c:k:p:P:s:D:S:T:O:vV:NR")) != -1) {
		switch (c) {
		case 'E':
			eeurl = optarg;
			break;
		case 'A':
			agenturl = optarg;
			break;
		case 'd':
			ssldir = optarg;
			break;
		case 'i':
			cainfo = optarg;
			break;
		case 'C':
			capath = optarg;
			break;
		case 'c':
		case 'n':
			sslcert = optarg;
			break;
		case 'k':
			sslkey = optarg;
			break;
		case 'p':
			sslpinfile = optarg;
			break;
		case 'P':
			sslpin = optarg;
			break;
		case 'D':
			serial = optarg;
			break;
		case 's':
			serial = util_dec_from_hex(optarg);
			break;
		case 'S':
			savedstate = optarg;
			break;
		case 'T':
			template = optarg;
			break;
		case 'O':
			if (strchr(optarg, '=') == NULL) {
				printf(_("Profile params (-O) must be in the form of param=value.\n"));
				help(argv[0]);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			options = realloc(options,
					  ++num_options * sizeof(*options));
			if (options == NULL) {
				printf(_("Out of memory.\n"));
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			p = strdup(optarg);
			if (p == NULL) {
				printf(_("Out of memory.\n"));
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			i = strcspn(p, "=");
			options[num_options - 1].name = p;
			p[i] = '\0';
			options[num_options - 1].value = p + i + 1;
			break;
		case 'v':
			verbose++;
			break;
#ifdef DOGTAG_IPA_RENEW_AGENT
		case 'V':
			dogtag_version = optarg;
			break;
#endif
		case 'N':
			force_new++;
			force_renew = 0;
			break;
		case 'R':
			force_renew++;
			force_new = 0;
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

#ifdef DOGTAG_IPA_RENEW_AGENT
	cm_dogtag_ipa_hostver(&host, &dogtag_version);
	if ((dogtag_version != NULL) && (atof(dogtag_version) >= 10)) {
		eeport = 8080;
		agentport = 8443;
	} else {
		eeport = 9180;
		agentport = 9443;
	}
	if (eeurl == NULL) {
		eeurl = cm_prefs_dogtag_ee_url();
		if ((eeurl == NULL) && (host != NULL)) {
			eeurl = talloc_asprintf(ctx,
						"http://%s:%d/ca/ee/ca",
						host, eeport);
		}
	}
	if (agenturl == NULL) {
		agenturl = cm_prefs_dogtag_agent_url();
		if ((agenturl == NULL) && (host != NULL)) {
			agenturl = talloc_asprintf(ctx,
						   "https://%s:%d/ca/agent/ca",
						   host, agentport);
		}
	}
#endif

	if (template == NULL) {
		template = getenv(CM_SUBMIT_PROFILE_ENV);
		if (template == NULL) {
			template = cm_prefs_dogtag_profile();
			if (template == NULL) {
				/* Maybe we should ask the server for which
				 * profiles it supports, but for now we just
				 * assume that this one hasn't been removed. */
				template = "caServerCert";
			}
		}
	}
	if (serial == NULL) {
		tmp = getenv(CM_SUBMIT_CERTIFICATE_ENV);
		if (tmp != NULL) {
			if (cm_prefs_dogtag_renew()) {
				serial = serial_hex_from_cert(tmp);
				if (serial != NULL) {
					serial = util_dec_from_hex(serial);
				}
			}
		}
	}
	if (cainfo == NULL) {
		cainfo = cm_prefs_dogtag_ca_info();
	}
	if (capath == NULL) {
		capath = cm_prefs_dogtag_ca_path();
	}
	if (ssldir == NULL) {
		ssldir = cm_prefs_dogtag_ssldir();
	}
	if (sslcert == NULL) {
		sslcert = cm_prefs_dogtag_sslcert();
	}
	if (sslkey == NULL) {
		sslkey = cm_prefs_dogtag_sslkey();
	}
	if ((sslpinfile == NULL) && (sslpin == NULL)) {
		sslpinfile = cm_prefs_dogtag_sslpinfile();
	}
#ifdef DOGTAG_IPA_RENEW_AGENT
	if ((cainfo == NULL) &&
	    (capath == NULL) &&
	    (ssldir == NULL) &&
	    (sslcert == NULL) &&
	    (sslkey == NULL) &&
	    (sslpin == NULL) &&
	    (sslpinfile == NULL)) {
		cainfo = "/etc/ipa/ca.crt";
		ssldir = "/etc/httpd/alias";
		sslcert = "ipaCert";
		sslpinfile = "/etc/httpd/alias/pwdfile.txt";
	}
#endif
	if ((sslcert != NULL) && (strlen(sslcert) > 0)) {
		can_agent = TRUE;
	} else {
		can_agent = FALSE;
	}
	if (force_renew && (serial == NULL)) {
		printf(_("Requested renewal, but no serial number provided.\n"));
		missing_args = TRUE;
	}
	if (eeurl == NULL) {
		printf(_("No end-entity URL (-E) given, and no default known.\n"));
		missing_args = TRUE;
	}
#ifdef DOGTAG_IPA_RENEW_AGENT
	if (agenturl == NULL) {
		printf(_("No agent URL (-A) given, and no default known.\n"));
		missing_args = TRUE;
	}
#endif
	if (template == NULL) {
		printf(_("No profile/template (-T) given, and no default known.\n"));
		missing_args = TRUE;
	}
	if (options != NULL) {
		if (agenturl == NULL) {
			printf(_("No agent URL (-A) given, and no default "
				 "known.\n"));
			missing_args = TRUE;
		}
		if (!can_agent) {
			printf(_("No agent credentials specified, and no "
				 "default known.\n"));
			missing_args = TRUE;
		}
	}
	if (missing_args) {
		help(argv[0]);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if (NSS_ShutdownContext(nctx) != SECSuccess) {
		printf(_("Error shutting down NSS.\n"));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}

	/* Figure out where we are in the multi-step process. */
	op = op_none;
	if ((savedstate != NULL) &&
	    ((p = statevar(savedstate, "state")) != NULL) &&
	    ((q = statevar(savedstate, "requestId")) != NULL)) {
		if (strcmp(p, "check") == 0) {
			op = op_check;
		}
		if ((strcmp(p, "review") == 0) ||
		    (strcmp(p, "approve") == 0)) {
			op = op_approve;
		}
		if ((strcmp(p, "fetch") == 0) ||
		    (strcmp(p, "retrieve") == 0)) {
			op = op_retrieve;
		}
		params = talloc_asprintf(ctx, "requestId=%s", q);
	} else {
		op = op_submit;
		params = "";
	}

	/* Figure out which form and arguments to use. */
	switch (op) {
	case op_none:
		printf(_("Internal error: unknown state.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
		break;
	case op_submit:
		url = talloc_asprintf(ctx, "%s/profileSubmit", eeurl);
		template = cm_submit_u_url_encode(template);
		if ((serial != NULL) && (strlen(serial) > 0) && !force_new) {
			/* Renew-by-serial. */
			serial = cm_submit_u_url_encode(serial);
			params = talloc_asprintf(ctx,
						 "profileId=%s&"
						 "serial_num=%s&"
						 "renewal=true&"
						 "xml=true",
						 template,
						 serial);
		} else {
			/* Fresh enrollment.  Read the CSR from the
			 * environment, or from the command-line, that we're
			 * going to submit for signing. */
			csr = getenv(CM_SUBMIT_CSR_ENV);
			if (csr == NULL) {
				csr = cm_submit_u_from_file((optind < argc) ?
							    argv[optind++] :
							    NULL);
			}
			if ((csr == NULL) || (strlen(csr) == 0)) {
				printf(_("Unable to read signing request.\n"));
				help(argv[0]);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			csr = cm_submit_u_url_encode(csr);
			params = talloc_asprintf(ctx,
						 "profileId=%s&"
						 "cert_request_type=pkcs10&"
						 "cert_request=%s&"
						 "xml=true",
						 template,
						 csr);
		}
		use_agent = FALSE;
		break;
	case op_check:
		/* Check if the certificate has been issued or rejected. */
		url = talloc_asprintf(ctx, "%s/checkRequest", eeurl);
		params = talloc_asprintf(ctx,
					 "%s&"
					 "xml=true",
					 params);
		use_agent = FALSE;
		break;
	case op_approve:
		if (agenturl == NULL) {
			printf(_("No agent URL (-A) given, and no default "
				 "known.\n"));
			help(argv[0]);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		if ((sslcert == NULL) || (strlen(sslcert) == 0)) {
			printf(_("No agent credentials (-n) given, but they "
				 "are needed.\n"));
			help(argv[0]);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		/* Reading profile defaults for this certificate, then applying
		 * them and issuing a new certificate. */
		url = talloc_asprintf(ctx, "%s/profileReview", agenturl);
		url2 = talloc_asprintf(ctx, "%s/profileProcess", agenturl);
		params = talloc_asprintf(ctx,
					 "%s&"
					 "xml=true",
					 params);
		params2 = talloc_asprintf(ctx,
					  "%s&"
					  "op=approve",
					  params);
		use_agent = TRUE;
		break;
	case op_retrieve:
		/* Retrieving the new certificate. */
		url = talloc_asprintf(ctx, "%s/displayCertFromRequest", eeurl);
		params = talloc_asprintf(ctx,
					 "%s&"
					 "importCert=true&"
					 "xml=true",
					 params);
		use_agent = FALSE;
		break;
	}

	/* Read the PIN, if we need to. */
	if ((sslpinfile != NULL) && (sslpin == NULL)) {
		sslpin = cm_submit_u_from_file(sslpinfile);
		if (sslpin != NULL) {
			sslpin = talloc_strndup(ctx, sslpin,
						strcspn(sslpin, "\r\n"));
		}
	}
	if (ssldir != NULL) {
		setenv("SSL_DIR", ssldir, 1);
	}

	/* Submit the form(s). */
	hctx = NULL;
	while (url != NULL) {
		hctx = cm_submit_h_init(ctx, "GET", url, params, NULL, NULL,
					cainfo, capath, sslcert, sslkey, sslpin,
					cm_submit_h_negotiate_off,
					cm_submit_h_delegate_off,
					use_agent ?
					cm_submit_h_clientauth_on :
					cm_submit_h_clientauth_off,
					cm_submit_h_env_modify_off,
					verbose > 1 ?
					cm_submit_h_curl_verbose_on :
					cm_submit_h_curl_verbose_off);
		lasturl = url;
		lastparams = params;
		cm_submit_h_run(hctx);
		if (verbose > 0) {
			fprintf(stderr, "%s \"%s?%s\"\n", "GET", url, params);
			fprintf(stderr, "code = %d\n", cm_submit_h_result_code(hctx));
			fprintf(stderr, "code_text = \"%s\"\n", cm_submit_h_result_code_text(hctx));
			syslog(LOG_DEBUG, "%s %s?%s\n", "GET", url, params);
		}
		results = cm_submit_h_results(hctx, NULL);
		if (verbose > 0) {
			fprintf(stderr, "results = \"%s\"\n", results);
			syslog(LOG_DEBUG, "%s", results);
		}
		if (cm_submit_h_result_code(hctx) != 0) {
			break;
		}
		/* If there's a next form, get ready to submit it. */
		switch (op) {
		case op_approve:
			/* We just reviewed the request.  Read the defaults and
			 * add them to the set of parameters for our next form
			 * submission. */
			if (results != NULL) {
				defaults = cm_submit_d_xml_defaults(ctx,
								    results);
			} else {
				defaults = NULL;
			}
			for (i = 0;
			     (defaults != NULL) && (defaults[i] != NULL);
			     i++) {
				/* Check if this default is one of the
				 * paramters we've been explicitly provided. */
				for (j = 0; j < num_options; j++) {
					if (strcmp(defaults[i]->name,
						   options[j].name) == 0) {
						break;
					}
				}
				/* If we have a non-default value for it, skip
				 * this default. */
				if (j < num_options) {
					continue;
				}
				p = cm_submit_u_url_encode(defaults[i]->name);
				q = cm_submit_u_url_encode(defaults[i]->value);
				params2 = talloc_asprintf(ctx,
							  "%s&%s=%s",
							  params2, p, q);
			};
			/* Add parameters specified on command line */
			for (j = 0; j < num_options; j++) {
				p = cm_submit_u_url_encode(options[j].name);
				q = cm_submit_u_url_encode(options[j].value);
				params2 = talloc_asprintf(ctx,
							  "%s&%s=%s",
							  params2, p, q);
			}
			break;
		case op_none:
		case op_submit:
		case op_check:
		case op_retrieve:
			/* No second form for these. */
			break;
		}
		url = url2;
		url2 = NULL;
		params = params2;
		params2 = NULL;
	}

	/* Figure out what to output. */
	if (cm_submit_h_result_code(hctx) != 0) {
		if (cm_submit_h_result_code_text(hctx) != NULL) {
			printf(_("Error %d connecting to %s: %s.\n"),
			       cm_submit_h_result_code(hctx),
			       lasturl,
			       cm_submit_h_result_code_text(hctx));
		} else {
			printf(_("Error %d connecting to %s.\n"),
			       cm_submit_h_result_code(hctx),
			       lasturl);
		}
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	if (results == NULL) {
		printf(_("Internal error: no response to \"%s?%s\".\n"),
		       lasturl, lastparams);
		return CM_SUBMIT_STATUS_REJECTED;
	}
	switch (op) {
	case op_none:
		printf(_("Internal error: unknown state.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
		break;
	case op_submit:
		ret = cm_submit_d_submit_eval(ctx, results, lasturl,
					      can_agent, &p, &q);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		return ret;
		break;
	case op_check:
		ret = cm_submit_d_check_eval(ctx, results, lasturl,
					     can_agent, &p, &q);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		return ret;
		break;
	case op_approve:
		if (url2 == NULL) {
			ret = cm_submit_d_approve_eval(ctx, results, lasturl,
						       can_agent, &p, &q);
			if (p != NULL) {
				fprintf(stdout, "%s", p);
			}
			if (q != NULL) {
				fprintf(stderr, "%s", q);
			}
			return ret;
		} else {
			ret = cm_submit_d_review_eval(ctx, results, lasturl,
						      can_agent, &p, &q);
			if (p != NULL) {
				fprintf(stdout, "%s", p);
			}
			if (q != NULL) {
				fprintf(stderr, "%s", q);
			}
			return ret;
		}
		break;
	case op_retrieve:
		ret = cm_submit_d_fetch_eval(ctx, results, lasturl,
					     can_agent, &p, &q);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		return ret;
		break;
	}
	return CM_SUBMIT_STATUS_UNCONFIGURED;
}
