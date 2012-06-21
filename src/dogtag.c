/*
 * Copyright (C) 2009,2010,2011,2012 Red Hat, Inc.
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

#include <krb5.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include "submit-d.h"
#include "submit-e.h"
#include "submit-h.h"
#include "submit-u.h"
#include "util.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

#define IPACONFIG "/etc/ipa/default.conf"
#define IPASECTION "dogtag"

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
		"\t[-S state]\n"
		"\t[-T profile]\n"
		"\t[csrfile]\n",
		strchr(cmd, '/') ?  strrchr(cmd, '/') + 1 : cmd);
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
			len = strcspn(p, "&");
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

int
main(int argc, char **argv)
{
	const char *eeurl = NULL, *agenturl = NULL, *url = NULL, *url2 = NULL;
	const char *ssldir = NULL, *cainfo = NULL, *capath = NULL;
	const char *sslcert = NULL, *sslkey = NULL;
	const char *sslpin = NULL, *sslpinfile = NULL;
	const char *csr = NULL, *serial = NULL, *template = NULL;
	char *ipaconfig = NULL, *savedstate = NULL;
	char *p, *q, *params = NULL, *params2 = NULL;
	const char *results = NULL;
	struct cm_submit_h_context *hctx;
	void *ctx;
	int c, verbose = 0, i;
	enum { op_none, op_submit, op_approve, op_retrieve } op = op_none;
	dbus_bool_t agent, error = FALSE;
	struct dogtag_default **defaults;

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif
	savedstate = getenv(CM_SUBMIT_COOKIE_ENV);

	while ((c = getopt(argc, argv, "E:A:d:n:i:C:c:k:p:P:s:S:T:v")) != -1) {
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
		case 's':
			serial = optarg;
			break;
		case 'S':
			savedstate = optarg;
			break;
		case 'T':
			template = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			help(argv[0]);
			return CM_STATUS_UNCONFIGURED;
			break;
		}
	}

	ipaconfig = read_config_file(IPACONFIG);
	if (ipaconfig == NULL) {
		printf(_("Unable to read configuration file \"%s\".\n"),
		       IPACONFIG);
	} else {
		if (eeurl == NULL) {
			eeurl = get_config_entry(ipaconfig, IPASECTION,
						 "default_ee_url");
			if (eeurl == NULL) {
				eeurl = "https://%s:9180/ca/ee/ca";
			}
		}
		if (agenturl == NULL) {
			agenturl = get_config_entry(ipaconfig, IPASECTION,
						    "default_agent_url");
			if (agenturl == NULL) {
				agenturl = "https://%s:9443/ca/agent/ca";
			}
		}
		if (template == NULL) {
			template = get_config_entry(ipaconfig, IPASECTION,
						    "default_profile");
			if (template == NULL) {
				template = "caServerCert";
			}
		}
		if (cainfo == NULL) {
			cainfo = get_config_entry(ipaconfig, IPASECTION,
						  "default_cainfo");
			if (cainfo == NULL) {
				cainfo = "/etc/ipa/ca.crt";
			}
		}
		if (ssldir == NULL) {
			ssldir = get_config_entry(ipaconfig, IPASECTION,
						  "default_agent_dir");
			if (ssldir == NULL) {
				ssldir = "/etc/httpd/alias";
			}
		}
		if (sslcert == NULL) {
			sslcert = get_config_entry(ipaconfig, IPASECTION,
						   "default_agent_nickname");
			if (sslcert == NULL) {
				sslcert = "ipa-ca-agent";
			}
		}
		if ((sslpinfile == NULL) && (sslpin == NULL)) {
			sslpinfile = get_config_entry(ipaconfig, IPASECTION,
						      "default_agent_pinfile");
			if (sslpinfile == NULL) {
				sslpinfile = "/etc/httpd/alias/pwdfile.txt";
			}
		}
	}

	if (eeurl == NULL) {
		printf(_("No end-entity URL (-E) given.\n"));
		error = TRUE;
	}
	if (agenturl == NULL) {
		printf(_("No agent URL (-A) given.\n"));
		error = TRUE;
	}
	if (template == NULL) {
		printf(_("No profile/template (-T) given.\n"));
		error = TRUE;
	}
	if (error) {
		help(argv[0]);
		return CM_STATUS_UNCONFIGURED;
	}

	if (serial == NULL) {
		/* Read the CSR from the environment, or from the command-line,
		 * that we're going to submit for signing. */
		csr = getenv(CM_SUBMIT_CSR_ENV);
		if (csr == NULL) {
			csr = cm_submit_u_from_file((optind < argc) ?
						    argv[optind++] : NULL);
		}
		if ((csr == NULL) || (strlen(csr) == 0)) {
			printf(_("Unable to read signing request.\n"));
			help(argv[0]);
			return CM_STATUS_UNCONFIGURED;
		}
	} else {
		/* We're renewing using a serial number, so no CSR. */
		csr = NULL;
	}

	ctx = talloc_new(NULL);

	/* Figure out where we are in the multi-step process. */
	op = op_none;
	if (savedstate != NULL) {
		p = statevar(savedstate, "state");
		if (strcmp(p, "approve") == 0) {
			op = op_approve;
		}
		if (strcmp(p, "retrieve") == 0) {
			op = op_retrieve;
		}
		p = statevar(savedstate, "requestId");
		params = talloc_asprintf(ctx, "requestId=%s", p);
	} else {
		op = op_submit;
		params = "";
	}

	/* Figure out which form and arguments to use. */
	switch (op) {
	case op_none:
		printf(_("Internal error: unknown state.\n"));
		return CM_STATUS_UNCONFIGURED;
		break;
	case op_submit:
		url = talloc_asprintf(ctx, "%s/profileSubmit", eeurl);
		template = cm_submit_u_url_encode(template);
		if (serial != NULL) {
			serial = cm_submit_u_url_encode(serial);
			params = talloc_asprintf(ctx,
						 "profileId=%s&"
						 "serial_num=%s&"
						 "renewal=true&"
						 "xml=true",
						 template,
						 serial);
		} else {
			csr = cm_submit_u_url_encode(csr);
			params = talloc_asprintf(ctx,
						 "profileId=%s&"
						 "cert_request_type=pkcs10&"
						 "cert_request=%s&"
						 "xml=true",
						 template,
						 csr);
		}
		agent = FALSE;
		break;
	case op_approve:
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
		agent = TRUE;
		break;
	case op_retrieve:
		url = talloc_asprintf(ctx, "%s/displayCertFromRequest", eeurl);
		params = talloc_asprintf(ctx,
					 "%s&"
					 "importCert=true&"
					 "xml=true",
					 params);
		agent = FALSE;
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
	while (url != NULL) {
		hctx = cm_submit_h_init(ctx, "GET", url, params,
					cainfo, capath, sslcert, sslkey, sslpin,
					cm_submit_h_negotiate_off,
					cm_submit_h_delegate_off,
					agent ?
					cm_submit_h_clientauth_on :
					cm_submit_h_clientauth_off,
					cm_submit_h_env_modify_off,
					verbose > 2 ?
					cm_submit_h_curl_verbose_on :
					cm_submit_h_curl_verbose_off);
		cm_submit_h_run(hctx);
		printf("%s %s?%s\n", "GET", url, params);
		printf("code = %d\n", cm_submit_h_result_code(hctx));
		printf("code_text = %s\n", cm_submit_h_result_code_text(hctx));
		results = cm_submit_h_results(hctx);
		printf("results = %s\n", results);
		/* If there's a next form, get ready to submit it. */
		switch (op) {
		case op_approve:
			/* We just reviewed the request.  Read the defaults and
			 * add them to the next set of parameters. */
			if (results != NULL) {
				defaults = cm_submit_d_xml_defaults(ctx,
								    results);
			} else {
				defaults = NULL;
			}
			for (i = 0;
			     (defaults != NULL) && (defaults[i] != NULL);
			     i++) {
				p = cm_submit_u_url_encode(defaults[i]->name);
				q = cm_submit_u_url_encode(defaults[i]->value);
				params2 = talloc_asprintf(ctx,
							  "%s&%s=%s",
							  params2, p, q);
			};
			break;
		case op_none:
		case op_submit:
		case op_retrieve:
			/* No second step for these. */
			break;
		}
		url = url2;
		url2 = NULL;
		params = params2;
		params2 = NULL;
	}

	/* Figure out what to output. */
	switch (op) {
	case op_none:
		printf(_("Internal error: unknown state.\n"));
		return CM_STATUS_UNCONFIGURED;
		break;
	case op_submit:
		break;
	case op_approve:
		break;
	case op_retrieve:
		break;
	}
	return 0;
}
