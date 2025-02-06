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

#include <jansson.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include <popt.h>

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
#include "util-ipa.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

#ifdef DOGTAG_IPA_RENEW_AGENT
#include "dogtag-ipa.h"
#endif

enum op_type {
	op_none, op_submit, op_check, op_approve, op_retrieve, op_profiles
};

struct options {
	char *name;
	char *value;
};

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

static int
xml_workflow(
	void *ctx,
	poptContext pctx,
	enum op_type op,
	char *savedstate,
	const char *eeurl, const char *agenturl,
	dbus_bool_t use_agent_submission,
	const char *serial, const char *template,
	int force_new,
	struct options *aoptions, struct options *soptions,
	size_t num_aoptions, size_t num_soptions,
	const char *uid,
	const char *udn,
	const char *pwd,
	const char *pin,
	dbus_bool_t use_agent_approval,
	const char *sslcert, const char *sslkey,
	const char *sslpin, const char *sslpinfile,
	const char *ssldir, const char *cainfo, const char *capath,
	dbus_bool_t can_agent,
	int verbose
)
{
	const char *method = NULL, *method2 = NULL;
	const char *url = NULL, *url2 = NULL;
	char *p, *q, *params = NULL, *params2 = NULL;
	const char *lasturl = NULL, *lastparams = NULL;
	const char *results = NULL;
	const char *csrfile = NULL;
	struct cm_submit_h_context *hctx;
	char *csr = NULL;
	size_t j;
	int i;
	struct dogtag_default **defaults;
	enum cm_external_status ret;

	/* Figure out where we are in the multi-step process. */
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
		free(p);
		free(q);
	} else {
		params = "";
	}


	/* Figure out which form and arguments to use. */
	switch (op) {
	case op_none:
		printf(_("Internal error: unknown state.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
		break;
	case op_submit:
		method = DOGTAG_PROFILE_SUBMIT_METHOD;
		url = talloc_asprintf(ctx, "%s/%s", eeurl,
				      use_agent_submission ?
				      DOGTAG_PROFILE_SUBMIT_AGENT_RESOURCE :
				      DOGTAG_PROFILE_SUBMIT_RESOURCE);
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
			csrfile = poptGetArg(pctx);
			if (csrfile != NULL) {
				csr = cm_submit_u_from_file(csrfile);
			} else {
				csr = getenv(CM_SUBMIT_CSR_ENV);
				if (csr != NULL) {
					csr = strdup(csr);
				}
			}
			if ((csr == NULL) || (strlen(csr) == 0)) {
				if (csrfile != NULL) {
					printf(_("Unable to read signing request from file \"%s\".\n"),
					       csrfile);
				} else {
					printf(_("Unable to read signing request from environment variable \"%s\".\n"),
					       CM_SUBMIT_CSR_ENV);
				}
				poptPrintUsage(pctx, stdout, 0);
				free(csr);
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
			free(csr);
		}
		/* Check for creds specified as options. */
		for (j = 0; j < num_soptions; j++) {
			if (strcmp(soptions[j].name, "uid") == 0) {
				uid = NULL;
			}
			if (strcmp(soptions[j].name, "udn") == 0) {
				udn = NULL;
			}
			if (strcmp(soptions[j].name, "pwd") == 0) {
				pwd = NULL;
			}
			if (strcmp(soptions[j].name, "pin") == 0) {
				pin = NULL;
			}
		}
		/* Add client creds. */
		if (uid != NULL) {
			uid = cm_submit_u_url_encode(uid);
			params = talloc_asprintf(ctx, "%s&uid=%s", params, uid);
		}
		if (udn != NULL) {
			udn = cm_submit_u_url_encode(udn);
			params = talloc_asprintf(ctx, "%s&udn=%s", params, udn);
		}
		if (pwd != NULL) {
			pwd = cm_submit_u_url_encode(pwd);
			params = talloc_asprintf(ctx, "%s&pwd=%s",
						 params, pwd);
		}
		if (pin != NULL) {
			pin = cm_submit_u_url_encode(pin);
			params = talloc_asprintf(ctx, "%s&pin=%s",
						 params, pin);
		}
		/* Add parameters specified on command line */
		for (j = 0; j < num_soptions; j++) {
			p = cm_submit_u_url_encode(soptions[j].name);
			q = cm_submit_u_url_encode(soptions[j].value);
			params = talloc_asprintf(ctx,
						 "%s&%s=%s",
						 params, p, q);
			free(p);
			free(q);
		}
		use_agent_approval = FALSE;
		break;
	case op_check:
		/* Check if the certificate has been issued or rejected. */
		method = DOGTAG_CHECK_REQUEST_METHOD;
		url = talloc_asprintf(ctx, "%s/%s", eeurl, DOGTAG_CHECK_REQUEST_RESOURCE);
		params = talloc_asprintf(ctx,
					 "%s&"
					 "xml=true",
					 params);
		use_agent_approval = FALSE;
		break;
	case op_approve:
		if (agenturl == NULL) {
			printf(_("No agent URL (-A) given, and no default "
				 "known.\n"));
			poptPrintUsage(pctx, stdout, 0);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		if ((sslcert == NULL) || (strlen(sslcert) == 0)) {
			printf(_("No agent credentials (-n) given, but they "
				 "are needed.\n"));
			poptPrintUsage(pctx, stdout, 0);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		/* Reading profile defaults for this certificate, then applying
		 * them and issuing a new certificate. */
		method = DOGTAG_PROFILE_REVIEW_METHOD;
		url = talloc_asprintf(ctx, "%s/%s", agenturl, DOGTAG_PROFILE_REVIEW_RESOURCE);
		method2 = DOGTAG_PROFILE_PROCESS_METHOD;
		url2 = talloc_asprintf(ctx, "%s/%s", agenturl, DOGTAG_PROFILE_PROCESS_RESOURCE);
		params = talloc_asprintf(ctx,
					 "%s&"
					 "xml=true",
					 params);
		params2 = talloc_asprintf(ctx,
					  "%s&"
					  "op=approve",
					  params);
		use_agent_approval = TRUE;
		break;
	case op_retrieve:
		/* Retrieving the new certificate. */
		method = DOGTAG_DISPLAY_CERT_METHOD;
		url = talloc_asprintf(ctx, "%s/%s", eeurl, DOGTAG_DISPLAY_CERT_RESOURCE);
		params = talloc_asprintf(ctx,
					 "%s&"
					 "importCert=true&"
					 "xml=true",
					 params);
		use_agent_approval = FALSE;
		break;
	case op_profiles:
		/* Retrieving the list of profiles. */
		method = DOGTAG_PROFILE_LIST_METHOD;
		url = talloc_asprintf(ctx, "%s/%s", eeurl, DOGTAG_PROFILE_LIST_RESOURCE);
		if (strlen(params) > 0) {
			params = talloc_asprintf(ctx,
						 "%s&"
						 "xml=true",
						 params);
		} else {
			params = "xml=true";
		}
		use_agent_approval = FALSE;
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
		hctx = cm_submit_h_init(ctx, method, url, params, NULL, NULL, NULL,
					cainfo, capath, sslcert, sslkey, sslpin,
					cm_submit_h_negotiate_off,
					cm_submit_h_delegate_off,
					use_agent_approval || use_agent_submission ?
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
			fprintf(stderr, "%s \"%s?%s\"\n", method, url, params);
			fprintf(stderr, "code = %d\n", cm_submit_h_result_code(hctx));
			fprintf(stderr, "code_text = \"%s\"\n", cm_submit_h_result_code_text(hctx));
			syslog(LOG_DEBUG, "%s %s?%s\n", method, url, params);
		}
		results = cm_submit_h_results(hctx, NULL);
		if (verbose > 0) {
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
				 * parameters we've been explicitly provided. */
				for (j = 0; j < num_aoptions; j++) {
					if (strcmp(defaults[i]->name,
						   aoptions[j].name) == 0) {
						break;
					}
				}
				/* If we have a non-default value for it, skip
				 * this default. */
				if (j < num_aoptions) {
					continue;
				}
				p = cm_submit_u_url_encode(defaults[i]->name);
				q = cm_submit_u_url_encode(defaults[i]->value);
				if (verbose > 0) {
					fprintf(stderr, "setting \"%s\" to "
						"default value \"%s\"\n",
						p, q);
				}
				params2 = talloc_asprintf(ctx,
							  "%s&%s=%s",
							  params2, p, q);
			};
			/* Add parameters specified on command line */
			for (j = 0; j < num_aoptions; j++) {
				p = cm_submit_u_url_encode(aoptions[j].name);
				q = cm_submit_u_url_encode(aoptions[j].value);
				params2 = talloc_asprintf(ctx,
							  "%s&%s=%s",
							  params2, p, q);
				if (verbose > 0) {
					fprintf(stderr, "setting \"%s\" to "
						"specified value \"%s\"\n",
						p, q);
				}
			}
			break;
		case op_none:
		case op_submit:
		case op_check:
		case op_retrieve:
		case op_profiles:
			/* No second form for these. */
			break;
		}
		url = url2;
		url2 = NULL;
		params = params2;
		params2 = NULL;
		method = method2;
		method2 = NULL;
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
					      can_agent, &p, &q, 1);
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
					     can_agent, &p, &q, 0);
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
						       &p, &q, 1);
			if (p != NULL) {
				fprintf(stdout, "%s", p);
			}
			if (q != NULL) {
				fprintf(stderr, "%s", q);
			}
			return ret;
		} else {
			ret = cm_submit_d_review_eval(ctx, results, lasturl,
						      &p, &q);
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
					     &p, &q, 1);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		return ret;
		break;
	case op_profiles:
		ret = cm_submit_d_profiles_eval(ctx, results,
						&p, &q, 1);
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

static int
ipa_workflow(
	void *ctx,
	poptContext pctx,
	enum op_type op,
	char *savedstate,
	const char *url,
	const char *host,
	const char *template,
	 __attribute__ ((unused)) struct options *aoptions,
	 __attribute__ ((unused)) size_t num_aoptions,
	const char *uid,
	const char *udn,
	const char *pwd,
	const char *pin,
	const char *cainfo, const char *capath,
	dbus_bool_t can_agent,
	int verbose
)
{
	struct cm_submit_h_context *hctx;
	char *p, *q;
	const char *csrfile = NULL;
	char *csr = NULL;
	char *request_id = NULL;
	json_t *json_req = NULL;
	json_error_t j_error;
	char *json_str = NULL;
	char *referer = NULL;
	const char *results = NULL;
	json_t *j_root = NULL;
	json_t *j_result_outer = NULL;
	json_t *j_result = NULL; 
	int i;
	int rval = CM_SUBMIT_STATUS_UNCONFIGURED;
	char *error_message = NULL;
	const char *reqprinc = NULL;

	reqprinc = talloc_asprintf(ctx, "host/%s", host);

	/* Figure out where we are in the multi-step process. */
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
		request_id = talloc_strdup(ctx, q);
		free(p);
		free(q);
	}

	/* Figure out which form and arguments to use. */
	switch (op) {
	case op_none:
		printf(_("Internal error: unknown state.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
		break;
	case op_submit:
		/* FIXME: need PKI to add support for submit options */

		/* Fresh enrollment.  Read the CSR from the
		 * environment, or from the command-line, that we're
		 * going to submit for signing. */
		csrfile = poptGetArg(pctx);
		if (csrfile != NULL) {
			csr = cm_submit_u_from_file(csrfile);
		} else {
			csr = getenv(CM_SUBMIT_CSR_ENV);
			if (csr != NULL) {
				csr = strdup(csr);
			}
		}
		if ((csr == NULL) || (strlen(csr) == 0)) {
			if (csrfile != NULL) {
				printf(_("Unable to read signing request from file \"%s\".\n"),
				       csrfile);
			} else {
				printf(_("Unable to read signing request from environment variable \"%s\".\n"),
				       CM_SUBMIT_CSR_ENV);
			}
			poptPrintUsage(pctx, stdout, 0);
			free(csr);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		/* Change the CSR from the format we get it in to the one the
		 * server expects.  IPA just wants base64-encoded binary data,
		 * no whitepace. */
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

		/* The soptions are not supported by the IPA API */
		if ((uid != NULL) || (udn != NULL) || (pwd != NULL) || (pin != NULL)) {
			printf(_(
				"Specifying uid, udn, pwd and pin are not supported with -J\n")
			);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}

		json_req = json_pack_ex(&j_error, 0,
								"{s:s, s:[[s], {s:s, s:s}]}",
								"method", "cert_request",
								"params",
								csr,
								"principal", reqprinc,
								"profile_id", template);
		break;
	case op_check:
		/* Check if the certificate has been issued or rejected. */
		json_req = json_pack_ex(&j_error, 0,
								"{s:s, s:[[s],{}]}",
								"method", "cert_status",
								"params",
								request_id);
		break;
	case op_approve:
		/* FIXME: need PKI to add support for approval options
		 * Then we need to grab the original profile and do replacements.
		 * This probably needs to happen within IPA which means we'd need
		 * a mechanism to pass the options in.
		 *
		 * HINT: See cm_submit_d_xml_defaults. This might have to
		 */
		json_req = json_pack_ex(&j_error, 0,
								"{s:s, s:[[s],{}]}",
								"method", "cert_approve",
								"params",
								request_id);
		break;
	case op_retrieve:
		/* Retrieving the new certificate. */
		json_req = json_pack_ex(&j_error, 0,
								"{s:s, s:[[s],{}]}",
								"method", "cert_show",
								"params",
								request_id);
		break;
	case op_profiles:
		json_req = json_pack_ex(&j_error, 0,
								"{s:s, s:[[],{s:s}]}",
								"method", "certprofile_find",
								"params",
								"all", "True");
		break;
	}
	free(csr);

	referer = talloc_asprintf(ctx, "%s", url);

	/* Generate the request */
	if (!json_req) {
		cm_log(0, "%d json_pack_ex() failed: %s\n", op, j_error.text);
		fprintf(stderr, "%d json_pack_ex() failed: %s\n", op, j_error.text);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	json_str = json_dumps(json_req, 0);

	if (verbose) {
		fprintf(stderr, "Submitting request %s\n", json_str);
	}
	/* Submit the request */
	hctx = cm_submit_h_init(ctx, "POST", url, json_str,
			"application/json", "application/json", referer,
			cainfo, capath,
			NULL, NULL, NULL,
			cm_submit_h_negotiate_on,
			cm_submit_h_delegate_off,
			cm_submit_h_clientauth_off,
			cm_submit_h_env_modify_off,
			verbose > 1 ?
			cm_submit_h_curl_verbose_on :
			cm_submit_h_curl_verbose_off);

	if (hctx == NULL) {
		fprintf(stderr, "Error setting up JSON-RPC to %s on "
		"the client.\n", url);
		printf(_("Error setting up for JSON-RPC on the client.\n"));
		rval = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto cleanup;
	}

	cm_submit_h_run(hctx);
	if (verbose > 0) {
		fprintf(stderr, "code = %d\n", cm_submit_h_result_code(hctx));
		fprintf(stderr, "code_text = \"%s\"\n", cm_submit_h_result_code_text(hctx));    
		syslog(LOG_DEBUG, "%s\n", json_str);
	}

	free(json_str);
	if (json_req)
		json_decref(json_req);

	results = cm_submit_h_results(hctx, NULL);
	if (verbose > 0) {
		syslog(LOG_DEBUG, "%s", results);
	}
	if (cm_submit_h_response_code(hctx) != 200) {
		cm_log(0, "JSON-RPC call failed with HTTP status code: %d\n",
				  cm_submit_h_response_code(hctx));
		cm_log(0, "code = %d, code_text = \"%s\"\n",
			cm_submit_h_result_code(hctx), cm_submit_h_result_code_text(hctx));
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto cleanup;
	}
    i = parse_json_result(results, &error_message);
	if (i < 0) {
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto cleanup;
	}
	if (i > 0) {
		/* Interpret the error. See IPA errors.py to get the
		 * classifications */
		switch (i / 1000) {
		case 2: /* authorization error - permanent */
		case 3: /* invocation error - permanent */
			printf("Server at %s denied our request, "
				   "giving up: %d (%s).\n", url, i,
				   error_message);
			rval = CM_SUBMIT_STATUS_REJECTED;
			goto cleanup;
			break;
		case 1: /* authentication error - transient? */
		case 4: /* execution error - transient? */
		case 5: /* generic error - transient? */
		default:
			printf("Server at %s failed request, "
				   "will retry: %d (%s).\n", url, i,
				   error_message);
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			goto cleanup;
			break;
		}
	}

	j_root = json_loads(results, 0, &j_error);
	if (!j_root) {
		cm_log(0, "Parsing JSON-RPC response failed: %s\n", j_error.text);
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto cleanup;
	}
	j_result_outer = json_object_get(j_root, "result");
	if (!j_result_outer) {
		cm_log(0, "Parsing JSON-RPC response failed, no outer result\n");
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto cleanup;
	}

	j_result = json_object_get(j_result_outer, "result");
		if (!j_result) {
	    cm_log(0, "Parsing JSON-RPC response failed, no inner result\n");
	    rval = CM_SUBMIT_STATUS_UNREACHABLE;
	    goto cleanup;
	}

	switch (op) {
	case op_submit:
		rval = cm_submit_d_submit_eval(ctx, results, NULL,
					      can_agent, &p, &q, 0);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		break;
	case op_check:
		rval = cm_submit_d_check_eval(ctx, results, NULL,
					 			      can_agent, &p, &q, 0);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		break;
	case op_retrieve:
		rval = cm_submit_d_fetch_eval(ctx, results, NULL,
					     &p, &q, 0);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		break;
	case op_approve:
		rval = cm_submit_d_approve_eval(ctx, results, NULL,
				 		         		&p, &q, 0);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		break;
	case op_profiles:
		rval = cm_submit_d_profiles_eval(ctx, results,
										 &p, &q, 0);

		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		break; 
	default:
		break;
	}

cleanup:
	cm_submit_h_cleanup(hctx);

	return rval;
}

int
main(int argc, const char **argv)
{
	const char *eeurl = NULL, *agenturl = NULL;
	const char *jsonrpc_url = NULL;
	const char *ssldir = NULL, *cainfo = NULL, *capath = NULL;
	const char *sslcert = NULL, *sslkey = NULL;
	const char *sslpin = NULL, *sslpinfile = NULL;
	const char *serial = NULL, *template = NULL;
	const char *uid = NULL, *pwd = NULL, *pwdfile = NULL;
	const char *udn = NULL, *pin = NULL, *pinfile = NULL;
	char *savedstate = NULL;
	char *poptarg;
	struct options *aoptions = NULL, *soptions = NULL;
	size_t num_aoptions = 0, num_soptions = 0;
	int c, verbose = 0, force_new = 0, force_renew = 0, i;
	const char *host = NULL;
#ifdef DOGTAG_IPA_RENEW_AGENT
	const char *dogtag_version = NULL;
	int eeport, agentport;
#endif
	enum op_type op = op_submit;
	dbus_bool_t can_agent, use_agent_approval = FALSE, missing_args = FALSE;
	dbus_bool_t use_agent_submission = FALSE;
	NSSInitContext *nctx;
	char *p, *tmp;
	const char *es;
	void *ctx;
	const char *mode = CM_OP_SUBMIT;
	poptContext pctx;
	int rval;

	const struct poptOption popts[] = {
		{"ee-url", 'E', POPT_ARG_STRING, &eeurl, 0, "end-entity services location", "URL"},
		{"agent-url", 'A', POPT_ARG_STRING, &agenturl, 0, "agent services location", "URL"},
		{"jsonrpc-url", 'J', POPT_ARG_STRING, &jsonrpc_url, 'J', "IPA JSON-RPC service location", "URL"},
		{"cafile", 'i', POPT_ARG_STRING, &cainfo, 0, NULL, "FILENAME"},
		{"capath", 'C', POPT_ARG_STRING, &capath, 0, NULL, "DIRECTORY"},
		{"dbdir", 'd', POPT_ARG_STRING, &ssldir, 0, "database containing agent or client creds", "DIRECTORY"},
		{"nickname", 'n', POPT_ARG_STRING, &sslcert, 0, "nickname of agent or client creds", "NAME"},
		{"certfile", 'c', POPT_ARG_STRING, &sslcert, 0, "agent or client certificate", "FILENAME"},
		{"keyfile", 'k', POPT_ARG_STRING, &sslkey, 0, "agent or client key", "FILENAME"},
		{"sslpinfile", 'p', POPT_ARG_STRING, &sslpinfile, 0, "agent or client key pinfile", "FILENAME"},
		{"sslpin", 'P', POPT_ARG_STRING, &sslpin, 0, "agent or client key pin", NULL},
		{"hex-serial", 's', POPT_ARG_STRING, NULL, 's', "request renewal for certificate by serial number (hexadecimal)", "NUMBER"},
		{"serial", 'D', POPT_ARG_STRING, &serial, 'D', "request renewal for certificate by serial number", "NUMBER"},
		{"submit-option", 'o', POPT_ARG_STRING, NULL, 'o', "key-value pair to send to server", NULL},
		{"approval-option", 'O', POPT_ARG_STRING, NULL, 'O', "key-value pair to set in certificate", NULL},
		{"profile", 'T', POPT_ARG_STRING, &template, 0, "enrollment profile", "NAME"},
		{"profile-list", 't', POPT_ARG_NONE, NULL, 't', "list enrollment profiles", NULL},
		{"state", 'S', POPT_ARG_STRING, &savedstate, 0, "previously-provided state data", "STATE-VALUE"},
#ifdef DOGTAG_IPA_RENEW_AGENT
		{"dogtag-version", 'V', POPT_ARG_STRING, &dogtag_version, 'V', NULL, "NUMBER"},
#endif
		{"force-new", 'N', POPT_ARG_NONE, NULL, 'N', "prefer to obtain a new certificate", NULL},
		{"force-renew", 'R', POPT_ARG_NONE, NULL, 'R', "prefer to renew a certificate", NULL},
		{"agent-submit", 'a', POPT_ARG_NONE, NULL, 'a', "submit enrollment or renewal request using agent or client creds", NULL},
		{"uid", 'u', POPT_ARG_STRING, &uid, 0, "submit enrollment or renewal request using user name", "USERNAME"},
		{"udn", 'U', POPT_ARG_STRING, &udn, 0, "submit enrollment or renewal request using user DN", "USERDN"},
		{"userpwd", 'W', POPT_ARG_STRING, &pwd, 0, "submit password with enrollment or renewal request", NULL},
		{"userpwdfile", 'w', POPT_ARG_STRING, &pwdfile, 0, "submit password from file with enrollment or renewal request", "FILENAME"},
		{"userpin", 'Y', POPT_ARG_STRING, &pin, 0, "submit pin with enrollment or renewal request", NULL},
		{"userpinfile", 'y', POPT_ARG_STRING, &pinfile, 0, "submit pin from file with enrollment or renewal request", "FILENAME"},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	if (getenv(CM_SUBMIT_OPERATION_ENV) != NULL) {
		mode = getenv(CM_SUBMIT_OPERATION_ENV);
	}
	if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
	    (strcasecmp(mode, CM_OP_POLL) == 0)) {
		/* fall through */
	} else
	if (strcasecmp(mode, CM_OP_FETCH_PROFILES) == 0) {
		op = op_profiles;
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

	pctx = poptGetContext(argv[0], argc, argv, popts, 0);
	if (pctx == NULL) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	poptSetOtherOptionHelp(pctx, "[options] -E EE-URL -A AGENT-URL [csrfile]");
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 's':
			serial = util_dec_from_hex(poptGetOptArg(pctx));
			break;
		case 'O':
			poptarg = poptGetOptArg(pctx);
			if (strchr(poptarg, '=') == NULL) {
				printf(_("Profile params (-O) must be in the form of param=value.\n"));
				poptPrintUsage(pctx, stdout, 0);
				free(soptions);
				free(aoptions);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			aoptions = realloc(aoptions,
					   ++num_aoptions * sizeof(*aoptions));
			if (aoptions == NULL) {
				printf(_("Out of memory.\n"));
				free(soptions);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			p = strdup(poptarg);
			if (p == NULL) {
				printf(_("Out of memory.\n"));
				free(aoptions);
				free(soptions);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			i = strcspn(p, "=");
			aoptions[num_aoptions - 1].name = p;
			p[i] = '\0';
			aoptions[num_aoptions - 1].value = p + i + 1;
			break;
		case 'o':
			poptarg = poptGetOptArg(pctx);
			if (strchr(poptarg, '=') == NULL) {
				printf(_("Submit params (-o) must be in the form of param=value.\n"));
				poptPrintUsage(pctx, stdout, 0);
				free(soptions);
				free(aoptions);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			soptions = realloc(soptions,
					   ++num_soptions * sizeof(*soptions));
			if (soptions == NULL) {
				printf(_("Out of memory.\n"));
				free(aoptions);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			p = strdup(poptarg);
			if (p == NULL) {
				printf(_("Out of memory.\n"));
				free(soptions);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			i = strcspn(p, "=");
			soptions[num_soptions - 1].name = p;
			p[i] = '\0';
			soptions[num_soptions - 1].value = p + i + 1;
			break;
		case 't':
			op = op_profiles;
			break;
		case 'v':
			verbose++;
			break;
#ifdef DOGTAG_IPA_RENEW_AGENT
		case 'V':
			dogtag_version = poptGetOptArg(pctx);
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
		case 'a':
			use_agent_submission = TRUE;
			break;
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		free(soptions);
		free(aoptions);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	umask(S_IRWXG | S_IRWXO);
	if (isatty(STDERR_FILENO))
		cm_log_set_method(cm_log_stderr);
	else
		cm_log_set_method(cm_log_syslog);
	cm_log_set_level(verbose);

	nctx = NSS_InitContext(CM_DEFAULT_CERT_STORAGE_LOCATION,
			       NULL, NULL, NULL, NULL,
			       NSS_INIT_NOCERTDB |
			       NSS_INIT_READONLY |
			       NSS_INIT_NOROOTINIT);
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
	if (host == NULL) {
		printf(_("Host must be set in /etc/ipa/default.conf.\n"));
		missing_args = TRUE;
	}
	if (jsonrpc_url == NULL) {
		if ((dogtag_version != NULL) && (atof(dogtag_version) >= 10)) {
			eeport = 8080;
			agentport = 8443;
		} else {
			eeport = 9180;
			agentport = 9443;
		}
		if ((eeurl == NULL) && (jsonrpc_url == NULL)) {
			cm_log(0, "jsonrpc_url is NULL\n");
			eeurl = cm_prefs_dogtag_ee_url();
			if ((eeurl == NULL) && (host != NULL)) {
				eeurl = talloc_asprintf(ctx,
							"http://%s:%d/ca/ee/ca",
							host, eeport);
			}
		}
		if ((agenturl == NULL) && (jsonrpc_url == NULL)) {
			cm_log(0, "jsonrpc_url is NULL\n");
			agenturl = cm_prefs_dogtag_agent_url();
			if ((agenturl == NULL) && (host != NULL)) {
				agenturl = talloc_asprintf(ctx,
							   "https://%s:%d/ca/agent/ca",
							   host, agentport);
			}
		}
	}
#else
	char tmphostname[255];
	int r;

	r = gethostname(tmphostname, 255 - 1);
	if (r != 0) {
		printf(_("gethostname() failed.\n"));
		missing_args = TRUE;
	}
	host = talloc_strdup(ctx, tmphostname);
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
	if (!force_new && serial && jsonrpc_url) {
		printf(_("Renew-by-serial is not supported over JSON-RPC.\n"));
		missing_args = TRUE;
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
	    (capath == NULL)) {
		cainfo = "/etc/ipa/ca.crt";
	}

	if ((((ssldir == NULL) &&
	   (sslcert == NULL)) ||
	   ((sslkey == NULL) &&
	   (sslcert == NULL)))) {
		printf(_("NSS database and nickname or certfile and keyfile "
			 "must be provided.\n"));
		missing_args = TRUE;
	}
#endif
	if ((sslcert != NULL) && (strlen(sslcert) > 0)) {
		can_agent = TRUE;
	} else {
		can_agent = FALSE;
	}
	if (use_agent_approval && !can_agent) {
		printf(_("No agent credentials specified, and no "
			 "default known.\n"));
		missing_args = TRUE;
	}
	if (use_agent_submission && !can_agent) {
		printf(_("No agent credentials specified, and no "
			 "default known.\n"));
		missing_args = TRUE;
	}
	if (force_renew && (serial == NULL)) {
		printf(_("Requested renewal, but no serial number provided.\n"));
		missing_args = TRUE;
	}
	if ((eeurl == NULL) && (jsonrpc_url == NULL)) {
		printf(_("No end-entity URL (-E) given, and no default known.\n"));
		missing_args = TRUE;
	}
#ifdef DOGTAG_IPA_RENEW_AGENT
	if (agenturl == NULL && jsonrpc_url == NULL) {
		printf(_("No agent URL (-A) given, and no default known.\n"));
		missing_args = TRUE;
	}
#endif
	if (template == NULL) {
		printf(_("No profile/template (-T) given, and no default known.\n"));
		missing_args = TRUE;
	}
	if ((aoptions != NULL) && (jsonrpc_url == NULL)) {
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
		poptPrintUsage(pctx, stdout, 0);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if (NSS_ShutdownContext(nctx) != SECSuccess) {
		printf(_("Error shutting down NSS.\n"));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}

	/* Read the client password and/or PIN, if we need to. */
	if ((pwdfile != NULL) && (pwd == NULL)) {
		pwd = cm_submit_u_from_file(pwdfile);
        if (pwd != NULL) {
            pwd = talloc_strndup(ctx, pwd,
                        strcspn(pwd, "\r\n"));
		}
	}
	if ((pinfile != NULL) && (pin == NULL)) {
		pin = cm_submit_u_from_file(pinfile);
        if (pin != NULL) {
            pin = talloc_strndup(ctx, pin,
                        strcspn(pin, "\r\n"));
		}
	}
    if (eeurl || agenturl) {
		rval = xml_workflow(ctx, pctx, op, savedstate, eeurl, agenturl,
					 use_agent_submission, serial,
					 template, force_new,
					 aoptions, soptions, num_aoptions, num_soptions,
					 uid, udn, pwd, pin, use_agent_approval,
					 sslcert, sslkey, sslpin, sslpinfile, ssldir,
					 cainfo, capath, can_agent, verbose
		);
	} else if (jsonrpc_url) {
		rval = ipa_workflow(ctx, pctx, op, savedstate, jsonrpc_url,
					 host,
					 template,
					 aoptions, num_aoptions,
					 uid, udn, pwd, pin,
					 cainfo, capath, can_agent, verbose
		);
	} else {
		printf(_("None of eeurl, agenturl or jsonrpc_url are set.\n"));
		rval = CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	poptFreeContext(pctx);
	talloc_free(ctx);

	fprintf(stderr, "Returning %d\n", rval);
	return rval;
}
