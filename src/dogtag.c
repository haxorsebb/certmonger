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

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

#ifdef DOGTAG_IPA_RENEW_AGENT
#include "dogtag-ipa.h"
#endif

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
main(int argc, const char **argv)
{
	const char *eeurl = NULL, *agenturl = NULL, *url = NULL, *url2 = NULL;
	const char *ssldir = NULL, *cainfo = NULL, *capath = NULL;
	const char *sslcert = NULL, *sslkey = NULL;
	const char *sslpin = NULL, *sslpinfile = NULL;
	const char *csr = NULL, *serial = NULL, *template = NULL;
	const char *uid = NULL, *pwd = NULL, *pwdfile = NULL;
	const char *udn = NULL, *pin = NULL, *pinfile = NULL;
	char *poptarg;
	struct {
		char *name;
		char *value;
	} *aoptions = NULL, *soptions = NULL;
	size_t num_aoptions = 0, num_soptions = 0, j;
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
	enum { op_none, op_submit, op_check, op_approve, op_retrieve, op_profiles } op = op_submit;
	dbus_bool_t can_agent, use_agent_approval = FALSE, missing_args = FALSE;
	dbus_bool_t use_agent_submission = FALSE;
	struct dogtag_default **defaults;
	enum cm_external_status ret;
	NSSInitContext *nctx;
	const char *es;
	const char *mode = CM_OP_SUBMIT, *csrfile;
	poptContext pctx;
	const struct poptOption popts[] = {
		{"ee-url", 'E', POPT_ARG_STRING, &eeurl, 0, "end-entity services location", "URL"},
		{"agent-url", 'A', POPT_ARG_STRING, &agenturl, 0, "agent services location", "URL"},
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
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			aoptions = realloc(aoptions,
					   ++num_aoptions * sizeof(*aoptions));
			if (aoptions == NULL) {
				printf(_("Out of memory.\n"));
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			p = strdup(poptarg);
			if (p == NULL) {
				printf(_("Out of memory.\n"));
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
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			soptions = realloc(soptions,
					   ++num_soptions * sizeof(*soptions));
			if (soptions == NULL) {
				printf(_("Out of memory.\n"));
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			p = strdup(poptarg);
			if (p == NULL) {
				printf(_("Out of memory.\n"));
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
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	umask(S_IRWXG | S_IRWXO);
	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(verbose);

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
	if (aoptions != NULL) {
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
	} else {
		params = "";
	}

	/* Read the client password and/or PIN, if we need to. */
	if ((pwdfile != NULL) && (pwd == NULL)) {
		pwd = cm_submit_u_from_file(pwdfile);
	}
	if ((pinfile != NULL) && (pin == NULL)) {
		pin = cm_submit_u_from_file(pinfile);
	}

	/* Figure out which form and arguments to use. */
	switch (op) {
	case op_none:
		printf(_("Internal error: unknown state.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
		break;
	case op_submit:
		url = talloc_asprintf(ctx, "%s/%s", eeurl,
				      use_agent_submission ?
				      "profileSubmitSSLClient" :
				      "profileSubmit");
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
				printf(_("Unable to read signing request.\n"));
				poptPrintUsage(pctx, stdout, 0);
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
		}
		use_agent_approval = FALSE;
		break;
	case op_check:
		/* Check if the certificate has been issued or rejected. */
		url = talloc_asprintf(ctx, "%s/checkRequest", eeurl);
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
		use_agent_approval = TRUE;
		break;
	case op_retrieve:
		/* Retrieving the new certificate. */
		url = talloc_asprintf(ctx, "%s/displayCertFromRequest", eeurl);
		params = talloc_asprintf(ctx,
					 "%s&"
					 "importCert=true&"
					 "xml=true",
					 params);
		use_agent_approval = FALSE;
		break;
	case op_profiles:
		/* Retrieving the list of profiles. */
		url = talloc_asprintf(ctx, "%s/profileList", eeurl);
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
		hctx = cm_submit_h_init(ctx, "GET", url, params, NULL, NULL,
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
		talloc_free(ctx);
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	if (results == NULL) {
		printf(_("Internal error: no response to \"%s?%s\".\n"),
		       lasturl, lastparams);
		talloc_free(ctx);
		return CM_SUBMIT_STATUS_REJECTED;
	}
	switch (op) {
	case op_none:
		printf(_("Internal error: unknown state.\n"));
		talloc_free(ctx);
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
		talloc_free(ctx);
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
		talloc_free(ctx);
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
			talloc_free(ctx);
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
			talloc_free(ctx);
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
		talloc_free(ctx);
		return ret;
		break;
	case op_profiles:
		ret = cm_submit_d_profiles_eval(ctx, results, lasturl,
						can_agent, &p, &q);
		if (p != NULL) {
			fprintf(stdout, "%s", p);
		}
		if (q != NULL) {
			fprintf(stderr, "%s", q);
		}
		talloc_free(ctx);
		return ret;
		break;
	}
	talloc_free(ctx);
	return CM_SUBMIT_STATUS_UNCONFIGURED;
}
