/*
 * Copyright (C) 2010,2011,2012 Red Hat, Inc.
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

#include <krb5.h>

#include <talloc.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "submit-d.h"
#include "submit-h.h"
#include "submit-u.h"
#include "util-o.h"

static char *
cm_submit_d_xml_value(void *parent, const char *xml, const char *path)
{
	/* "xpath" -> content */
	xmlXPathContextPtr xpctx;
	xmlXPathObjectPtr obj;
	xmlDocPtr doc;
	xmlNodePtr node;
	xmlChar *xpath;
	char *ret = NULL;
	const char *content;
	int i;

	doc = xmlParseMemory(xml, strlen(xml));
	if (doc != NULL) {
		xpctx = xmlXPathNewContext(doc);
		if (xpctx != NULL) {
			xpath = xmlCharStrdup(path);
			obj = NULL;
			if (xpath != NULL) {
				obj = xmlXPathEval(xpath, xpctx);
				xmlFree(xpath);
			}
			node = NULL;
			if ((obj != NULL) &&
			    (obj->nodesetval != NULL) &&
			    (obj->nodesetval->nodeNr > 0)) {
				for (i = 0;
				     (i < obj->nodesetval->nodeNr) &&
				     (node == NULL);
				     i++) {
					node = obj->nodesetval->nodeTab[i]->children;
					while (node != NULL) {
						if (node->type == XML_TEXT_NODE) {
							break;
						}
						node = node->next;
					}
				}
			}
			if (node != NULL) {
				content = (const char *) node->content;
				content = content + strspn(content, "\n");
				i = strlen(content) - 1;
				while ((i > 0) &&
				       (strchr("\n", content[i]) != NULL)) {
					i--;
				}
				ret = talloc_strndup(parent, content, i + 1);
			}
			xmlXPathFreeContext(xpctx);
		}
		xmlFreeDoc(doc);
	}
	return ret;
}

char *
cm_submit_d_req_error(void *parent, const char *xml)
{
	/* ProfileSubmitServlet.java:
	 * 1: internal error
	 * 2: deferred
	 * 3: rejected
	 */
	return cm_submit_d_xml_value(parent, xml, "/xml/output/set/errorCode") ?:
	       cm_submit_d_xml_value(parent, xml, "/XMLResponse/Status");
}

char *
cm_submit_d_req_status(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "/xml/output/set/errorReason") ?:
	       cm_submit_d_xml_value(parent, xml, "/XMLResponse/Error");
}

char *
cm_submit_d_req_requestid(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "/xml/output/set/requestList/list/requestList/set/requestId") ?:
	       cm_submit_d_xml_value(parent, xml, "/XMLResponse/RequestId");
}

char *
cm_submit_d_check_status(void *parent, const char *xml)
{
	/* RequestStatus.java:
	 * begin
	 * pending
	 * approved
	 * svc_pending
	 * canceled
	 * rejected
	 * complete
	 */
	return cm_submit_d_xml_value(parent, xml, "/xml/header/status");
}

char *
cm_submit_d_check_bundle(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "/xml/header/pkcs7ChainBase64");
}

char *
cm_submit_d_fetch_status(void *parent, const char *xml)
{
	/* RequestStatus.java:
	 * begin
	 * pending
	 * approved
	 * svc_pending
	 * canceled
	 * rejected
	 * complete
	 */
	return cm_submit_d_xml_value(parent, xml, "/xml/header/status");
}

char *
cm_submit_d_fetch_bundle(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "/xml/header/pkcs7ChainBase64");
}

#ifdef CM_SUBMIT_D_MAIN
static void
usage(void)
{
	printf("usage: submit-d [-u EE-URL | -U AGENT-URL] MODE OPTIONS\n");
	printf("Modes:\n"
	       "\t-S serialhex: submit-renewal-by-serial\n"
	       "\t-s csrfile:   submit-request-using-CSR\n"
	       "\t-c requestid: check-request-progress\n"
	       "\t-f requestid: fetch-requested-certificate\n"
	       "\t-R requestid: review-profile-request\n");
	printf("Options:\n"
	       "\t-a  use client auth\n"
	       "\t-d: NSS db\n"
	       "\t-P: ca_path\n"
	       "\t-I: ca_info\n"
	       "\t-K: ssl_key\n"
	       "\t-C: ssl_cert\n"
	       "\t-p: ssl_pin\n"
	       "\t-T: profile_name\n"
	       "\t-n: requestor_name\n"
	       "\t-e: requestor_email\n"
	       "\t-t: requestor_telephone\n"
	       "\t-v  verbose (repeat for more)\n");
}

int
main(int argc, char **argv)
{
	void *ctx;
	enum {
		op_none,
		op_submit_csr,
		op_submit_serial,
		op_check,
		op_review,
		op_fetch
	} op;
	int c, i, j, id, agent, clientauth, verbose;
	const char *method, *eeurl, *agenturl, *cgi, *file, *serial, *profile;
	const char *name, *email, *tele;
	const char *nssdb, *capath, *cainfo, *sslkey, *sslcert, *sslpin;
	const char *result;
	char *params, *uri, **var, **vars, *p, *request;
	char *submit_x_vars[] = {"/xml/output/set/requestList/list/requestList/set/requestId",
				 "/xml/output/set/errorCode",
				 "/xml/output/set/errorReason",
				 "/XMLResponse/Status",
				 "/XMLResponse/Error",
				 "/XMLResponse/RequestId",
				 NULL};
	char *check_x_vars[] = {"/xml/header/status",
				"/xml/header/requestId",
				"/xml/fixed/unexpectedError",
				NULL};
	char *review_x_vars[] = {"/xml/header/status",
				 "/xml/header/requestId",
				 "/xml/fixed/unexpectedError",
				 NULL};
	char *fetch_x_vars[] = {"/xml/header/status",
				"/xml/header/requestId",
				"/xml/fixed/unexpectedError",
				"/xml/records/record/base64Cert",
				NULL};
	struct cm_submit_h_context *hctx;
	op = op_none;
	id = 0;
	verbose = 0;
	agent = 0;
	clientauth = 0;
	eeurl = NULL;
	agenturl = NULL;
	uri = NULL;
	file = NULL;
	serial = NULL;
	name = NULL;
	email = NULL;
	tele = NULL;
	nssdb = NULL;
	capath = NULL;
	cainfo = NULL;
	sslkey = NULL;
	sslcert = NULL;
	sslpin = NULL;
	profile = "caServerCert";
	while ((c = getopt(argc, argv, "u:U:n:e:t:T:s:S:c:f:R:vaP:I:K:C:d:p:")) != -1) {
		switch (c) {
		case 'u':
			eeurl = optarg;
			break;
		case 'U':
			agenturl = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		case 'e':
			email = optarg;
			break;
		case 't':
			tele = optarg;
			break;
		case 'T':
			profile = optarg;
			break;
		case 's':
			op = op_submit_csr;
			agent = 0;
			file = optarg;
			break;
		case 'S':
			op = op_submit_serial;
			agent = 0;
			serial = optarg;
			break;
		case 'c':
			op = op_check;
			agent = 0;
			id = strtol(optarg, NULL, 0);
			break;
		case 'R':
			op = op_review;
			agent = 1;
			id = strtol(optarg, NULL, 0);
			break;
		case 'f':
			op = op_fetch;
			agent = 0;
			id = strtol(optarg, NULL, 0);
			break;
		case 'v':
			verbose++;
			break;
		case 'a':
			clientauth++;
			break;
		case 'd':
			nssdb = optarg;
			break;
		case 'P':
			capath = optarg;
			break;
		case 'I':
			cainfo = optarg;
			break;
		case 'K':
			sslkey = optarg;
			break;
		case 'C':
			sslcert = optarg;
			break;
		case 'p':
			sslpin = optarg;
			break;
		default:
			usage();
			return 1;
			break;
		}
	}
	if (nssdb != NULL) {
		setenv("SSL_DIR", nssdb, 1);
	}
	ctx = talloc_new(NULL);
	switch (op) {
	case op_submit_csr:
		method = "POST";
		cgi = "profileSubmit";
		p = cm_submit_u_from_file_single(file);
		if (p == NULL) {
			printf("Error reading CSR from \"%s\".\n", file);
			return 1;
		}
		request = talloc_size(ctx, strlen(p) * 3 + 1);
		for (i = 0, j = 0; p[i] != '\0'; i++) {
			switch (p[i]) {
			case '+':
				strcpy(request + j, "%2B");
				j += 3;
				break;
			default:
				request[j++] = p[i];
				break;
			}
		}
		request[j] = '\0';
		params = talloc_asprintf(ctx,
					 "profileId=%s&"
					 "cert_request_type=pkcs10&"
					 "cert_request=%s&"
					 "xml=true",
					 profile,
					 request);
		if (name != NULL) {
			params = talloc_asprintf(ctx, "%s&requestor_name=%s",
						 params, name);
		}
		if (email != NULL) {
			params = talloc_asprintf(ctx, "%s&requestor_email=%s",
						 params, email);
		}
		if (tele != NULL) {
			params = talloc_asprintf(ctx, "%s&requestor_phone=%s",
						 params, tele);
		}
		vars = submit_x_vars;
		break;
	case op_submit_serial:
		method = "POST";
		cgi = "profileSubmit";
		params = talloc_asprintf(ctx,
					 "profileId=%s&"
					 "serial_num=%s&"
					 "renewal=true&"
					 "xml=true",
					 profile,
					 util_o_dec_from_hex(serial));
		if (name != NULL) {
			params = talloc_asprintf(ctx, "%s&requestor_name=%s",
						 params, name);
		}
		if (email != NULL) {
			params = talloc_asprintf(ctx, "%s&requestor_email=%s",
						 params, email);
		}
		if (tele != NULL) {
			params = talloc_asprintf(ctx, "%s&requestor_phone=%s",
						 params, tele);
		}
		vars = submit_x_vars;
		break;
	case op_review:
		method = "GET";
		cgi = "profileReview";
		params = talloc_asprintf(ctx,
					 "requestId=%d&"
					 "xml=true",
					 id);
		vars = review_x_vars;
		break;
	case op_check:
		method = "GET";
		cgi = "checkRequest";
		params = talloc_asprintf(ctx,
					 "requestId=%d&"
					 "importCert=true&"
					 "xml=true",
					 id);
		vars = check_x_vars;
		break;
	case op_fetch:
		method = "GET";
		cgi = "displayCertFromRequest";
		params = talloc_asprintf(ctx,
					 "requestId=%d&"
					 "importCert=true&"
					 "xml=true",
					 id);
		vars = fetch_x_vars;
		break;
	case op_none:
		printf("Error: no specific request given.\n");
		usage();
		return 1;
	}
	if (agent) {
		if (agenturl == NULL) {
			printf("Error: CA AGENT-URL not given.\n");
			usage();
			return 1;
		}
		if (strstr(agenturl, "/") == NULL) {
			agenturl = talloc_asprintf(ctx, "%s/ca/agent/ca",
						   agenturl);
		}
		if ((strstr(agenturl, "http://") == NULL) &&
		    (strstr(agenturl, "https://") == NULL)) {
			agenturl = talloc_asprintf(ctx, "https://%s", agenturl);
		}
	} else {
		if (eeurl == NULL) {
			printf("Error: CA EE-URL not given.\n");
			usage();
			return 1;
		}
		if (strstr(eeurl, "/") == NULL) {
			eeurl = talloc_asprintf(ctx, "%s/ca/ee/ca", eeurl);
		}
		if ((strstr(eeurl, "http://") == NULL) &&
		    (strstr(eeurl, "https://") == NULL)) {
			eeurl = talloc_asprintf(ctx, "http://%s", eeurl);
		}
	}
	uri = talloc_asprintf(ctx, "%s/%s", agent ? agenturl : eeurl, cgi);
	if (verbose > 1) {
		printf("url = \"%s\"\n", uri);
		if (verbose > 2) {
			printf("params = \"%s\"\n", params);
		}
	}
	hctx = cm_submit_h_init(ctx, method, uri, params,
				cainfo, capath, sslcert, sslkey, sslpin,
				cm_submit_h_negotiate_off,
				cm_submit_h_delegate_off,
				clientauth ?
				cm_submit_h_clientauth_on :
				cm_submit_h_clientauth_off,
				cm_submit_h_env_modify_off,
				verbose > 2 ?
				cm_submit_h_curl_verbose_on :
				cm_submit_h_curl_verbose_off);
	cm_submit_h_run(hctx);
	c = cm_submit_h_result_code(hctx);
	if (c != 0) {
		printf("Error %d.\n", c);
		if ((result = cm_submit_h_result_code_text(hctx)) != NULL) {
			printf("%s\n", result);
		}
		return 1;
	}
	result = cm_submit_h_results(hctx) ?: "";
	switch (op) {
	case op_submit_csr:
	case op_submit_serial:
		printf("%s:%s\n",
		       cm_submit_d_req_error(hctx, result),
		       cm_submit_d_req_status(hctx, result));
		p = cm_submit_d_req_requestid(hctx, result);
		if (p != NULL) {
			printf("%s\n", p);
		}
		break;
	case op_review:
		printf("%s\n", cm_submit_d_check_status(hctx, result) ?: "(unknown)");
		p = cm_submit_d_check_bundle(hctx, result);
		if (p != NULL) {
			printf("%s\n", p);
		}
		break;
	case op_check:
		printf("%s\n", cm_submit_d_check_status(hctx, result) ?: "(unknown)");
		p = cm_submit_d_check_bundle(hctx, result);
		if (p != NULL) {
			printf("%s\n", p);
		}
		break;
	case op_fetch:
		printf("%s\n", cm_submit_d_fetch_status(hctx, result) ?: "(unknown)");
		p = cm_submit_d_fetch_bundle(hctx, result);
		if (p != NULL) {
			printf("%s\n", p);
		}
		break;
	case op_none:
		/* never reached */
		break;
	}
	if (verbose > 0) {
		for (var = vars; (var != NULL) && (*var != NULL); var++) {
			p = cm_submit_d_xml_value(hctx, result, *var);
			if (p != NULL) {
				printf("%s = \"%s\"\n", *var, p);
			}
		}
		if (verbose > 1) {
			printf("result = \"%s\"\n", result);
		}
	}
	return 0;
}
#endif
