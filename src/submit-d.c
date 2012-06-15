/*
 * Copyright (C) 2010,2011 Red Hat, Inc.
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
	return cm_submit_d_xml_value(parent, xml, "/xml/output/set/errorCode");
}

char *
cm_submit_d_req_status(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "/xml/output/set/errorReason");
}

char *
cm_submit_d_req_requestid(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "/xml/output/set/requestList/list/requestList/set/requestId");
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

#ifdef CM_SUBMIT_D_MAIN
/* 
 * profileSubmit:
	HTTP/1.1 200 OK
	Server: Apache-Coyote/1.1
	Content-Type: text/xml
	Content-Length: 248
	Date: Tue, 04 Oct 2011 08:08:41 GMT

	<?xml version="1.0"?>
	<xml>
	  <output>
	    <set>
	      <errorReason>
		Request Deferred - defer request
		</errorReason>
	      <requestList>
		<list>
		  <requestList>
		    <set>
		      <requestId>
		50
		</requestId>
		    </set>
		  </requestList>
		</list>
	      </requestList>
	      <errorCode>
		2
		</errorCode>
	    </set>
	  </output>
	</xml>

 * checkRequest:
	HTTP/1.1 200 OK
	Server: Apache-Coyote/1.1
	Content-Type: text/xml
	Content-Length: 204
	Date: Tue, 04 Oct 2011 08:11:58 GMT

	<?xml version="1.0"?>
	<xml>
	  <header>
	    <status>
	pending
	</status>
	    <updatedOn>
	1317715721
	</updatedOn>
	    <requestId>
	50
	</requestId>
	    <authority>
	ca
	</authority>
	    <createdOn>
	1317715721
	</createdOn>
	  </header>
	  <fixed>
	</fixed>
	</xml>

 * checkRequest:
	HTTP/1.1 200 OK
	Server: Apache-Coyote/1.1
	Content-Type: text/xml
	Content-Length: 3011
	Date: Tue, 04 Oct 2011 08:29:56 GMT

	<?xml version="1.0"?>
	<xml>
	  <header>
	    <status>
	complete
	</status>
	    <pkcs7ChainBase64>
	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
	</pkcs7ChainBase64>
	    <updatedOn>
	1317716551
	</updatedOn>
	    <requestId>
	53
	</requestId>
	    <authority>
	ca
	</authority>
	    <createdOn>
	1317716542
	</createdOn>
	  </header>
	  <fixed>
	</fixed>
	</xml>
 */
static void
usage(void)
{
	printf("usage: submit-d -C CA-EE-URL [-s csrfile OPTIONS] "
	       "[-c requestid]\n");
	printf("Options:\n"
	       "\t-p profile_name\n"
	       "\t-n requestor_name\n"
	       "\t-e requestor_email\n"
	       "\t-t requestor_telephone\n");
}

int
main(int argc, char **argv)
{
	void *ctx;
	int c, i, j, submit, check, id, verbose;
	const char *method, *ca, *cgi, *file, *profile, *result;
	const char *name, *email, *tele;
	char *params, *uri, **var, **vars, *p, *request;
	char *submit_x_vars[] = {"/xml/output/set/requestList/list/requestList/set/requestId",
				 "/xml/output/set/errorCode",
				 "/xml/output/set/errorReason",
				 NULL};
	char *check_x_vars[] = {"/xml/header/status",
				"/xml/header/requestId",
				"/xml/fixed/unexpectedError",
				"/xml/header/pkcs7ChainBase64",
				NULL};
	struct cm_submit_h_context *hctx;
	submit = 0;
	check = 0;
	id = 0;
	verbose = 0;
	ca = NULL;
	file = NULL;
	name = NULL;
	email = NULL;
	tele = NULL;
	profile = "caServerCert";
	while ((c = getopt(argc, argv, "C:n:e:t:T:p:s:c:r:x")) != -1) {
		switch (c) {
		case 'C':
			ca = optarg;
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
		case 'p':
			profile = optarg;
			break;
		case 's':
			submit++;
			file = optarg;
			break;
		case 'c':
			check++;
			id = strtol(optarg, NULL, 0);
			break;
		case 'v':
			verbose++;
			break;
		case 'T':
			profile = optarg;
			break;
		default:
			usage();
			return 1;
			break;
		}
	}
	ctx = talloc_new(NULL);
	if (submit) {
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
	} else
	if (check) {
		method = "GET";
		cgi = "checkRequest";
		params = talloc_asprintf(ctx, "requestId=%d&importCert=true&xml=true", id);
		vars = check_x_vars;
	} else {
		printf("Error: no specific request given.\n");
		usage();
		return 1;
	}
	if (ca == NULL) {
		printf("Error: CA URI not given.\n");
		usage();
		return 1;
	}
	if (strstr(ca, "/") == NULL) {
		/* Append a location on the server. */
		ca = talloc_asprintf(ctx, "%s/ca/ee/ca", ca);
	}
	if ((strstr(ca, "http://") == NULL) &&
	    (strstr(ca, "https://") == NULL)) {
		/* Guess HTTP. */
		ca = talloc_asprintf(ctx, "http://%s", ca);
	}
	uri = talloc_asprintf(ctx, "%s/%s", ca, cgi);
	hctx = cm_submit_h_init(ctx, method, uri, params,
				NULL, NULL, NULL, NULL, NULL,
				cm_submit_h_negotiate_off,
				cm_submit_h_delegate_off,
				cm_submit_h_clientauth_off,
				cm_submit_h_env_modify_on);
	cm_submit_h_run(hctx);
	c = cm_submit_h_result_code(hctx);
	if (c != 0) {
		printf("Error %d.\n", c);
		return 1;
	}
	result = cm_submit_h_results(hctx);
	if (submit) {
		printf("%s:%s\n",
		       cm_submit_d_req_error(hctx, result),
		       cm_submit_d_req_status(hctx, result));
		p = cm_submit_d_req_requestid(hctx, result);
		if (p != NULL) {
			printf("%s\n", p);
		}
	}
	if (check) {
		printf("%s\n", cm_submit_d_check_status(hctx, result));
		p = cm_submit_d_check_bundle(hctx, result);
		if (p != NULL) {
			printf("%s\n", p);
		}
	}
	if (verbose) {
		for (var = vars; (var != NULL) && (*var != NULL); var++) {
			p = cm_submit_d_xml_value(hctx, result, *var);
			if (p != NULL) {
				printf("%s = \"%s\"\n", *var, p);
			}
		}
	}
	return 0;
}
#endif
