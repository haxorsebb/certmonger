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
				content = content + strspn(content, "\r\n");
				i = strlen(content) - 1;
				while ((i > 0) &&
				       (strchr("\r\n", content[i]) != NULL)) {
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

static char *
cm_submit_d_html_value(void *parent, const char *html, const char *value)
{
	/* Try to be scrape out the part we care about. */
	char *work, *p, *q, *var, *v, *ret;
	int i, esc;
	unsigned long acc;
	work = talloc_strdup(parent, html);
	/* Convert end-of-lines to newline. */
	for (i = 0; work[i] != '\0'; i++) {
		if (work[i] == '\r') {
			work[i] = '\n';
		}
	}
	for (i = 0; work[i] != '\0'; i++) {
		if ((work[i] == '\n') && (work[i + 1] == '\n')) {
			memmove(work + i, work + i + 1, strlen(work + i));
			i--;
		}
	}
	/* Find the start and end of what might be the hard-coded part of the
	 * output. */
	p = strstr(work, "<SCRIPT LANGUAGE=\"JavaScript\">\n");
	ret = NULL;
	while ((p != NULL) && (ret == NULL)) {
		q = strstr(p, "</SCRIPT>\n");
		if (q != NULL) {
			var = talloc_asprintf(work, "\n%s = \"", value);
			if (var != NULL) {
				v = strstr(p, var);
				if (v == NULL) {
					var = talloc_asprintf(work, "\n%s=\"",
							      value);
					v = strstr(p, var);
				}
				if (v != NULL) {
					v += strlen(var);
					/* Pull out the rest of the line. */
					ret = talloc_strndup(work,
							     v,
							     strcspn(v,
								     "\r\n"));
				}
			}
			p = strstr(q, "<SCRIPT LANGUAGE=\"JavaScript\">\n");
		} else {
			p = NULL;
		}
	}
	if (ret != NULL) {
		/* Find the end of the value - the first unescaped double-quote
		 * character. */
		p = ret;
		ret = talloc_strdup(parent, p);
		if (ret != NULL) {
			q = ret;
			esc = 0;
			while (*p != '\0') {
				if (*p == '\\') {
					/* Escape character, or second half of
					 * an escaped escape character. */
					esc = !esc;
					if (!esc) {
						*q++ = '\\';
					}
					p++;
				} else {
					if (esc) {
						/* Escaped. */
						esc = 0;
						switch (*p) {
						case '"':
						case '\'':
						case '\\': /* Not possible, but
							    * mentioned here for
							    * completeness. */
						case '/':
						default:
							/* Echo out. */
							*q++ = *p++;
							break;
						case 'b':
							*q++ = '\b';
							p++;
							break;
						case 'f':
							*q++ = '\f';
							p++;
							break;
						case 'n':
							*q++ = '\n';
							p++;
							break;
						case 'r':
							*q++ = '\r';
							p++;
							break;
						case 't':
							*q++ = '\t';
							p++;
							break;
						case 'u':
							p++;
							v = talloc_strndup(work,
									   p,
									   4);
							acc = strtoul(v, NULL, 16);
							if (acc > 0xffff) {
								q[0] = 0xf0 |
								((acc >> 18) & 0x07);
								q[1] = 0x80 |
								((acc >> 12) & 0x3f);
								q[2] = 0x80 |
								((acc >> 6) & 0x3f);
								q[3] = 0x80 |
								(acc & 0x3f);
								q += 4;
							} else if (acc > 0x7ff){
								q[0] = 0xe0 |
								((acc >> 12) & 0x0f);
								q[1] = 0x80 |
								((acc >> 6) & 0x3f);
								q[2] = 0x80 |
								(acc & 0x3f);
								q += 3;
							} else if (acc > 0x7f) {
								q[0] = 0xc0 |
								((acc >> 6) & 0x1f);
								q[1] = 0x80 |
								(acc & 0x3f);
								q += 2;
							} else {
								q[0] = acc;
								q++;
							}
							p += 4;
							break;
						}
					} else {
						/* Common case:  not escaped. */
						if (*p == '"') {
							/* End of value. */
							*q++ = '\0';
							break;
						} else {
							*q++ = *p++;
						}
					}
				}
			}
		}
	}
	talloc_free(work);
	return ret;
}

char *
cm_submit_d_req_error(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "error");
}

char *
cm_submit_d_req_status(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "status");
}

char *
cm_submit_d_req_requestid(void *parent, const char *xml)
{
	return cm_submit_d_xml_value(parent, xml, "requestId");
}

char *
cm_submit_d_check_status(void *parent, const char *html)
{
	return cm_submit_d_html_value(parent, html, "header.status");
}

char *
cm_submit_d_check_requestid(void *parent, const char *html)
{
	return cm_submit_d_html_value(parent, html, "header.requestId");
}

char *
cm_submit_d_check_serial(void *parent, const char *html)
{
	return cm_submit_d_html_value(parent, html, "record.serialNumber");
}

char *
cm_submit_d_retr_status(void *parent, const char *html)
{
	return NULL;
}

char *
cm_submit_d_retr_cert(void *parent, const char *html)
{
	return NULL;
}

#ifdef CM_SUBMIT_D_MAIN
static void
parse_exercise(void)
{
	const char reqxml[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			      "<XMLResponse>"
			      "<Status>2</Status>"
			      "<Error>Request Deferred - defer request</Error>"
			      "<RequestId>  21</RequestId>"
			      "</XMLResponse>";
	const char checkhtml[] =
		"<SCRIPT LANGUAGE=\"JavaScript\">\n"
		"var header = new Object();\n"
		"var fixed = new Object();\n"
		"var recordSet = new Array;\n"
		"var result = new Object();\n"
		"var httpParamsCount = 0;\n"
		"var httpHeadersCount = 0;\n"
		"var authTokenCount = 0;\n"
		"var serverAttrsCount = 0;\n"
		"header.HTTP_PARAMS = new Array;\n"
		"header.HTTP_HEADERS = new Array;\n"
		"header.AUTH_TOKEN = new Array;\n"
		"header.SERVER_ATTRS = new Array;\n"
		"header.status = \"complete\";\n"
		"header.updatedOn = \"1271976823\";\n"
		"header.requestId = \"21\";\n"
		"header.authority = \"ca\";\n"
		"header.createdOn = \"1271975644\";\n"
		"var recordCount = 0;\n"
		"var record;\n"
		"record = new Object;\n"
		"record.HTTP_PARAMS = new Array;\n"
		"record.HTTP_HEADERS = new Array;\n"
		"record.AUTH_TOKEN = new Array;\n"
		"record.SERVER_ATTRS = new Array;\n"
		"record.serialNumber=\"14\";\n"
		"recordSet[recordCount++] = record;\n"
		"record.recordSet = recordSet;\n"
		"result.header = header;\n"
		"result.fixed = fixed;\n"
		"result.recordSet = recordSet;\n"
		"shemp = \" \\r\\n\\b\\f\\t->\\u0041\\u2262\\u0391\\u002e<-\\\"\\\'\""
		"</SCRIPT>\n";
	char *status, *error, *id;
	printf("XML\n");
	status = cm_submit_d_req_status(NULL, reqxml);
	if (status != NULL) {
		printf("\t\"%s\"\n", status);
	}
	error = cm_submit_d_req_error(NULL, reqxml);
	if (error != NULL) {
		printf("\t\"%s\"\n", error);
	}
	id = cm_submit_d_req_requestid(NULL, reqxml);
	if (id != NULL) {
		printf("\t\"%s\" -> =%ld=\n", id, atol(id));
	}
	printf("HTML\n");
	status = cm_submit_d_check_status(NULL, checkhtml);
	if (status != NULL) {
		printf("\t\"%s\"\n", status);
	}
	id = cm_submit_d_check_requestid(NULL, checkhtml);
	if (id != NULL) {
		printf("\t\"%s\" -> =%ld=\n", id, atol(id));
	}
	id = cm_submit_d_check_serial(NULL, checkhtml);
	if (id != NULL) {
		printf("\t\"%s\" -> =%ld=\n", id, atol(id));
	}
	id = cm_submit_d_html_value(NULL, checkhtml, "shemp");
	if (id != NULL) {
		printf("\t\"%s\"\n", id);
	}
}

static void
usage(void)
{
	printf("usage: submit-d -C CA-EE-URL [-s csrfile OPTIONS] "
	       "[-c requestid] [-r serial]\n");
	printf("Options:\n"
	       "\t-n requestor_name\n"
	       "\t-e requestor_email\n"
	       "\t-t requestor_telephone\n");
}

int
main(int argc, char **argv)
{
	void *ctx;
	int c, i, j, pflag, submit, check, retrieve, id, try_xml;
	const char *method, *ca, *cgi, *file, *profile, *result;
	const char *name, *email, *tele;
	char *params, *uri, **var, **vars, *p, *request;
	char *submit_h_vars[] = {"header.status",
				 "header.error",
				 "header.requestId",
				 NULL};
	char *submit_x_vars[] = {"/xmlResponse/status",
				 "/xmlResponse/error",
				 "/xmlResponse/requestId",
				 NULL};
	char *check_h_vars[] = {"header.status",
				"header.requestId",
				"record.serialNumber",
				"fixed.unexpectedError",
				NULL};
	char *check_x_vars[] = {"/xml/header/status",
				"/xml/header/requestId",
				/* Doesn't give us a serial number!?!?! */
				"/xml/fixed/unexpectedError",
				NULL};
	char *display_h_vars[] = {"header.certChainBase64",
				  "header.certPrettyPrint",
				  NULL};
	char *display_x_vars[] = {"/xml/header/certChainBase64",
				  "/xml/header/certPrettyPrint",
				  NULL};
	struct cm_submit_h_context *hctx;
	pflag = 0;
	submit = 0;
	try_xml = 0;
	check = 0;
	retrieve = 0;
	id = 0;
	ca = NULL;
	file = NULL;
	name = NULL;
	email = NULL;
	tele = NULL;
	profile = "caServerCert";
	while ((c = getopt(argc, argv, "PC:n:e:t:p:s:c:r:x")) != -1) {
		switch (c) {
		case 'P':
			parse_exercise();
			return 0;
			break;
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
			try_xml++;
			file = optarg;
			break;
		case 'c':
			check++;
			id = strtol(optarg, NULL, 0);
			break;
		case 'r':
			retrieve++;
			id = strtol(optarg, NULL, 0);
			break;
		case 'x':
			try_xml++;
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
					 "sessionID=208&"
					 "auth_hostname=cats.bos.redhat.com&"
					 "auth_port=9180"
					 "%s",
					 profile,
					 request,
					 try_xml ? "&xmlOutput=true" : "");
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
		vars = try_xml ? submit_x_vars : submit_h_vars;
	} else
	if (check) {
		method = "GET";
		cgi = "checkRequest";
		params = talloc_asprintf(ctx, "requestId=%d%s", id,
					 try_xml ? "&xml=true" : "");
		vars = try_xml ? check_x_vars : check_h_vars;
	} else
	if (retrieve) {
		method = "GET";
		cgi = "displayBySerial";
		params = talloc_asprintf(ctx, "serialNumber=%d%s", id,
					 try_xml ? "&xml=true" : "");
		vars = try_xml ? display_x_vars : display_h_vars;
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
	hctx = cm_submit_h_init(ctx, method, uri, params);
	cm_submit_h_run(hctx);
	c = cm_submit_h_result_code(hctx);
	if (c != 0) {
		printf("Error %d.\n", c);
		return 1;
	}
	result = cm_submit_h_results(hctx);
	for (var = vars; (var != NULL) && (*var != NULL); var++) {
		if (try_xml) {
			p = cm_submit_d_xml_value(hctx, result, *var);
		} else {
			p = cm_submit_d_html_value(hctx, result, *var);
		}
		if (p != NULL) {
			printf("%s = \"%s\"\n", *var, p);
		}
	}
	return 0;
}
#endif
