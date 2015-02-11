/*
 * Copyright (C) 2010,2011,2012,2013 Red Hat, Inc.
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

#include <dbus/dbus.h>

#include <talloc.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "submit-d.h"
#include "submit-e.h"
#include "submit-h.h"
#include "submit-u.h"
#include "util-m.h"

#define DOGTAG_DEFAULTS_SET_PATH \
	"/xml/output/set/record/list/record/set/defList/list/defList/set"
#define DOGTAG_DEFAULTS_SET_MEMBER_NAME "defId"
#define DOGTAG_DEFAULTS_SET_MEMBER_VALUE "defVal"
#define DOGTAG_DEFAULTS_SET_MEMBER_CONSTRAINT "defConstraint"
#define DOGTAG_DEFAULTS_SET_MEMBER_SYNTAX "defSyntax"

static char *
trim(void *parent, const char *value)
{
	int l;
	if (value != NULL) {
		value += strspn(value, " \t\r\n");
		l = strlen(value);
		while ((l > 0) && (strchr(" \t\r\n", value[l - 1]) != NULL)) {
			l--;
		}
		if (l > 0) {
			return talloc_strndup(parent, value, l);
		} else {
			return NULL;
		}
	}
	return NULL;
}

static char *
cm_submit_d_xml_node_text(void *parent, xmlNodePtr node, const char *subname)
{
	xmlNodePtr subnode;
	char *ret;
	const char *content;
	int i;

	subnode = NULL;
	if (subname != NULL) {
		/* point "node" at a child with the given name */
		subnode = node->children;
		node = NULL;
		while (subnode != NULL) {
			if ((subnode->type == XML_ELEMENT_NODE) &&
			    (strcmp((const char *) subnode->name,
				    subname) == 0)) {
				node = subnode;
				break;
			}
			subnode = subnode->next;
		}
	}
	if (node != NULL) {
		/* point "node" at its first text child, if it has one */
		subnode = node->children;
		node = NULL;
		while (subnode != NULL) {
			if (subnode->type == XML_TEXT_NODE) {
				node = subnode;
				break;
			}
			subnode = subnode->next;
		}
	}
	ret = NULL;
	if (node != NULL) {
		content = (const char *) node->content;
		content += strspn(content, "\r\n");
		i = strlen(content);
		while ((i > 0) && (strchr("\r\n", content[i - 1]) != NULL)) {
			i--;
		}
		ret = talloc_strndup(parent, content, i);
	}
	return ret;
}

static struct dogtag_default *
cm_submit_d_xml_default(void *parent, xmlNodePtr node)
{
	char *name, *value, *constraint, *syntax;
	const char *subname;
	struct dogtag_default *ret;

	subname = DOGTAG_DEFAULTS_SET_MEMBER_NAME;
	name = cm_submit_d_xml_node_text(parent, node, subname);
	subname = DOGTAG_DEFAULTS_SET_MEMBER_VALUE;
	value = cm_submit_d_xml_node_text(parent, node, subname);
	subname = DOGTAG_DEFAULTS_SET_MEMBER_CONSTRAINT;
	constraint = cm_submit_d_xml_node_text(parent, node, subname);
	subname = DOGTAG_DEFAULTS_SET_MEMBER_SYNTAX;
	syntax = cm_submit_d_xml_node_text(parent, node, subname);
	if ((value == NULL) && (syntax != NULL) &&
	    (strcmp(syntax, "choice") == 0)) {
		value = talloc_strdup(parent, constraint);
		if (value != NULL) {
			value[strcspn(value, ",")] = '\0';
		}
	}
	if ((name == NULL) ||
	    (value == NULL) ||
	    (constraint == NULL) ||
	    (syntax == NULL)) {
		return NULL;
	}
	if (strcmp(constraint, "readonly") == 0) {
		return NULL;
	}
	ret = talloc_ptrtype(parent, ret);
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		ret->name = name;
		ret->value = value;
		if (strcmp(syntax, "int") == 0) {
			ret->syntax = dogtag_int;
		} else
		if (strcmp(syntax, "string") == 0) {
			ret->syntax = dogtag_string;
		} else
		if (strcmp(syntax, "boolean") == 0) {
			ret->syntax = dogtag_boolean;
		} else
		if (strcmp(syntax, "choice") == 0) {
			ret->syntax = dogtag_choice;
		} else
		if (strcmp(syntax, "string_list") == 0) {
			ret->syntax = dogtag_string_list;
		} else {
			ret->syntax = dogtag_unknown;
		}
	}

	return ret;
}

struct dogtag_default **
cm_submit_d_xml_defaults(void *parent, const char *xml)
{
	/* "xpath" -> content */
	struct dogtag_default **ret;
	xmlXPathContextPtr xpctx;
	xmlXPathObjectPtr obj;
	xmlDocPtr doc;
	xmlNodePtr node;
	xmlChar *xpath;
	int i, j;

	ret = NULL;
	doc = xmlParseMemory(xml, strlen(xml));
	if (doc != NULL) {
		xpctx = xmlXPathNewContext(doc);
		if (xpctx != NULL) {
			xpath = xmlCharStrdup(DOGTAG_DEFAULTS_SET_PATH);
			obj = NULL;
			if (xpath != NULL) {
				obj = xmlXPathEval(xpath, xpctx);
				xmlFree(xpath);
			}
			node = NULL;
			if ((obj != NULL) &&
			    (obj->nodesetval != NULL) &&
			    (obj->nodesetval->nodeNr > 0)) {
				ret = malloc(sizeof(*ret) *
					     (obj->nodesetval->nodeNr + 1));
				if (ret == NULL) {
					return NULL;
				}
				memset(ret, 0,
				       sizeof(*ret) *
				       (obj->nodesetval->nodeNr + 1));
				for (i = 0, j = 0;
				     (i < obj->nodesetval->nodeNr);
				     i++) {
					node = obj->nodesetval->nodeTab[i];
					ret[j] = cm_submit_d_xml_default(parent, node);
					if (ret[j] != NULL) {
						j++;
					}
				}
				ret[j] = NULL;
			}
			xmlXPathFreeContext(xpctx);
		}
		xmlFreeDoc(doc);
	}
	return ret;
}

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

int
cm_submit_d_submit_result(void *parent, const char *xml,
			  char **error_code, char **error_reason,
			  char **error, char **status, char **requestId)
{
	/* ProfileSubmitServlet.java:
	 * 1: internal error
	 * 2: deferred (or "pending")
	 * 3: rejected
	 */
	*error_code = cm_submit_d_xml_value(parent, xml,
					    "/xml/output/set/errorCode");
	*error_reason = cm_submit_d_xml_value(parent, xml,
					      "/xml/output/set/errorReason");
	*error = cm_submit_d_xml_value(parent, xml, "/XMLResponse/Error");
	*status = cm_submit_d_xml_value(parent, xml, "/XMLResponse/Status");
	*requestId = trim(parent,
			  cm_submit_d_xml_value(parent,
						xml,
						"/XMLResponse/RequestId"));
	return 0;
}

int
cm_submit_d_check_result(void *parent, const char *xml,
			 char **error_code, char **error_reason,
			 char **error, char **status, char **requestId)
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
	*error = cm_submit_d_xml_value(parent, xml, "/xml/fixed/unexpectedError");
	*status = cm_submit_d_xml_value(parent, xml, "/xml/header/status");
	*requestId = cm_submit_d_xml_value(parent, xml, "/xml/header/requestId");
	return 0;
}

int
cm_submit_d_reject_result(void *parent, const char *xml,
			  char **error_code, char **error_reason,
			  char **error, char **status, char **requestId)
{
	*error = cm_submit_d_xml_value(parent, xml,
				       "/xml/output/set/errorReason") ?:
		 cm_submit_d_xml_value(parent, xml, "/XMLResponse/Error");
	*status = cm_submit_d_xml_value(parent, xml, "/XMLResponse/Status");
	*requestId = trim(parent,
			  cm_submit_d_xml_value(parent,
						xml,
						"/XMLResponse/RequestId"));
	return 0;
}

int
cm_submit_d_review_result(void *parent, const char *xml,
			  char **error_code, char **error_reason,
			  char **error, char **status, char **requestId)
{
	*error_code = trim(parent,
			   cm_submit_d_xml_value(parent, xml,
						 "/xml/output/set/errorCode"));
	*error_reason = trim(parent,
			     cm_submit_d_xml_value(parent,
						   xml,
						   "/xml/output/set/errorReason"));
	*requestId = trim(parent,
			  cm_submit_d_xml_value(parent,
						xml,
						"/xml/output/set/requestId"));
	*status = trim(parent,
		       cm_submit_d_xml_value(parent,
					     xml,
					     "/xml/output/set/requestStatus"));
	return 0;
}

int
cm_submit_d_approve_result(void *parent, const char *xml,
			   char **error_code, char **error_reason,
			   char **error, char **status, char **requestId)
{
	*error_code = trim(parent,
			   cm_submit_d_xml_value(parent, xml,
						 "/xml/output/set/errorCode"));
	*error_reason = trim(parent,
			     cm_submit_d_xml_value(parent,
						   xml,
						   "/xml/output/set/errorReason"));
	*requestId = trim(parent,
			  cm_submit_d_xml_value(parent,
						xml,
						"/xml/output/set/requestId"));
	*status = trim(parent,
		       cm_submit_d_xml_value(parent,
					     xml,
					     "/xml/output/set/requestStatus"));
	return 0;
}

int
cm_submit_d_fetch_result(void *parent, const char *xml,
			 char **error_code, char **error_reason,
			 char **error, char **status,
			 char **requestId, char **cert)
{
	*error = cm_submit_d_xml_value(parent, xml,
				       "/xml/fixed/unexpectedError");
	*status = cm_submit_d_xml_value(parent, xml,
					"/xml/fixed/requestStatus");
	*requestId = cm_submit_d_xml_value(parent, xml,
					   "/xml/header/requestId");
	*cert = cm_submit_d_xml_value(parent, xml,
				      "/xml/records/record/base64Cert");
	return 0;
}

enum cm_external_status
cm_submit_d_submit_eval(void *parent, const char *xml, const char *url,
			dbus_bool_t can_agent, char **out, char **err)
{
	char *error = NULL, *error_code = NULL, *error_reason = NULL;
	char *status = NULL, *requestId = NULL;
	*out = NULL;
	*err = NULL;
	cm_submit_d_submit_result(parent, xml,
				  &error_code, &error_reason, &error,
				  &status, &requestId);
	if ((status != NULL) && (strcmp(status, "2") == 0) &&
	    (requestId != NULL)) {
		if (can_agent) {
			*out = talloc_asprintf(parent,
					       "0\nstate=approve&requestId=%s\n",
					       cm_submit_u_url_encode(requestId));
			return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
		} else {
			*out = talloc_asprintf(parent,
					       "state=check&requestId=%s\n",
					       cm_submit_u_url_encode(requestId));
			return CM_SUBMIT_STATUS_WAIT;
		}
	}
	if ((error != NULL) || (error_code != NULL) || (error_reason != NULL)) {
		*out = talloc_asprintf(parent, "Server at \"%s\" replied", url);
		if (error != NULL) {
			*out = talloc_asprintf_append(*out, ": %s", error);
		}
		if (error_code != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_code);
		}
		if (error_reason != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_reason);
		}
	}
	return CM_SUBMIT_STATUS_REJECTED;
}

enum cm_external_status
cm_submit_d_check_eval(void *parent, const char *xml, const char *url,
		       dbus_bool_t can_agent, char **out, char **err)
{
	char *error = NULL, *error_code = NULL, *error_reason = NULL;
	char *status = NULL, *requestId = NULL;
	*out = NULL;
	*err = NULL;
	cm_submit_d_check_result(parent, xml,
				 &error_code, &error_reason, &error,
				 &status, &requestId);
	if ((status != NULL) &&
	    (strcmp(status, "complete") == 0) &&
	    (requestId != NULL)) {
		*out = talloc_asprintf(parent,
				       "0\nstate=retrieve&requestId=%s\n",
				       cm_submit_u_url_encode(requestId));
		return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
	}
	if ((status != NULL) &&
	    (strcmp(status, "pending") == 0) &&
	    (requestId != NULL)) {
		if (can_agent) {
			*out = talloc_asprintf(parent,
					       "0\nstate=approve&requestId=%s\n",
					       cm_submit_u_url_encode(requestId));
			return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
		} else {
			*out = talloc_asprintf(parent,
					       "state=check&requestId=%s\n",
					       cm_submit_u_url_encode(requestId));
			return CM_SUBMIT_STATUS_WAIT;
		}
	}
	if ((error != NULL) || (error_code != NULL) || (error_reason != NULL)) {
		*out = talloc_asprintf(parent, "Server at \"%s\" replied", url);
		if (error != NULL) {
			*out = talloc_asprintf_append(*out, ": %s", error);
		}
		if (error_code != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_code);
		}
		if (error_reason != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_reason);
		}
	}
	return CM_SUBMIT_STATUS_REJECTED;
}

enum cm_external_status
cm_submit_d_reject_eval(void *parent, const char *xml, const char *url,
			dbus_bool_t can_agent, char **out, char **err)
{
	char *error = NULL, *error_code = NULL, *error_reason = NULL;
	char *status = NULL, *requestId = NULL;
	*out = NULL;
	*err = NULL;
	cm_submit_d_reject_result(parent, xml,
				  &error_code, &error_reason, &error,
				  &status, &requestId);
	if ((error != NULL) || (error_code != NULL) || (error_reason != NULL)) {
		*out = talloc_asprintf(parent, "Server at \"%s\" replied", url);
		if (error != NULL) {
			*out = talloc_asprintf_append(*out, ": %s", error);
		}
		if (error_code != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_code);
		}
		if (error_reason != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_reason);
		}
	}
	return CM_SUBMIT_STATUS_REJECTED;
}

enum cm_external_status
cm_submit_d_review_eval(void *parent, const char *xml, const char *url,
			dbus_bool_t can_agent, char **out, char **err)
{
	char *error = NULL, *error_code = NULL, *error_reason = NULL;
	char *status = NULL, *requestId = NULL;
	*out = NULL;
	*err = NULL;
	cm_submit_d_review_result(parent, xml,
				  &error_code, &error_reason, &error,
				  &status, &requestId);
	if ((status != NULL) &&
	    (strcmp(status, "pending") == 0) &&
	    (requestId != NULL)) {
		*out = talloc_asprintf(parent,
				       "0\nstate=approve&requestId=%s\n",
				       cm_submit_u_url_encode(requestId));
		return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
	}
	if ((status != NULL) &&
	    (strcmp(status, "complete") == 0) &&
	    (requestId != NULL)) {
		*out = talloc_asprintf(parent,
				       "0\nstate=retrieve&requestId=%s\n",
				       cm_submit_u_url_encode(requestId));
		return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
	}
	if ((error != NULL) || (error_code != NULL) || (error_reason != NULL)) {
		*out = talloc_asprintf(parent, "Server at \"%s\" replied", url);
		if (error != NULL) {
			*out = talloc_asprintf_append(*out, ": %s", error);
		}
		if (error_code != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_code);
		}
		if (error_reason != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_reason);
		}
	}
	return CM_SUBMIT_STATUS_REJECTED;
}

enum cm_external_status
cm_submit_d_approve_eval(void *parent, const char *xml, const char *url,
			 dbus_bool_t can_agent, char **out, char **err)
{
	char *error = NULL, *error_code = NULL, *error_reason = NULL;
	char *status = NULL, *requestId = NULL;
	*out = NULL;
	*err = NULL;
	cm_submit_d_approve_result(parent, xml,
				   &error_code, &error_reason, &error,
				   &status, &requestId);
	if ((status != NULL) && (strcmp(status, "complete") == 0) &&
	    (requestId != NULL)) {
		*out = talloc_asprintf(parent,
				       "0\nstate=retrieve&requestId=%s\n",
				       cm_submit_u_url_encode(requestId));
		return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
	}
	if ((error != NULL) || (error_code != NULL) || (error_reason != NULL)) {
		*out = talloc_asprintf(parent, "Server at \"%s\" replied", url);
		if (error != NULL) {
			*out = talloc_asprintf_append(*out, ": %s", error);
		}
		if (error_code != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_code);
		}
		if (error_reason != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_reason);
		}
	}
	return CM_SUBMIT_STATUS_REJECTED;
}

enum cm_external_status
cm_submit_d_fetch_eval(void *parent, const char *xml, const char *url,
		       dbus_bool_t can_agent, char **out, char **err)
{
	char *error = NULL, *error_code = NULL, *error_reason = NULL;
	char *status = NULL, *requestId = NULL, *cert = NULL;
	*out = NULL;
	*err = NULL;
	cm_submit_d_fetch_result(parent, xml,
				 &error_code, &error_reason, &error,
				 &status, &requestId, &cert);
	if (cert != NULL) {
		*out = talloc_asprintf(parent, "%s\n", trim(parent, cert));
		return CM_SUBMIT_STATUS_ISSUED;
	}
	if ((error != NULL) || (error_code != NULL) || (error_reason != NULL)) {
		*out = talloc_asprintf(parent, "Server at \"%s\" replied", url);
		if (error != NULL) {
			*out = talloc_asprintf_append(*out, ": %s", error);
		}
		if (error_code != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_code);
		}
		if (error_reason != NULL) {
			*out = talloc_asprintf_append(*out, ": %s",
						      error_reason);
		}
	}
	return CM_SUBMIT_STATUS_REJECTED;
}

#ifdef CM_SUBMIT_D_MAIN
static void
usage(void)
{
	printf("usage: submit-d [-u EE-URL | -U AGENT-URL] MODE OPTIONS\n");
	printf("Modes:\n"
	       "\t-S serialhex: submit-renewal-by-serial\n"
	       "\t-D serialdec: submit-renewal-by-serial\n"
	       "\t-s csrfile:   submit-request-using-CSR\n"
	       "\t-c requestid: check-request-progress\n"
	       "\t-f requestid: fetch-requested-certificate\n"
	       "\t-R requestid: review-profile-based-request\n"
	       "\t-J requestid: reject-profile-based-request\n"
	       "\t-A requestid: approve-profile-based-request\n");
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
	       "\t-V: approval_params\n"
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
		op_reject,
		op_approve,
		op_fetch
	} op;
	int c, i, id, agent, clientauth, verbose;
	const char *method, *eeurl, *agenturl, *cgi, *file, *serial, *profile;
	const char *name, *email, *tele;
	const char *nssdb, *capath, *cainfo, *sslkey, *sslcert, *sslpin;
	const char *result, *default_values;
	struct dogtag_default **defaults, *nodefault[] = { NULL };
	char *params, *uri, *p, *q, *request;
	char *error = NULL, *error_code = NULL, *error_reason = NULL;
	char *status = NULL, *requestId = NULL, *cert = NULL;
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
	defaults = NULL;
	default_values = NULL;
	profile = "caServerCert";
	while ((c = getopt(argc, argv, "u:U:n:e:t:T:s:S:D:c:f:R:J:A:vaP:I:K:C:d:p:V:")) != -1) {
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
			serial = util_dec_from_hex(optarg);
			break;
		case 'D':
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
		case 'A':
			op = op_approve;
			agent = 1;
			id = strtol(optarg, NULL, 0);
			break;
		case 'J':
			op = op_reject;
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
		case 'V':
			default_values = optarg;
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
restart:
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
		request = cm_submit_u_url_encode(p);
		if (request == NULL) {
			printf("Error URL-encoding CSR.\n");
			return 1;
		}
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
					 serial);
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
		break;
	case op_review:
		method = "GET";
		cgi = "profileReview";
		params = talloc_asprintf(ctx,
					 "requestId=%d&"
					 "xml=true",
					 id);
		break;
	case op_reject:
		method = "GET";
		cgi = "profileProcess";
		params = talloc_asprintf(ctx,
					 "requestId=%d&"
					 "op=reject&"
					 "xml=true",
					 id);
		break;
	case op_approve:
		if ((defaults == NULL) && (default_values == NULL)) {
			/* ask for defaults */
			method = "GET";
			cgi = "profileReview";
			params = talloc_asprintf(ctx,
						 "requestId=%d&"
						 "xml=true",
						 id);
		} else
		if (default_values != NULL) {
			/* use supplied defaults */
			method = "GET";
			cgi = "profileProcess";
			params = talloc_asprintf(ctx,
						 "requestId=%d&"
						 "op=approve&"
						 "xml=true&%s",
						 id, default_values);
		} else {
			/* use asked-for defaults */
			method = "GET";
			cgi = "profileProcess";
			params = talloc_asprintf(ctx,
						 "requestId=%d&"
						 "op=approve&"
						 "xml=true",
						 id);
			for (i = 0;
			     (defaults != NULL) &&
			     (defaults[i] != NULL) &&
			     (defaults[i]->name != NULL) &&
			     (defaults[i]->value != NULL);
			     i++) {
				p = cm_submit_u_url_encode(defaults[i]->name);
				q = cm_submit_u_url_encode(defaults[i]->value);
				if ((p != NULL) && (q != NULL)) {
					params = talloc_asprintf(ctx,
								 "%s&%s=%s",
								 params, p, q);
				}
			}
		}
		break;
	case op_check:
		method = "GET";
		cgi = "checkRequest";
		params = talloc_asprintf(ctx,
					 "requestId=%d&"
					 "importCert=true&"
					 "xml=true",
					 id);
		break;
	case op_fetch:
		method = "GET";
		cgi = "displayCertFromRequest";
		params = talloc_asprintf(ctx,
					 "requestId=%d&"
					 "importCert=true&"
					 "xml=true",
					 id);
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
	if (verbose > 0) {
		fprintf(stderr, "url = \"%s%s%s\"\n", uri,
		        params ? "?" : "", params ? params : "");
	}
	hctx = cm_submit_h_init(ctx, method, uri, params, NULL, NULL,
				cainfo, capath, sslcert, sslkey, sslpin,
				cm_submit_h_negotiate_off,
				cm_submit_h_delegate_off,
				clientauth ?
				cm_submit_h_clientauth_on :
				cm_submit_h_clientauth_off,
				cm_submit_h_env_modify_off,
				verbose > 1 ?
				cm_submit_h_curl_verbose_on :
				cm_submit_h_curl_verbose_off);
	cm_submit_h_run(hctx);
	c = cm_submit_h_result_code(hctx);
	if (c != 0) {
		if ((result = cm_submit_h_result_code_text(hctx)) != NULL) {
			printf("Error %d: %s\n", c, result);
		} else {
			printf("Error %d.\n", c);
		}
		return 1;
	}
	result = cm_submit_h_results(hctx, NULL) ?: "";
	if (verbose > 0) {
		fprintf(stderr, "result = \"%s\"\n", result);
	}
	switch (op) {
	case op_submit_csr:
	case op_submit_serial:
		cm_submit_d_submit_result(hctx, result,
					  &error_code, &error_reason,
					  &error, &status, &requestId);
		if (error_code != NULL) {
			printf("error code: %s\n", error_code);
		}
		if (error_reason != NULL) {
			printf("error reason: %s\n", error_reason);
		}
		if (error != NULL) {
			printf("error: %s\n", error);
		}
		if (status != NULL) {
			printf("status: %s\n", status);
		}
		if (requestId != NULL) {
			printf("requestId: %s\n", requestId);
		}
		break;
	case op_reject:
		cm_submit_d_reject_result(hctx, result,
					  &error_code, &error_reason,
					  &error, &status, &requestId);
		if (error_code != NULL) {
			printf("error code: %s\n", error_code);
		}
		if (error_reason != NULL) {
			printf("error reason: %s\n", error_reason);
		}
		if (error != NULL) {
			printf("error: %s\n", error);
		}
		if (status != NULL) {
			printf("status: %s\n", status);
		}
		if (requestId != NULL) {
			printf("requestId: %s\n", requestId);
		}
		break;
	case op_review:
		defaults = cm_submit_d_xml_defaults(hctx, result);
		for (i = 0;
		     (defaults != NULL) &&
		     (defaults[i] != NULL) &&
		     (defaults[i]->name != NULL) &&
		     (defaults[i]->value != NULL);
		     i++) {
			p = cm_submit_u_url_encode(defaults[i]->name);
			q = cm_submit_u_url_encode(defaults[i]->value);
			if ((p != NULL) && (q != NULL)) {
				printf("default: %s=%s\n", p, q);
			}
		}
		cm_submit_d_approve_result(hctx, result,
					   &error_code, &error_reason,
					   &error, &status, &requestId);
		if (error_code != NULL) {
			printf("error code: %s\n", error_code);
		}
		if (error_reason != NULL) {
			printf("error reason: %s\n", error_reason);
		}
		if (error != NULL) {
			printf("error: %s\n", error);
		}
		if (status != NULL) {
			printf("status: %s\n", status);
		}
		if (requestId != NULL) {
			printf("requestId: %s\n", requestId);
		}
		break;
	case op_approve:
		if ((defaults == NULL) && (default_values == NULL)) {
			/* ask for defaults */
			defaults = cm_submit_d_xml_defaults(hctx, result);
			if (defaults == NULL) {
				defaults = nodefault;
			}
			goto restart;
		} else {
			cm_submit_d_approve_result(hctx, result,
						   &error_code, &error_reason,
						   &error, &status, &requestId);
			if (error_code != NULL) {
				printf("error code: %s\n", error_code);
			}
			if (error_reason != NULL) {
				printf("error reason: %s\n", error_reason);
			}
			if (error != NULL) {
				printf("error: %s\n", error);
			}
			if (status != NULL) {
				printf("status: %s\n", status);
			}
			if (requestId != NULL) {
				printf("requestId: %s\n", requestId);
			}
		}
		break;
	case op_check:
		cm_submit_d_check_result(hctx, result,
					 &error_code, &error_reason,
					 &error, &status, &requestId);
		if (error_code != NULL) {
			printf("error code: %s\n", error_code);
		}
		if (error_reason != NULL) {
			printf("error reason: %s\n", error_reason);
		}
		if (error != NULL) {
			printf("error: %s\n", error);
		}
		if (status != NULL) {
			printf("status: %s\n", status);
		}
		if (requestId != NULL) {
			printf("requestId: %s\n", requestId);
		}
		break;
	case op_fetch:
		cm_submit_d_fetch_result(hctx, result,
					 &error_code, &error_reason,
					 &error, &status, &requestId, &cert);
		if (error_code != NULL) {
			printf("error code: %s\n", error_code);
		}
		if (error_reason != NULL) {
			printf("error reason: %s\n", error_reason);
		}
		if (error != NULL) {
			printf("error: %s\n", error);
		}
		if (status != NULL) {
			printf("status: %s\n", status);
		}
		if (requestId != NULL) {
			printf("requestId: %s\n", requestId);
		}
		if (cert != NULL) {
			printf("cert: %s\n", cert);
		}
		break;
	case op_none:
		/* never reached */
		break;
	}
	return 0;
}
#endif
