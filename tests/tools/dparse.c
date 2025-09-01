/*
 * Copyright (C) 2012,2015 Red Hat, Inc.
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

#include "../../src/config.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <krb5.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include "../../src/submit.h"
#include "../../src/submit-d.h"
#include "../../src/submit-e.h"
#include "../../src/submit-u.h"

int
main(int argc, char **argv)
{
	const char *mode, *role, *filename;
	char *error = NULL, *error_code = NULL, *error_reason = NULL;
	char *status = NULL, *requestId = NULL, *cert = NULL;
	char *xml, *out = NULL, *err = NULL, **profiles = NULL;
	dbus_bool_t can_agent;
	enum cm_rpc_protocol format;
	int i, vars;
	void *ctx;

	if (argc < 4) {
		printf("usage: dparse "
		       "{submit|check|review|reject|approve|fetch|profiles} "
		       "{agent|end-entity|json} "
		       "reply.xml\n");
		return 0;
	}
	mode = argv[1];
	role = argv[2];
	filename = argv[3];
	can_agent = (strcasecmp(role, "agent") == 0);
	if ((strcasecmp(role, "agent") == 0) || (strcasecmp(role, "end-entity") == 0)) {
		format = CM_RPC_PROTOCOL_XML;
	} else {
		format = CM_RPC_PROTOCOL_JSON;
	}

	xml = cm_submit_u_from_file(filename);
	if (xml == NULL) {
		fprintf(stderr, "error reading %s\n", filename);
		return -1;
	}
	ctx = talloc_new(NULL);

	if (strcmp(mode, "submit") == 0) {

		switch (format) {
		case CM_RPC_PROTOCOL_XML:
			cm_submit_d_submit_result(ctx, xml,
						  &error_code, &error_reason, &error,
						  &status, &requestId, &cert);
			break;
		case CM_RPC_PROTOCOL_JSON:
			cm_submit_d_rest_submit_result(ctx, xml,
						  &error_code, &error_reason,
						  &status, &requestId, &cert);
			break;
		}
		i = cm_submit_d_submit_eval(ctx, xml, "SUBMIT",
					    can_agent, &out, &err, format);
	} else
	if (strcmp(mode, "check") == 0) {
		switch (format) {
		case CM_RPC_PROTOCOL_XML:
			cm_submit_d_check_result(ctx, xml,
						 &error, &status, &requestId);
			break;
		case CM_RPC_PROTOCOL_JSON:
			cm_submit_d_rest_check_result(ctx, xml,
						 &error_code, &error_reason,
						 &status, &requestId);
			break;
		}
		i = cm_submit_d_check_eval(ctx, xml, "CHECK",
					   can_agent, &out, &err, format);
	} else
	if (strcmp(mode, "reject") == 0) {
		cm_submit_d_reject_result(ctx, xml,
					  &error, &status, &requestId);
		i = cm_submit_d_reject_eval(ctx, xml, "REJECT",
					    &out, &err);
	} else
	if (strcmp(mode, "review") == 0) {
		cm_submit_d_review_result(ctx, xml,
					  &error_code, &error_reason,
					  &status, &requestId);
		i = cm_submit_d_review_eval(ctx, xml, "REVIEW",
					    &out, &err);
	} else
	if (strcmp(mode, "approve") == 0) {
		switch (format) {
		case CM_RPC_PROTOCOL_XML:
			cm_submit_d_approve_result(ctx, xml,
						   &error_code, &error_reason,
						   &status, &requestId);
			break;
		case CM_RPC_PROTOCOL_JSON:
			cm_submit_d_rest_approve_result(ctx, xml,
						   &error_code, &error_reason, &error,
						   &requestId);
			break;
		}
		i = cm_submit_d_approve_eval(ctx, xml, "APPROVE",
					     &out, &err, format);
	} else
	if (strcmp(mode, "fetch") == 0) {
		switch (format) {
		case CM_RPC_PROTOCOL_XML:
			cm_submit_d_fetch_result(ctx, xml,
						 &error, &status, &requestId, &cert);
			break;
		case CM_RPC_PROTOCOL_JSON:
			cm_submit_d_rest_fetch_result(ctx, xml,
						 &error_code, &error_reason,
						 &status, &cert);
			break;
		}
		i = cm_submit_d_fetch_eval(ctx, xml, "FETCH",
					   &out, &err, format);
	} else
	if (strcmp(mode, "profiles") == 0) {
		switch (format) {
		case CM_RPC_PROTOCOL_XML:
			cm_submit_d_profiles_result(ctx, xml,
						    &error_code, &error_reason,
						    &profiles);
			break;
		case CM_RPC_PROTOCOL_JSON:
			cm_submit_d_rest_profiles_result(ctx, xml,
						    &error_code, &error_reason,
						    &profiles);
			break;
		}
		i = cm_submit_d_profiles_eval(ctx, xml, &out, &err, format);
	} else {
		fprintf(stderr, "unknown mode \"%s\"\n", mode);
		return -1;
	}

	printf("[%s-as-%s(%s) = %s]\n",
	       mode,
	       role,
	       filename,
	       cm_submit_e_status_text(i));
	vars = 0;
	if (error != NULL) {
		printf("error=\"%s\"", error);
		vars++;
	}
	if (error_code != NULL) {
		if (vars > 0) {
			printf(",");
		}
		printf("error_code=\"%s\"", error_code);
		vars++;
	}
	if (error_reason != NULL) {
		if (vars > 0) {
			printf(",");
		}
		printf("error_reason=\"%s\"", error_reason);
		vars++;
	}
	if (status != NULL) {
		if (vars > 0) {
			printf(",");
		}
		printf("status=\"%s\"", status);
		vars++;
	}
	if (requestId != NULL) {
		if (vars > 0) {
			printf(",");
		}
		printf("requestId=\"%s\"", requestId);
		vars++;
	}
	if (cert != NULL) {
		if (vars > 0) {
			printf(",");
		}
		printf("cert=\"%.*s\"", (int) strcspn(cert, "\r\n"), cert);
		vars++;
	}
	if (vars > 0) {
		printf("\n");
	}
	while ((out != NULL) && (*out != '\0')) {
		if (strchr("\r", *out) == NULL) {
			putchar((unsigned char) *out);
		}
		out++;
	}
	while ((err != NULL) && (*err != '\0')) {
		if (strchr("\r", *err) == NULL) {
			putchar((unsigned char) *err);
		}
		err++;
	}
	printf("\n");

	free(xml);
	talloc_free(ctx);

	return 0;
}
