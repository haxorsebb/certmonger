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

#include <talloc.h>

#include <curl/curl.h>

#include "log.h"
#include "submit-e.h"
#include "submit-h.h"

struct cm_submit_h_context {
	int ret;
	char *method, *uri, *args, *result;
	CURL *curl;
};

struct cm_submit_h_context *
cm_submit_h_init(void *parent,
		 const char *method, const char *uri, const char *args)
{
	struct cm_submit_h_context *ctx;
	ctx = talloc_ptrtype(parent, ctx);
	if (ctx != NULL) {
		ctx->method = talloc_strdup(ctx, method);
		ctx->uri = talloc_strdup(ctx, uri);
		ctx->args = talloc_strdup(ctx, args);
		ctx->curl = NULL;
		ctx->ret = -1;
		ctx->result = NULL;
	}
	return ctx;
}

static uint
append_result(char *in, uint size, uint nmemb, struct cm_submit_h_context *ctx)
{
	uint n;
	if (size < nmemb) {
		n = nmemb;
		nmemb = size;
		size = n;
	}
	for (n = 0; n < nmemb; n++) {
		if (ctx->result == NULL) {
			ctx->result = talloc_strndup(ctx, in, size);
		} else {
			ctx->result = talloc_strndup_append_buffer(ctx->result,
								   in +
								   n * size,
								   size);
		}
	}
	return n * size;
}

void
cm_submit_h_run(struct cm_submit_h_context *ctx)
{
	char *uri;
	if (ctx->curl != NULL) {
		curl_easy_cleanup(ctx->curl);
	}
	ctx->curl = curl_easy_init();
	if (ctx->curl != NULL) {
		if (strcasecmp(ctx->method, "GET") == 0) {
			uri = talloc_asprintf(ctx, "%s?%s",
					      ctx->uri, ctx->args);
			curl_easy_setopt(ctx->curl, CURLOPT_URL, uri);
		} else {
			curl_easy_setopt(ctx->curl, CURLOPT_URL, ctx->uri);
			curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS,
					 ctx->args);
		}
		talloc_free(ctx->result);
		curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION,
				 append_result);
		curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, ctx);
		ctx->ret = curl_easy_perform(ctx->curl);
	}
}

int
cm_submit_h_result_code(struct cm_submit_h_context *ctx)
{
	return ctx->ret;
}

const char *
cm_submit_h_results(struct cm_submit_h_context *ctx)
{
	return ctx->result;
}

#ifdef CM_SUBMIT_H_MAIN
int
main(int argc, char **argv)
{
	struct cm_submit_h_context *ctx;
	if (argc < 3) {
		printf("Usage: submit-h METHOD URI [ARGS]\n");
		return 1;
	}
	ctx = cm_submit_h_init(NULL, argv[1], argv[2],
			       (argc > 3) ? argv[3] : "");
	cm_submit_h_run(ctx);
	printf("%s", cm_submit_h_results(ctx));
	return cm_submit_h_result_code(ctx);
}
#endif
