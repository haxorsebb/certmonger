/*
 * Copyright (C) 2010,2011,2012,2015 Red Hat, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include <curl/curl.h>

#include <popt.h>

#include "log.h"
#include "submit-e.h"
#include "submit-h.h"

#if HAVE_DECL_CURLOPT_KEYPASSWD
#define CM_CURLOPT_PKI_PASSWD CURLOPT_KEYPASSWD
#else
#if HAVE_DECL_CURLOPT_SSLKEYPASSWD
#define CM_CURLOPT_PKI_PASSWD CURLOPT_SSLKEYPASSWD
#else
#if HAVE_DECL_CURLOPT_SSLCERTPASSWD
#define CM_CURLOPT_PKI_PASSWD CURLOPT_SSLCERTPASSWD
#endif
#endif
#endif

struct cm_submit_h_context {
	int ret;
	long response_code;
	char *method, *uri, *args, *accept, *ctype, *cainfo, *capath, *result;
	int result_length;
	char *sslcert, *sslkey, *sslpass;
	enum cm_submit_h_opt_negotiate negotiate;
	enum cm_submit_h_opt_delegate negotiate_delegate;
	enum cm_submit_h_opt_clientauth client_auth;
	enum cm_submit_h_opt_env_modify modify_env;
	enum cm_submit_h_opt_curl_verbose verbose;
	CURL *curl;
};

struct cm_submit_h_context *
cm_submit_h_init(void *parent,
		 const char *method, const char *uri, const char *args,
		 const char *content_type, const char *accept,
		 const char *cainfo, const char *capath,
		 const char *sslcert, const char *sslkey, const char *sslpass,
		 enum cm_submit_h_opt_negotiate neg,
		 enum cm_submit_h_opt_delegate del,
		 enum cm_submit_h_opt_clientauth cli,
		 enum cm_submit_h_opt_env_modify env,
		 enum cm_submit_h_opt_curl_verbose verbose)
{
	struct cm_submit_h_context *ctx;
	ctx = talloc_ptrtype(parent, ctx);
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(*ctx));
		ctx->method = talloc_strdup(ctx, method);
		ctx->uri = talloc_strdup(ctx, uri);
		ctx->args = args ? talloc_strdup(ctx, args) : NULL;
		ctx->ctype = content_type ?
			     talloc_strdup(ctx, content_type) :
			     NULL;
		ctx->accept = accept ? talloc_strdup(ctx, accept) : NULL;
		ctx->cainfo = cainfo ? talloc_strdup(ctx, cainfo) : NULL;
		ctx->capath = capath ? talloc_strdup(ctx, capath) : NULL;
		ctx->sslcert = sslcert ? talloc_strdup(ctx, sslcert) : NULL;
		ctx->sslkey = sslkey ? talloc_strdup(ctx, sslkey) : NULL;
		ctx->sslpass = sslpass ? talloc_strdup(ctx, sslpass) : NULL;
		ctx->curl = NULL;
		ctx->ret = -1;
		ctx->response_code = 0;
		ctx->result = NULL;
		ctx->negotiate = neg;
		ctx->negotiate_delegate = del;
		ctx->client_auth = cli;
		ctx->modify_env = env;
		ctx->verbose = verbose;
	}
	return ctx;
}

static uint
append_result(char *in, uint size, uint nmemb, struct cm_submit_h_context *ctx)
{
	uint n;
	char *data;

	if (size < nmemb) {
		n = nmemb;
		nmemb = size;
		size = n;
	}
	for (n = 0; n < nmemb; n++) {
		data = talloc_realloc_size(ctx, ctx->result, ctx->result_length + size + 1);
		if (data == NULL) {
			return n * size;
		}
		memcpy(data + ctx->result_length, in + n * size, size);
		data[ctx->result_length + size] = '\0';
		ctx->result = data;
		ctx->result_length += size;
	}
	return n * size;
}

void
cm_submit_h_run(struct cm_submit_h_context *ctx)
{
	struct curl_slist *headers = NULL;
	char *uri, *header;
	if (ctx->curl != NULL) {
		curl_easy_cleanup(ctx->curl);
	}
	if ((ctx->modify_env == cm_submit_h_env_modify_on) &
	    (ctx->cainfo != NULL)) {
		setenv("SSL_DIR", ctx->cainfo, 1);
	}
	ctx->curl = curl_easy_init();
	if (ctx->curl != NULL) {
		if (ctx->verbose) {
			curl_easy_setopt(ctx->curl,
					 CURLOPT_VERBOSE,
					 1L);
		}
		if ((ctx->cainfo != NULL) || (ctx->capath != NULL)) {
			curl_easy_setopt(ctx->curl,
					 CURLOPT_SSL_VERIFYPEER,
					 1L);
			curl_easy_setopt(ctx->curl,
					 CURLOPT_SSL_VERIFYHOST,
					 2L);
		}
		if (ctx->cainfo != NULL) {
			curl_easy_setopt(ctx->curl,
					 CURLOPT_CAINFO,
					 ctx->cainfo);
		}
		if (ctx->capath != NULL) {
			curl_easy_setopt(ctx->curl,
					 CURLOPT_CAPATH,
					 ctx->capath);
		}
		if (strcasecmp(ctx->method, "GET") == 0) {
			uri = talloc_asprintf(ctx, "%s%s%s",
					      ctx->uri,
					      ctx->args ? "?" : "",
					      ctx->args ? ctx->args : "");
			curl_easy_setopt(ctx->curl, CURLOPT_URL, uri);
			curl_easy_setopt(ctx->curl, CURLOPT_HTTPGET, 1L);
		} else {
			curl_easy_setopt(ctx->curl, CURLOPT_URL, ctx->uri);
			curl_easy_setopt(ctx->curl, CURLOPT_HTTPGET, 0L);
			if ((ctx->args != NULL) && (strlen(ctx->args) > 0)) {
				curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS,
						 ctx->args);
			}
		}
		if (ctx->negotiate == cm_submit_h_negotiate_on) {
#if defined(CURLOPT_HTTPAUTH) && defined(CURLAUTH_GSSNEGOTIATE)
			curl_easy_setopt(ctx->curl,
					 CURLOPT_HTTPAUTH,
					 CURLAUTH_GSSNEGOTIATE);
#else
			cm_log(-1,
			       "warning: libcurl doesn't appear to support "
			       "Negotiate authentication, continuing\n");
#endif
#if defined(CURLOPT_GSSAPI_DELEGATION) && defined(CURLGSSAPI_DELEGATION_FLAG)
			/* The default before CURLOPT_GSSAPI_DELEGATION existed
			 * was CURLGSSAPI_DELEGATION_FLAG, so we should be fine
			 * if it's not defined. */
			curl_easy_setopt(ctx->curl,
					 CURLOPT_GSSAPI_DELEGATION,
					 ctx->negotiate_delegate == cm_submit_h_delegate_on ?
					 CURLGSSAPI_DELEGATION_FLAG :
					 CURLGSSAPI_DELEGATION_NONE);
#endif
		} else
		if (ctx->client_auth == cm_submit_h_clientauth_on) {
			curl_easy_setopt(ctx->curl,
					 CURLOPT_HTTPAUTH,
					 CURLAUTH_NONE);
			if (ctx->sslcert != NULL) {
				curl_easy_setopt(ctx->curl,
						 CURLOPT_SSLCERT,
						 ctx->sslcert);
			}
			if (ctx->sslkey != NULL) {
				curl_easy_setopt(ctx->curl,
						 CURLOPT_SSLKEY,
						 ctx->sslkey);
			}
			if (ctx->sslpass != NULL) {
				curl_easy_setopt(ctx->curl,
						 CM_CURLOPT_PKI_PASSWD,
						 ctx->sslpass);
			}
		} else {
			curl_easy_setopt(ctx->curl,
					 CURLOPT_FOLLOWLOCATION,
					 1);
			curl_easy_setopt(ctx->curl,
					 CURLOPT_HTTPAUTH,
					 CURLAUTH_NONE);
		}
		if (ctx->accept != NULL) {
			header = talloc_asprintf(ctx, "Accept: %s",
						 ctx->accept);
			if (header != NULL) {
				headers = curl_slist_append(headers,
							    header);
			}
		}
		if (ctx->ctype != NULL) {
			header = talloc_asprintf(ctx, "Content-Type: %s",
						 ctx->ctype);
			if (header != NULL) {
				headers = curl_slist_append(headers,
							    header);
			}
		}
		curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION,
				 append_result);
		curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, ctx);
		if (ctx->result != NULL) {
			talloc_free(ctx->result);
			ctx->result = NULL;
		}
		ctx->ret = curl_easy_perform(ctx->curl);
		curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE,
				  &ctx->response_code);
		if (headers != NULL) {
			curl_slist_free_all(headers);
		}
	}
}

int
cm_submit_h_response_code(struct cm_submit_h_context *ctx)
{
	return ctx->response_code;
}
int
cm_submit_h_result_code(struct cm_submit_h_context *ctx)
{
	return ctx->ret;
}
const char *
cm_submit_h_result_code_text(struct cm_submit_h_context *ctx)
{
	return curl_easy_strerror(ctx->ret);
}

const char *
cm_submit_h_results(struct cm_submit_h_context *ctx, int *length)
{
	if (length != NULL) {
		*length = ctx->result_length;
	}
	return ctx->result;
}

const char *
cm_submit_h_result_type(struct cm_submit_h_context *ctx)
{
	char *ret = NULL;
	if (ctx->curl != NULL) {
		if (curl_easy_getinfo(ctx->curl, CURLINFO_CONTENT_TYPE,
				      &ret) != CURLE_OK) {
			ret = NULL;
		}
	}
	return ret;
}

#ifdef CM_SUBMIT_H_MAIN
int
main(int argc, const char **argv)
{
	struct cm_submit_h_context *ctx;
	struct stat st;
	enum cm_submit_h_opt_negotiate negotiate;
	enum cm_submit_h_opt_delegate negotiate_delegate;
	enum cm_submit_h_opt_clientauth clientauth;
	int c, fd, l, verbose = 0, length = 0;
	char *ctype, *accept, *capath, *cainfo, *sslcert, *sslkey, *sslpass;
	char *pinfile;
	const char *method, *url;
	poptContext pctx;
	struct poptOption popts[] = {
		{"accept-type", 'a', POPT_ARG_STRING, &accept, 0, "acceptable response content-type", NULL},
		{"capath", 'C', POPT_ARG_STRING, &capath, 0, "root certificate directory", "DIRECTORY"},
		{"cainfo", 'c', POPT_ARG_STRING, &cainfo, 0, "root certificate info", NULL},
		{"negotiate", 'N', POPT_ARG_NONE, NULL, 'N', "use Negotiate", NULL},
		{"delegate", 'D', POPT_ARG_NONE, NULL, 'D', "use Negotiate with delegation", NULL},
		{"sslcert", 'k', POPT_ARG_STRING, &sslcert, 'k', "use client authentication with cert", "CERT"},
		{"sslkey", 'K', POPT_ARG_STRING, &sslkey, 'K', "use client authentication with key", "KEY"},
		{"pinfile", 'p', POPT_ARG_STRING, &pinfile, 'p', "client authentication key pinfile", "FILENAME"},
		{"pin", 'P', POPT_ARG_STRING, &sslpass, 0, "client authentication key pin", NULL},
		{"content-type", 't', POPT_ARG_STRING, &ctype, 0, "client data content-type", NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};
	ctype = NULL;
	accept = NULL;
	capath = NULL;
	cainfo = NULL;
	sslcert = NULL;
	sslkey = NULL;
	sslpass = NULL;
	pinfile = NULL;
	negotiate = cm_submit_h_negotiate_off;
	negotiate_delegate = cm_submit_h_delegate_off;
	clientauth = cm_submit_h_clientauth_off;

	pctx = poptGetContext("submit-h", argc, argv, popts, 0);
	if (pctx == NULL) {
		exit(1);
	}
	poptSetOtherOptionHelp(pctx, "[options...] METHOD URL");
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 'N':
			negotiate = cm_submit_h_negotiate_on;
			break;
		case 'D':
			negotiate = cm_submit_h_negotiate_on;
			negotiate_delegate = cm_submit_h_delegate_on;
			break;
		case 'k':
			clientauth = cm_submit_h_clientauth_on;
			break;
		case 'K':
			clientauth = cm_submit_h_clientauth_on;
			break;
		case 'p':
			if (pinfile != NULL) {
				fd = open(pinfile, O_RDONLY);
				if (fd != -1) {
					if ((fstat(fd, &st) == 0) && (st.st_size > 0)) {
						sslpass = malloc(st.st_size + 1);
						if (sslpass != NULL) {
							if (read(fd, sslpass, st.st_size) != -1) {
								sslpass[st.st_size] = '\0';
								l = strcspn(sslpass, "\r\n");
								if (l != 0) {
									sslpass[l] = '\0';
								}
							} else {
								fprintf(stderr, "Error reading \"%s\": %s.\n", pinfile, strerror(errno));
								exit(1);
							}
						}
					} else {
						fprintf(stderr, "Error determining size of \"%s\": %s.\n", pinfile, strerror(errno));
						exit(1);
					}
					close(fd);
				} else {
					fprintf(stderr, "Error reading PIN from \"%s\": %s.\n", pinfile, strerror(errno));
					exit(1);
				}
			}
			break;
		case 'v':
			verbose++;
			break;
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}
	method = poptGetArg(pctx);
	url = poptGetArg(pctx);
	if ((method == NULL) || (url == NULL)) {
		printf("Missing a required argument.\n");
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}

	ctx = cm_submit_h_init(NULL, method, url, poptGetArg(pctx),
			       ctype, accept,
			       cainfo, capath, sslcert, sslkey, sslpass,
			       negotiate, negotiate_delegate,
			       clientauth, cm_submit_h_env_modify_on,
			       verbose ?
			       cm_submit_h_curl_verbose_on :
			       cm_submit_h_curl_verbose_off);
	cm_submit_h_run(ctx);
	if (cm_submit_h_results(ctx, &length) != NULL) {
		printf("%.*s", length, cm_submit_h_results(ctx, NULL));
	}
	if (cm_submit_h_result_code(ctx) != 0) {
		fflush(stdout);
		fprintf(stderr, "libcurl error %d:%s\n",
			cm_submit_h_result_code(ctx),
			cm_submit_h_result_code_text(ctx));
	}
	return cm_submit_h_result_code(ctx);
}
#endif
