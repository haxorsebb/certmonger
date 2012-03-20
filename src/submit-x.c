/*
 * Copyright (C) 2009,2010,2012 Red Hat, Inc.
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

#include <talloc.h>

#include <xmlrpc-c/client.h>
#include <xmlrpc-c/transport.h>

#include <krb5.h>

#include "certext.h"
#include "log.h"
#include "submit-e.h"
#include "submit-u.h"
#include "submit-x.h"

static char *
get_error_message(krb5_context ctx, krb5_error_code kcode)
{
	const char *ret;
#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
	ret = ctx ? krb5_get_error_message(ctx, kcode) : NULL;
	if (ret == NULL) {
		ret = error_message(kcode);
	}
#else
	ret = error_message(kcode);
#endif
	return strdup(ret);
}

char *
cm_submit_x_make_ccache(const char *ktname, const char *principal)
{
	krb5_context ctx;
	krb5_keytab keytab;
	krb5_ccache ccache;
	krb5_creds creds;
	krb5_principal princ;
	krb5_error_code kret;
	krb5_get_init_creds_opt gicopts, *gicoptsp;
	char tgs[LINE_MAX], *ret;

	kret = krb5_init_context(&ctx);
	if (kret != 0) {
		fprintf(stderr, "Error initializing Kerberos: %s.\n",
			ret = get_error_message(ctx, kret));
		return ret;
	}
	if (ktname != NULL) {
		kret = krb5_kt_resolve(ctx, ktname, &keytab);
	} else {
		kret = krb5_kt_default(ctx, &keytab);
	}
	if (kret != 0) {
		fprintf(stderr, "Error resolving keytab: %s.\n",
			ret = get_error_message(ctx, kret));
		return ret;
	}
	princ = NULL;
	if (principal != NULL) {
		kret = krb5_parse_name(ctx, principal, &princ);
		if (kret != 0) {
			fprintf(stderr, "Error parsing \"%s\": %s.\n",
				principal, ret = get_error_message(ctx, kret));
			return ret;
		}
	} else {
		kret = krb5_sname_to_principal(ctx, NULL, NULL,
					       KRB5_NT_SRV_HST, &princ);
		if (kret != 0) {
			fprintf(stderr, "Error building client name: %s.\n",
				ret = get_error_message(ctx, kret));
			return ret;
		}
	}
	strcpy(tgs, KRB5_TGS_NAME);
	snprintf(tgs + strlen(tgs), sizeof(tgs) - strlen(tgs), "/%.*s",
		 cm_submit_princ_realm_len(ctx, princ),
		 cm_submit_princ_realm_data(ctx, princ));
	snprintf(tgs + strlen(tgs), sizeof(tgs) - strlen(tgs), "@%.*s",
		 cm_submit_princ_realm_len(ctx, princ),
		 cm_submit_princ_realm_data(ctx, princ));
	memset(&creds, 0, sizeof(creds));
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
	memset(&gicopts, 0, sizeof(gicopts));
	gicoptsp = NULL;
	kret = krb5_get_init_creds_opt_alloc(ctx, &gicoptsp);
	if (kret != 0) {
		fprintf(stderr, "Internal error: %s.\n",
			ret = get_error_message(ctx, kret));
		return ret;
	}
#else
	krb5_get_init_creds_opt_init(&gicopts);
	gicoptsp = &gicopts;
#endif
	krb5_get_init_creds_opt_set_forwardable(gicoptsp, 1);
	kret = krb5_get_init_creds_keytab(ctx, &creds, princ, keytab,
					  0, tgs, gicoptsp);
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
	krb5_get_init_creds_opt_free(ctx, gicoptsp);
#endif
	if (kret != 0) {
		fprintf(stderr, "Error obtaining initial credentials: %s.\n",
			ret = get_error_message(ctx, kret));
		return ret;
	}
	ccache = NULL;
	kret = krb5_cc_resolve(ctx, "MEMORY:" PACKAGE_NAME "_submit",
			       &ccache);
	if (kret == 0) {
		kret = krb5_cc_initialize(ctx, ccache, creds.client);
	}
	if (kret != 0) {
		fprintf(stderr, "Error initializing credential cache: %s.\n",
			ret = get_error_message(ctx, kret));
		return ret;
	}
	kret = krb5_cc_store_cred(ctx, ccache, &creds);
	if (kret != 0) {
		fprintf(stderr,
			"Error storing creds in credential cache: %s.\n",
			ret = get_error_message(ctx, kret));
		return ret;
	}
	krb5_cc_close(ctx, ccache);
	krb5_kt_close(ctx, keytab);
	krb5_free_principal(ctx, princ);
	krb5_free_context(ctx);
	putenv("KRB5CCNAME=MEMORY:" PACKAGE_NAME "_submit");
	return NULL;
}

struct cm_submit_x_context {
	xmlrpc_env xenv;
	xmlrpc_server_info *server;
	struct xmlrpc_clientparms cparams;
	struct xmlrpc_curl_xportparms xparams;
	xmlrpc_client_transport *xtransport;
	xmlrpc_client *client;
	const char *method;
	xmlrpc_value *params, *namedarg, *results;
	int fault_occurred:1, fault_code;
	const char *fault_text;
};

struct cm_submit_x_context *
cm_submit_x_init(void *parent, const char *uri, const char *method,
		 const char *cainfo, const char *capath,
		 enum cm_submit_x_opt_negotiate negotiate,
		 enum cm_submit_x_opt_delegate delegate)
{
	struct cm_submit_x_context *ctx;
	ctx = talloc_ptrtype(parent, ctx);
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	xmlrpc_env_init(&ctx->xenv);
	xmlrpc_client_setup_global_const(&ctx->xenv);
	ctx->server = xmlrpc_server_info_new(&ctx->xenv, uri);
	if (ctx->server == NULL) {
		talloc_free(ctx);
		return NULL;
	}
	xmlrpc_server_info_set_user(&ctx->xenv, ctx->server, "", "");
	if (ctx->xenv.fault_occurred) {
		fprintf(stderr, "Fault %d faking up basic auth: (%s).\n",
			ctx->xenv.fault_code, ctx->xenv.fault_string);
		xmlrpc_env_clean(&ctx->xenv);
	}
	if (negotiate == cm_submit_x_negotiate_on) {
		xmlrpc_server_info_allow_auth_negotiate(&ctx->xenv,
							ctx->server);
		if (ctx->xenv.fault_occurred) {
			fprintf(stderr, "Fault %d turning on negotiate auth: "
				"(%s).\n",
				ctx->xenv.fault_code, ctx->xenv.fault_string);
			xmlrpc_env_clean(&ctx->xenv);
		}
	} else {
		xmlrpc_server_info_disallow_auth_negotiate(&ctx->xenv,
							   ctx->server);
		if (ctx->xenv.fault_occurred) {
			fprintf(stderr, "Fault %d turning off negotiate auth: "
				"(%s).\n",
				ctx->xenv.fault_code, ctx->xenv.fault_string);
			xmlrpc_env_clean(&ctx->xenv);
		}
	}

	memset(&ctx->xparams, 0, sizeof(ctx->xparams));
	ctx->xparams.cainfo = talloc_strdup(ctx, cainfo);
	ctx->xparams.capath = talloc_strdup(ctx, capath);
    
	/* Use a specially-crafted User-Agent value to pass along a
	 * Referer header so the request won't be rejected by the remote
	 * IPA server.
	 */
	ctx->xparams.user_agent = talloc_asprintf(ctx, "%s/%s\r\nReferer: %s\r\nX-Original-User-Agent:", PACKAGE_NAME, PACKAGE_VERSION, uri);

#ifdef HAVE_STRUCT_XMLRPC_CURL_XPORTPARMS_GSSAPI_DELEGATION
	if ((negotiate == cm_submit_x_negotiate_on) &&
	    (delegate == cm_submit_x_delegate_on)) {
		ctx->xparams.gssapi_delegation = TRUE;
	}
#endif
	(*xmlrpc_curl_transport_ops.create)(&ctx->xenv, 0,
					    PACKAGE_NAME,
					    PACKAGE_VERSION,
					    &ctx->xparams,
					    sizeof(ctx->xparams),
					    &ctx->xtransport);
	if (ctx->xenv.fault_occurred) {
		fprintf(stderr, "Fault %d: (%s).\n",
			ctx->xenv.fault_code, ctx->xenv.fault_string);
		xmlrpc_env_clean(&ctx->xenv);
	}
	if (ctx->xtransport != NULL) {
		memset(&ctx->cparams, 0, sizeof(ctx->cparams));
		ctx->cparams.transportOpsP = &xmlrpc_curl_transport_ops;
		ctx->cparams.transportP = ctx->xtransport;
		xmlrpc_client_create(&ctx->xenv,
				     XMLRPC_CLIENT_NO_FLAGS,
				     PACKAGE_NAME,
				     PACKAGE_VERSION,
				     &ctx->cparams, sizeof(ctx->cparams),
				     &ctx->client);
		if (ctx->client == NULL) {
			talloc_free(ctx);
		}
	}
	ctx->params = xmlrpc_array_new(&ctx->xenv);
	ctx->namedarg = xmlrpc_struct_new(&ctx->xenv);
	ctx->results = NULL;
	ctx->method = talloc_strdup(ctx, method);
	return ctx;
}

void
cm_submit_x_add_arg_s(struct cm_submit_x_context *ctx, const char *s)
{
	xmlrpc_value *arg;
	arg = xmlrpc_string_new(&ctx->xenv, s);
	if (arg != NULL) {
		xmlrpc_array_append_item(&ctx->xenv, ctx->params, arg);
	}
}

void
cm_submit_x_add_arg_as(struct cm_submit_x_context *ctx, const char **s)
{
	xmlrpc_value *arg, *str;
	int i;
	arg = xmlrpc_array_new(&ctx->xenv);
	if (arg != NULL) {
		for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
			str = xmlrpc_string_new(&ctx->xenv, s[i]);
			if (str != NULL) {
				xmlrpc_array_append_item(&ctx->xenv, arg, str);
			}
		}
		xmlrpc_array_append_item(&ctx->xenv, ctx->params, arg);
	}
}

void
cm_submit_x_add_arg_b(struct cm_submit_x_context *ctx, int b)
{
	xmlrpc_value *arg;
	arg = xmlrpc_bool_new(&ctx->xenv, b != 0);
	if (arg != NULL) {
		xmlrpc_array_append_item(&ctx->xenv, ctx->params, arg);
	}
}

void
cm_submit_x_add_named_arg_s(struct cm_submit_x_context *ctx,
			    const char *name, const char *s)
{
	xmlrpc_value *arg;
	arg = xmlrpc_string_new(&ctx->xenv, s);
	if (arg != NULL) {
		xmlrpc_struct_set_value(&ctx->xenv, ctx->namedarg, name, arg);
	}
}

void
cm_submit_x_add_named_arg_b(struct cm_submit_x_context *ctx,
			    const char *name, int b)
{
	xmlrpc_value *arg;
	arg = xmlrpc_bool_new(&ctx->xenv, b != 0);
	if (arg != NULL) {
		xmlrpc_struct_set_value(&ctx->xenv, ctx->namedarg, name, arg);
	}
}

void
cm_submit_x_run(struct cm_submit_x_context *ctx)
{
	if (xmlrpc_struct_size(&ctx->xenv, ctx->namedarg) > 0) {
		xmlrpc_array_append_item(&ctx->xenv,
					 ctx->params,
					 ctx->namedarg);
	}
	ctx->results = NULL;
	xmlrpc_client_call2(&ctx->xenv,
			    ctx->client,
			    ctx->server,
			    ctx->method,
			    ctx->params,
			    &ctx->results);
	if (ctx->xenv.fault_occurred) {
		fprintf(stderr, "Fault %d: (%s).\n",
			ctx->xenv.fault_code, ctx->xenv.fault_string);
		ctx->fault_occurred = TRUE;
		ctx->fault_code = ctx->xenv.fault_code;
		ctx->fault_text = talloc_strdup(ctx, ctx->xenv.fault_string);
		xmlrpc_env_clean(&ctx->xenv);
	} else {
		ctx->fault_occurred = FALSE;
		ctx->fault_code = 0;
		ctx->fault_text = NULL;
	}
}

int
cm_submit_x_has_results(struct cm_submit_x_context *ctx)
{
	return (ctx->results != NULL) ? 0 : -1;
}

int
cm_submit_x_faulted(struct cm_submit_x_context *ctx)
{
	return ctx->fault_occurred ? 0 : -1;
}

int
cm_submit_x_fault_code(struct cm_submit_x_context *ctx)
{
	return ctx->fault_occurred ? ctx->fault_code : -1;
}

const char *
cm_submit_x_fault_text(struct cm_submit_x_context *ctx)
{
	return ctx->fault_occurred ? ctx->fault_text : NULL;
}

int
cm_submit_x_get_bss(struct cm_submit_x_context *ctx,
		    int *b, char **s1, char **s2)
{
	const char *p;
	xmlrpc_bool boo;
	xmlrpc_value *arg;
	*b = 0;
	*s1 = NULL;
	*s2 = NULL;
	if (xmlrpc_value_type(ctx->results) != XMLRPC_TYPE_ARRAY) {
		return -1;
	}
	xmlrpc_array_read_item(&ctx->xenv, ctx->results, 0, &arg);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	} else {
		xmlrpc_read_bool(&ctx->xenv, arg, &boo);
		if (ctx->xenv.fault_occurred) {
			xmlrpc_env_clean(&ctx->xenv);
			return -1;
		}
		*b = boo;
	}
	xmlrpc_array_read_item(&ctx->xenv, ctx->results, 1, &arg);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	} else {
		xmlrpc_read_string(&ctx->xenv, arg, &p);
		if (ctx->xenv.fault_occurred) {
			xmlrpc_env_clean(&ctx->xenv);
			return -1;
		}
		*s1 = talloc_strdup(ctx, p);
	}
	xmlrpc_array_read_item(&ctx->xenv, ctx->results, 2, &arg);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	} else {
		xmlrpc_read_string(&ctx->xenv, arg, &p);
		if (ctx->xenv.fault_occurred) {
			xmlrpc_env_clean(&ctx->xenv);
			return -1;
		}
		*s2 = talloc_strdup(ctx, p);
	}
	return 0;
}

int
cm_submit_x_get_b(struct cm_submit_x_context *ctx, int idx, int *b)
{
	xmlrpc_bool boo;
	xmlrpc_value *arg;
	*b = 0;
	if (xmlrpc_value_type(ctx->results) != XMLRPC_TYPE_ARRAY) {
		return -1;
	}
	xmlrpc_array_read_item(&ctx->xenv, ctx->results, idx, &arg);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	} else {
		xmlrpc_read_bool(&ctx->xenv, arg, &boo);
		if (ctx->xenv.fault_occurred) {
			xmlrpc_env_clean(&ctx->xenv);
			return -1;
		}
		*b = boo;
	}
	return 0;
}

int
cm_submit_x_get_s(struct cm_submit_x_context *ctx, int idx, char **s)
{
	const char *p;
	xmlrpc_value *arg;
	*s = NULL;
	if (xmlrpc_value_type(ctx->results) != XMLRPC_TYPE_ARRAY) {
		return -1;
	}
	xmlrpc_array_read_item(&ctx->xenv, ctx->results, idx, &arg);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	} else {
		xmlrpc_read_string(&ctx->xenv, arg, &p);
		if (ctx->xenv.fault_occurred) {
			xmlrpc_env_clean(&ctx->xenv);
			return -1;
		}
		*s = talloc_strdup(ctx, p);
	}
	return 0;
}

static xmlrpc_value *
cm_submit_x_get_struct(struct cm_submit_x_context *ctx)
{
	int i;
	xmlrpc_value *arg;
	if (xmlrpc_value_type(ctx->results) == XMLRPC_TYPE_STRUCT) {
		return ctx->results;
	}
	if (xmlrpc_value_type(ctx->results) != XMLRPC_TYPE_ARRAY) {
		return NULL;
	}
	for (i = 0;; i++) {
		xmlrpc_array_read_item(&ctx->xenv, ctx->results, i, &arg);
		if (arg == NULL) {
			break;
		}
		if (ctx->xenv.fault_occurred) {
			xmlrpc_env_clean(&ctx->xenv);
			return NULL;
		}
		if (xmlrpc_value_type(arg) == XMLRPC_TYPE_STRUCT) {
			return arg;
		}
	}
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return NULL;
	}
	return NULL;
}

int
cm_submit_x_get_named_n(struct cm_submit_x_context *ctx,
			const char *name, int *n)
{
	int i;
	xmlrpc_value *arg, *val, *result;
	*n = 0;
	arg = cm_submit_x_get_struct(ctx);
	if (arg == NULL) {
		return -1;
	}
	xmlrpc_struct_find_value(&ctx->xenv, arg, name, &val);
	if (val == NULL) {
		xmlrpc_struct_find_value(&ctx->xenv, arg, "result", &result);
		if (result == NULL) {
			return -1;
		}
		if (xmlrpc_value_type(result) != XMLRPC_TYPE_STRUCT) {
			return -1;
		}
		xmlrpc_struct_find_value(&ctx->xenv, result, name, &val);
		if (val == NULL) {
			return -1;
		}
	}
	if (xmlrpc_value_type(val) != XMLRPC_TYPE_INT) {
		fprintf(stderr, "Expected value \"%s\" is not an integer.\n",
			name);
		return -1;
	}
	xmlrpc_read_int(&ctx->xenv, val, &i);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	}
	*n = i;
	return 0;
}

int
cm_submit_x_get_named_b(struct cm_submit_x_context *ctx,
			const char *name, int *b)
{
	xmlrpc_bool boo;
	xmlrpc_value *arg, *val, *result;
	*b = 0;
	arg = cm_submit_x_get_struct(ctx);
	if (arg == NULL) {
		return -1;
	}
	xmlrpc_struct_find_value(&ctx->xenv, arg, name, &val);
	if (val == NULL) {
		xmlrpc_struct_find_value(&ctx->xenv, arg, "result", &result);
		if (result == NULL) {
			return -1;
		}
		if (xmlrpc_value_type(result) != XMLRPC_TYPE_STRUCT) {
			return -1;
		}
		xmlrpc_struct_find_value(&ctx->xenv, result, name, &val);
		if (val == NULL) {
			return -1;
		}
	}
	if (xmlrpc_value_type(val) != XMLRPC_TYPE_BOOL) {
		fprintf(stderr, "Expected value \"%s\" is not a boolean.\n",
			name);
		return -1;
	}
	xmlrpc_read_bool(&ctx->xenv, val, &boo);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	}
	*b = boo;
	return 0;
}

int
cm_submit_x_get_named_s(struct cm_submit_x_context *ctx,
			const char *name, char **s)
{
	const char *p;
	char *tmp;
	const unsigned char *binary;
	size_t length;
	xmlrpc_value *arg, *val, *result;
	*s = NULL;
	arg = cm_submit_x_get_struct(ctx);
	if (arg == NULL) {
		return -1;
	}
	xmlrpc_struct_find_value(&ctx->xenv, arg, name, &val);
	if (val == NULL) {
		xmlrpc_struct_find_value(&ctx->xenv, arg, "result", &result);
		if (result == NULL) {
			return -1;
		}
		if (xmlrpc_value_type(result) != XMLRPC_TYPE_STRUCT) {
			return -1;
		}
		xmlrpc_struct_find_value(&ctx->xenv, result, name, &val);
		if (val == NULL) {
			return -1;
		}
	}
	if (xmlrpc_value_type(val) != XMLRPC_TYPE_STRING) {
		if (xmlrpc_value_type(val) == XMLRPC_TYPE_BASE64) {
			xmlrpc_read_base64(&ctx->xenv, val, &length, &binary);
			tmp = talloc_strndup(ctx, (const char *) binary,
					     length);
			if (strlen(tmp) == length) {
				*s = tmp;
				return 0;
			} else {
				fprintf(stderr,
					"Expected value \"%s\" is "
					"not a string.\n",
					name);
				return -1;
			}
		} else {
			fprintf(stderr,
				"Expected value \"%s\" is not a string.\n",
				name);
			return -1;
		}
	}
	xmlrpc_read_string(&ctx->xenv, val, &p);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	}
	*s = talloc_strdup(ctx, p);
	return 0;
}

#ifdef CM_SUBMIT_X_MAIN
int
main(int argc, char **argv)
{
	int i, j, c, ret, k5 = FALSE, make_ccache = TRUE;
	int64_t i8;
	int32_t i32;
	const char *uri = NULL, *method = NULL, *ktname = NULL, *kpname = NULL;
	const char *s, *cainfo = NULL, *capath = NULL;
	char *csr, *p, *skey, *sval, *s1, *s2;
	struct cm_submit_x_context *ctx;
	xmlrpc_value *arg, *key, *val;
	xmlrpc_bool boo;

	cm_log_set_method(cm_log_stderr);
	while ((c = getopt(argc, argv, "s:m:kKt:p:c:")) != -1) {
		switch (c) {
		case 's':
			uri = optarg;
			break;
		case 'm':
			method = optarg;
			break;
		case 'p':
			kpname = optarg;
			break;
		case 't':
			ktname = optarg;
			break;
		case 'k':
			k5 = TRUE;
			break;
		case 'K':
			make_ccache = FALSE;
			break;
		case 'C':
			capath = optarg;
			break;
		case 'c':
			cainfo = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-s serverURI] [-m method] "
				"[-k [-K]] [-t keytab] [-p principal] "
				"[-C capath] [-c cainfo]\n"
				"Examples:\n"
				"           -s http://localhost:51235/\n"
				"           -m wait_for_cert\n"
				"           -t /etc/krb5.keytab\n",
				strchr(argv[0], '/') ?
				strrchr(argv[0], '/') + 1 :
				argv[0]);
			return CM_STATUS_UNCONFIGURED;
			break;
		}
	}
	if ((uri == NULL) || (method == NULL)) {
		fprintf(stderr,
			"Usage: %s [-s serverURI] [-m method] "
			"[-k [-K]] [-t keytab] [-p principal] "
			"[-C capath] [-c cainfo]\n"
			"Examples:\n"
			"           -s http://localhost:51235/\n"
			"           -m wait_for_cert\n"
			"           -t /etc/krb5.keytab\n",
			strchr(argv[0], '/') ?
			strrchr(argv[0], '/') + 1 :
			argv[0]);
		return CM_STATUS_UNCONFIGURED;
	}
	ret = CM_STATUS_UNREACHABLE;

	/* Read the CSR from the environment, or from the command-line. */
	csr = getenv(CM_SUBMIT_CSR_ENV);
	if (csr == NULL) {
		csr = cm_submit_u_from_file((optind < argc) ?
					    argv[optind++] : NULL);
	}

	/* Clean up the CSR. */
	if (strcmp(method, "wait_for_cert") == 0) {
		/* certmaster rewrites the incoming request to its cache
		 * previously-received requests, and in doing so uses a
		 * different PEM header than the one we default to using.  So
		 * turn any "NEW CERTIFICATE REQUEST" notes into "CERTIFICATE
		 * REQUEST" before sending them. */
		while ((p = strstr(csr, "NEW CERTIFICATE REQUEST")) != NULL) {
			memmove(p, p + 4, strlen(p + 4) + 1);
		}
	}
	if (strcmp(method, "cert_request") == 0) {
		/* IPA just wants base64-encoded binary data, no whitepace */
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
	}

	/* Initialize for XML-RPC. */
	ctx = cm_submit_x_init(NULL, uri, method, cainfo, capath,
			       k5 || (kpname != NULL) || (ktname != NULL) ?
			       cm_submit_x_negotiate_on :
			       cm_submit_x_negotiate_off,
			       k5 || (kpname != NULL) || (ktname != NULL) ?
			       cm_submit_x_delegate_on :
			       cm_submit_x_delegate_off);
	if (ctx == NULL) {
		fprintf(stderr, "Error setting up for XMLRPC.\n");
		return CM_STATUS_UNCONFIGURED;
	}

	/* Both servers take the CSR, in their preferred format, first. */
	cm_submit_x_add_arg_s(ctx, csr);

	/* Maybe we need a ccache. */
	if (k5 || (kpname != NULL) || (ktname != NULL)) {
		if (!make_ccache ||
		    (cm_submit_x_make_ccache(ktname, kpname) == 0)) {
			k5 = TRUE;
		}
	}

	/* Add additional arguments as dict values. */
	for (i = optind; i < argc; i++) {
		skey = strdup(argv[i]);
		sval = skey + strcspn(skey, "=");
		if (*sval != '\0') {
			*sval++ = '\0';
		}
		if (strcasecmp(sval, "true") == 0) {
			cm_submit_x_add_named_arg_b(ctx, skey, 1);
		} else
		if (strcasecmp(sval, "false") == 0) {
			cm_submit_x_add_named_arg_b(ctx, skey, 0);
		} else {
			cm_submit_x_add_named_arg_s(ctx, skey, sval);
		}
	}

	/* Submit the request. */
	cm_submit_x_run(ctx);

	/* Check the results. */
	if (cm_submit_x_has_results(ctx) == 0) {
		for (i = 0;
		     (xmlrpc_value_type(ctx->results) == XMLRPC_TYPE_ARRAY) &&
		     (i < xmlrpc_array_size(&ctx->xenv, ctx->results));
		     i++) {
			xmlrpc_array_read_item(&ctx->xenv, ctx->results,
					       i, &arg);
			if (ctx->xenv.fault_occurred) {
				fprintf(stderr, "Fault %d: (%s).\n",
					ctx->xenv.fault_code,
					ctx->xenv.fault_string);
				xmlrpc_env_clean(&ctx->xenv);
			} else {
				switch (xmlrpc_value_type(arg)) {
				case XMLRPC_TYPE_BOOL:
					xmlrpc_read_bool(&ctx->xenv, arg, &boo);
					printf("b: %s\n",
					       boo ? "true" : "false");
					break;
				case XMLRPC_TYPE_STRING:
					xmlrpc_read_string(&ctx->xenv, arg, &s);
					printf("s: %s\n", s);
					break;
				case XMLRPC_TYPE_I8:
					xmlrpc_read_i8(&ctx->xenv, arg, &i8);
					printf("n: %lld\n", (long long) i8);
					break;
				case XMLRPC_TYPE_INT:
					xmlrpc_read_int(&ctx->xenv, arg, &i32);
					printf("n: %ld\n", (long) i32);
					break;
				case XMLRPC_TYPE_STRUCT:
					for (j = 0;
					     j < xmlrpc_struct_size(&ctx->xenv,
								    arg);
					     j++) {
						xmlrpc_struct_read_member(&ctx->xenv, arg, j,
									  &key, &val);
						xmlrpc_read_string(&ctx->xenv, key, &s);
						if (ctx->xenv.fault_occurred) {
							fprintf(stderr, "Fault %d: (%s).\n",
								ctx->xenv.fault_code, ctx->xenv.fault_string);
							xmlrpc_env_clean(&ctx->xenv);
						} else {
							skey = (char *) s;
							switch (xmlrpc_value_type(val)) {
							case XMLRPC_TYPE_BOOL:
								xmlrpc_read_bool(&ctx->xenv, val, &boo);
								printf("%s: b: %s\n", skey,
								       boo ? "true" : "false");
								break;
							case XMLRPC_TYPE_STRING:
								xmlrpc_read_string(&ctx->xenv, arg, &s);
								printf("%s: s: %s\n", skey, s);
								break;
							case XMLRPC_TYPE_I8:
								xmlrpc_read_i8(&ctx->xenv, val, &i8);
								printf("%s: n: %lld\n", skey, (long long) i8);
								break;
							case XMLRPC_TYPE_INT:
								xmlrpc_read_int(&ctx->xenv, val, &i32);
								printf("%s: n: %ld\n", skey, (long) i32);
								break;
							default:
								break;
							}
						}
					}
					break;
				default:
					break;
				}
				if (ctx->xenv.fault_occurred) {
					fprintf(stderr, "Fault %d: (%s).\n",
						ctx->xenv.fault_code, ctx->xenv.fault_string);
					xmlrpc_env_clean(&ctx->xenv);
				}
			}
		}
	}

	/* Try formatted output, specific. */
	if ((cm_submit_x_has_results(ctx) == 0) &&
	    (strcmp(method, "wait_for_cert") == 0)) {
		if (cm_submit_x_get_bss(ctx, &i, &s1, &s2) == 0) {
			printf("BSS: OK\nb: %s\ns1 = \"%s\"\ns2 = \"%s\"\n",
			       i ? "true" : "false", s1, s2);
		}
	}
	if ((cm_submit_x_has_results(ctx) == 0) &&
	    (strcmp(method, "cert_request") == 0)) {
		if (cm_submit_x_get_named_n(ctx, "status", &i) == 0) {
			printf("Status: %d\n", i);
		}
		if (cm_submit_x_get_named_s(ctx, "certificate", &s1) == 0) {
			printf("Certificate: \"%s\"\n", s1);
		}
	}

	return ret;
}
#endif
