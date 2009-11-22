/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#include <xmlrpc-c/client.h>
#include <xmlrpc-c/transport.h>

#include <krb5.h>

#include "submit-e.h"

static int
cm_submit_x_make_ccache(const char *ktname, const char *principal)
{
	krb5_context ctx;
	krb5_keytab keytab;
	krb5_ccache ccache;
	krb5_creds creds;
	krb5_principal princ;
	krb5_error_code kret;
	char tgs[LINE_MAX];

	kret = krb5_init_context(&ctx);
	if (kret != 0) {
		printf("Error initializing Kerberos: %s.\n",
		       error_message(kret));
		return kret;
	}
	if (ktname != NULL) {
		kret = krb5_kt_resolve(ctx, ktname, &keytab);
	} else {
		kret = krb5_kt_default(ctx, &keytab);
	}
	if (kret != 0) {
		printf("Error resolving keytab: %s.\n",
		       error_message(kret));
		return kret;
	}
	princ = NULL;
	if (principal != NULL) {
		kret = krb5_parse_name(ctx, principal, &princ);
		if (kret != 0) {
			printf("Error parsing \"%s\": %s.\n", principal,
			       error_message(kret));
			return kret;
		}
	} else {
		kret = krb5_sname_to_principal(ctx, NULL, NULL,
					       KRB5_NT_SRV_HST, &princ);
		if (kret != 0) {
			printf("Error building client name: %s.\n",
			       error_message(kret));
			return kret;
		}
	}
	strcpy(tgs, KRB5_TGS_NAME);
	snprintf(tgs + strlen(tgs), sizeof(tgs) - strlen(tgs), "/%.*s",
		 (krb5_princ_realm(ctx, princ))->length,
		 (krb5_princ_realm(ctx, princ))->data);
	snprintf(tgs + strlen(tgs), sizeof(tgs) - strlen(tgs), "@%.*s",
		 (krb5_princ_realm(ctx, princ))->length,
		 (krb5_princ_realm(ctx, princ))->data);
	memset(&creds, 0, sizeof(creds));
	kret = krb5_get_init_creds_keytab(ctx, &creds, princ, keytab,
					  0, tgs, NULL);
	if (kret != 0) {
		printf("Error obtaining initial credentials: %s.\n",
		       error_message(kret));
		return kret;
	}
	ccache = NULL;
	kret = krb5_cc_resolve(ctx, "MEMORY:" PACKAGE_NAME "_submit",
			       &ccache);
	if (kret == 0) {
		kret = krb5_cc_initialize(ctx, ccache, creds.client);
	}
	if (kret != 0) {
		printf("Error initializing credential cache: %s.\n",
		       error_message(kret));
		return kret;
	}
	kret = krb5_cc_store_cred(ctx, ccache, &creds);
	if (kret != 0) {
		printf("Error storing creds in credential cache: %s.\n",
		       error_message(kret));
		return kret;
	}
	krb5_cc_close(ctx, ccache);
	putenv("KRB5CCNAME=MEMORY:" PACKAGE_NAME "_submit");
	return 0;
}

static char *
my_stpcpy(char *dest, char *src)
{
	size_t len;
	len = strlen(src);
	memcpy(dest, src, len);
	dest[len] = '\0';
	return dest + len;
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
};

struct cm_submit_x_context *
cm_submit_x_init(void *parent, const char *uri, const char *method,
		 const char *cainfo, const char *capath,
		 int negotiate)
{
	struct cm_submit_x_context *ctx;
	ctx = talloc_ptrtype(parent, ctx);
	if (ctx == NULL) {
		return NULL;
	}
	memset(&ctx->xenv, 0, sizeof(ctx->xenv));
	xmlrpc_env_init(&ctx->xenv);
	xmlrpc_client_setup_global_const(&ctx->xenv);
	ctx->server = xmlrpc_server_info_new(&ctx->xenv, uri);
	if (ctx->server == NULL) {
		talloc_free(ctx);
		return NULL;
	}
	xmlrpc_server_info_set_user(&ctx->xenv, ctx->server, "", "");
	if (ctx->xenv.fault_occurred) {
		printf("Fault %d faking up basic auth: (%s).\n",
		       ctx->xenv.fault_code, ctx->xenv.fault_string);
		xmlrpc_env_clean(&ctx->xenv);
	}
	if (negotiate) {
		xmlrpc_server_info_allow_auth_negotiate(&ctx->xenv,
							ctx->server);
		if (ctx->xenv.fault_occurred) {
			printf("Fault %d turning on negotiate auth: "
			       "(%s).\n",
			       ctx->xenv.fault_code, ctx->xenv.fault_string);
			xmlrpc_env_clean(&ctx->xenv);
		}
	} else {
		xmlrpc_server_info_disallow_auth_negotiate(&ctx->xenv,
							   ctx->server);
		if (ctx->xenv.fault_occurred) {
			printf("Fault %d turning off negotiate auth: "
			       "(%s).\n",
			       ctx->xenv.fault_code, ctx->xenv.fault_string);
			xmlrpc_env_clean(&ctx->xenv);
		}
	}

	memset(&ctx->xparams, 0, sizeof(ctx->xparams));
	ctx->xparams.cainfo = talloc_strdup(ctx, cainfo);
	ctx->xparams.capath = talloc_strdup(ctx, capath);
	(*xmlrpc_curl_transport_ops.create)(&ctx->xenv, 0,
					    PACKAGE_NAME,
					    PACKAGE_VERSION,
					    &ctx->xparams,
					    sizeof(ctx->xparams),
					    &ctx->xtransport);
	if (ctx->xenv.fault_occurred) {
		printf("Fault %d: (%s).\n",
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
		xmlrpc_array_append_item(&ctx->xenv,
					 ctx->params,
					 arg);
	}
}

void
cm_submit_x_add_arg_b(struct cm_submit_x_context *ctx, int b)
{
	xmlrpc_value *arg;
	arg = xmlrpc_bool_new(&ctx->xenv, b != 0);
	if (arg != NULL) {
		xmlrpc_array_append_item(&ctx->xenv,
					 ctx->params,
					 arg);
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
	xmlrpc_client_call2(&ctx->xenv,
			    ctx->client,
			    ctx->server,
			    ctx->method,
			    ctx->params,
			    &ctx->results);
	if (ctx->xenv.fault_occurred) {
		printf("Fault %d: (%s).\n",
		       ctx->xenv.fault_code,
		       ctx->xenv.fault_string);
		xmlrpc_env_clean(&ctx->xenv);
	}
}

int
cm_submit_x_get_bss(struct cm_submit_x_context *ctx,
		    int *b, char **s1, char **s2)
{
	const char *p;
	xmlrpc_bool boo;
	xmlrpc_value *arg;
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

xmlrpc_value *
cm_submit_x_get_struct(struct cm_submit_x_context *ctx)
{
	int i;
	xmlrpc_value *arg;
	i = 0;
	for (;;) {
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
	xmlrpc_value *arg, *val;
	arg = cm_submit_x_get_struct(ctx);
	if (arg == NULL) {
		return -1;
	}
	xmlrpc_struct_find_value(&ctx->xenv, arg, name, &val);
	if (val == NULL) {
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
	xmlrpc_value *arg, *val;
	arg = cm_submit_x_get_struct(ctx);
	if (arg == NULL) {
		return -1;
	}
	xmlrpc_struct_find_value(&ctx->xenv, arg, name, &val);
	if (val == NULL) {
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
	xmlrpc_value *arg, *val;
	arg = cm_submit_x_get_struct(ctx);
	if (arg == NULL) {
		return -1;
	}
	xmlrpc_struct_find_value(&ctx->xenv, arg, name, &val);
	if (val == NULL) {
		return -1;
	}
	xmlrpc_read_string(&ctx->xenv, val, &p);
	if (ctx->xenv.fault_occurred) {
		xmlrpc_env_clean(&ctx->xenv);
		return -1;
	}
	*s = talloc_strdup(ctx, p);
	return 0;
}

int
main(int argc, char **argv)
{
	xmlrpc_env xenv;
	xmlrpc_server_info *server;
	xmlrpc_client *client;
	xmlrpc_value *req, *params, *arg, *named, *results;
	struct xmlrpc_clientparms cparams;
	struct xmlrpc_curl_xportparms xparams;
	xmlrpc_client_transport *xtransport;
	xmlrpc_bool boo;
	int i, c, ret, k5 = FALSE;
	const char *uri = NULL, *method = NULL, *ktname = NULL, *kpname = NULL;
	const char *s, *cainfo = NULL, *capath = NULL;
	char *csr, *p, buf[BUFSIZ], *skey, *sval;
	FILE *fp;

	while ((c = getopt(argc, argv, "s:m:kt:p:c:")) != -1) {
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
		case 'C':
			capath = optarg;
			break;
		case 'c':
			cainfo = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-s serverURI] [-m method] "
				"[-k] [-t keytab] [-p principal] "
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
			"[-k] [-t keytab] [-p principal] "
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
	results = NULL;
	ret = CM_STATUS_UNREACHABLE;
	csr = getenv(CM_SUBMIT_CSR_ENV);
	if (csr == NULL) {
		if ((optind < argc) && (strchr(argv[optind], '=') == NULL)) {
			fp = fopen(argv[optind], "r");
			if (fp == NULL) {
				printf("Error opening \"%s\": %s.\n",
				       argv[optind], strerror(errno));
				return CM_STATUS_UNCONFIGURED;
			}
			optind++;
		} else {
			fp = stdin;
		}
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			if (csr == NULL) {
				csr = strdup(buf);
				if (csr == NULL) {
					return CM_STATUS_UNREACHABLE;
				}
			} else {
				p = malloc(strlen(csr) + sizeof(buf));
				if (p == NULL) {
					return CM_STATUS_UNREACHABLE;
				}
				memcpy(my_stpcpy(p, csr), buf, sizeof(buf));
				free(csr);
				csr = p;
			}
		}
		if (fp != stdin) {
			fclose(fp);
		}
		if (csr == NULL) {
			csr = strdup("");
		}
	}

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

	if (k5 || (kpname != NULL) || (ktname != NULL)) {
		if (cm_submit_x_make_ccache(ktname, kpname) == 0) {
			k5 = TRUE;
		}
	}

	server = xmlrpc_server_info_new(&xenv, uri);
	if (server != NULL) {
		xmlrpc_server_info_set_user(&xenv, server, "", "");
		if (xenv.fault_occurred) {
			printf("Fault %d faking up basic auth: (%s).\n",
			       xenv.fault_code, xenv.fault_string);
			xmlrpc_env_clean(&xenv);
		}
		if (k5) {
			xmlrpc_server_info_allow_auth_negotiate(&xenv, server);
			if (xenv.fault_occurred) {
				printf("Fault %d turning on negotiate auth: "
				       "(%s).\n",
				       xenv.fault_code, xenv.fault_string);
				xmlrpc_env_clean(&xenv);
			}
		} else {
			xmlrpc_server_info_disallow_auth_negotiate(&xenv,
								   server);
			if (xenv.fault_occurred) {
				printf("Fault %d turning off negotiate auth: "
				       "(%s).\n",
				       xenv.fault_code, xenv.fault_string);
				xmlrpc_env_clean(&xenv);
			}
		}

		memset(&xparams, 0, sizeof(xparams));
		xparams.cainfo = cainfo;
		xparams.capath = capath;
		(*xmlrpc_curl_transport_ops.create)(&xenv, 0,
						    PACKAGE_NAME,
						    PACKAGE_VERSION,
						    &xparams, sizeof(xparams),
						    &xtransport);
		if (xenv.fault_occurred) {
			printf("Fault %d: (%s).\n",
			       xenv.fault_code, xenv.fault_string);
			xmlrpc_env_clean(&xenv);
		}
		if (xtransport != NULL) {
			memset(&cparams, 0, sizeof(cparams));
			cparams.transportOpsP = &xmlrpc_curl_transport_ops;
			cparams.transportP = xtransport;
			xmlrpc_client_create(&xenv,
					     XMLRPC_CLIENT_NO_FLAGS,
					     PACKAGE_NAME,
					     PACKAGE_VERSION,
					     &cparams, sizeof(cparams),
					     &client);
			if (client != NULL) {
				params = NULL;
				results = NULL;
				params = xmlrpc_array_new(&xenv);
				if (params != NULL) {
					req = xmlrpc_string_new(&xenv, csr);
					if (req != NULL) {
						xmlrpc_array_append_item(&xenv,
									 params,
									 req);
					}
					if ((optind < argc) &&
					    ((named = xmlrpc_struct_new(&xenv)) != NULL)) {
						for (i = optind; i < argc; i++) {
							skey = strdup(argv[i]);
							sval = skey + strcspn(skey, "=");
							if (*sval != '\0') {
								*sval++ = '\0';
							}
							if (strcasecmp(sval, "true") == 0) {
								xmlrpc_struct_set_value(&xenv, named, skey, xmlrpc_bool_new(&xenv, 1));
							} else
							if (strcasecmp(sval, "false") == 0) {
								xmlrpc_struct_set_value(&xenv, named, skey, xmlrpc_bool_new(&xenv, 0));
							} else {
								xmlrpc_struct_set_value(&xenv, named, skey, xmlrpc_string_new(&xenv, sval));
							}
						}
						xmlrpc_array_append_item(&xenv,
									 params,
									 named);
					}
					xmlrpc_client_call2(&xenv,
							    client,
							    server,
							    method,
							    params,
							    &results);
					if (xenv.fault_occurred) {
						printf("Fault %d: (%s).\n",
						       xenv.fault_code,
						       xenv.fault_string);
						xmlrpc_env_clean(&xenv);
					}
				} else {
					printf("Error creating params.\n");
					if (xenv.fault_occurred) {
						printf("Fault %d: (%s).\n",
						       xenv.fault_code,
						       xenv.fault_string);
						xmlrpc_env_clean(&xenv);
					}
				}
			} else {
				printf("Error creating client.\n");
				if (xenv.fault_occurred) {
					printf("Fault %d: (%s).\n",
					       xenv.fault_code,
					       xenv.fault_string);
					xmlrpc_env_clean(&xenv);
				}
			}
		} else {
			printf("Error creating transport.\n");
			if (xenv.fault_occurred) {
				printf("Fault %d: (%s).\n",
				       xenv.fault_code, xenv.fault_string);
				xmlrpc_env_clean(&xenv);
			}
		}
		xmlrpc_server_info_free(server);
	} else {
		printf("Error creating server info.\n");
		if (xenv.fault_occurred) {
			printf("Fault %d: (%s).\n",
			       xenv.fault_code, xenv.fault_string);
			xmlrpc_env_clean(&xenv);
		}
	}

	if (results != NULL) {
		i = xmlrpc_array_size(&xenv, results);
		if (xenv.fault_occurred) {
			printf("Fault %d: (%s).\n",
			       xenv.fault_code, xenv.fault_string);
			xmlrpc_env_clean(&xenv);
		} else {
			printf("%d arguments for response.\n", i);
			if (i > 0) {
				/* The first element is a boolean. */
				arg = NULL;
				xmlrpc_array_read_item(&xenv, results, 0, &arg);
				if (xenv.fault_occurred) {
					printf("Fault %d: (%s).\n",
					       xenv.fault_code,
					       xenv.fault_string);
					xmlrpc_env_clean(&xenv);
				} else {
					xmlrpc_read_bool(&xenv, arg, &boo);
					if (xenv.fault_occurred) {
						printf("Fault %d: (%s).\n",
						       xenv.fault_code,
						       xenv.fault_string);
						xmlrpc_env_clean(&xenv);
					} else {
						printf("Status: %d.\n", boo);
						if (boo) {
							ret = CM_STATUS_ISSUED;
						}
						if (i > 2) {
							/* The next two are our
							 * certificate and the
							 * CA's certificate. */
							xmlrpc_array_read_item(&xenv, results, 1, &arg);
							if (xenv.fault_occurred) {
								printf("Fault %d: (%s).\n",
								       xenv.fault_code,
								       xenv.fault_string);
								xmlrpc_env_clean(&xenv);
							} else {
								xmlrpc_read_string(&xenv, arg, &s);
								if (xenv.fault_occurred) {
									printf("Fault %d: (%s).\n",
									       xenv.fault_code,
									       xenv.fault_string);
									xmlrpc_env_clean(&xenv);
								} else {
									printf("\"%s\"\n", s);
								}
							}
						}
					}
				}
			}
		}
	}
	return ret;
}
