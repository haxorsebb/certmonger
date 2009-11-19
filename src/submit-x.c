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

#include <xmlrpc-c/client.h>
#include <xmlrpc-c/transport.h>

#include <krb5.h>

#include "submit-e.h"

int
main(int argc, char **argv)
{
	xmlrpc_env xenv;
	xmlrpc_server_info *server;
	xmlrpc_client *client;
	xmlrpc_value *req, *params, *arg, *results;
	struct xmlrpc_clientparms cparams;
	struct xmlrpc_curl_xportparms xparams;
	xmlrpc_client_transport *xtransport;
	xmlrpc_bool boo;
	int i, c, ret, k5 = FALSE;
	const char *uri = NULL, *method = NULL, *ktname = NULL, *kpname = NULL;
	const char *s;
	char *csr, *p, buf[BUFSIZ];
	krb5_context ctx;
	krb5_keytab keytab;
	krb5_ccache ccache;
	krb5_creds creds;
	krb5_principal princ;
	krb5_error_code kret;

	memset(&xenv, 0, sizeof(xenv));
	xmlrpc_env_init(&xenv);
	xmlrpc_client_setup_global_const(&xenv);

	while ((c = getopt(argc, argv, "s:m:kt:p:")) != -1) {
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
		default:
			fprintf(stderr,
				"Usage: %s [-s serverURI] [-m method] "
				"[-k] [-t keytab] [-p principal]\n"
				"Examples:\n"
				"           -s http://localhost:51235/\n"
				"           -m wait_for_cert\n"
				"           -k /etc/krb5.keytab\n",
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
			"[-k] [-t keytab] [-p principal]\n"
			"Examples:\n"
			"           -s http://localhost:51235/\n"
			"           -m wait_for_cert\n"
			"           -k /etc/krb5.keytab\n",
			strchr(argv[0], '/') ?
			strrchr(argv[0], '/') + 1 :
			argv[0]);
		return CM_STATUS_UNCONFIGURED;
	}
	server = xmlrpc_server_info_new(&xenv, uri);
	results = NULL;
	ret = CM_STATUS_UNREACHABLE;
	csr = getenv(CM_SUBMIT_CSR_ENV);
	if (csr == NULL) {
		while (fgets(buf, sizeof(buf), stdin) != NULL) {
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
				memcpy(stpcpy(p, csr), buf, sizeof(buf));
				free(csr);
				csr = p;
			}
		}
	}
	if (strcmp(method, "wait_for_cert") == 0) {
		/* certmaster rewrites the incoming request to its cache
		 * previously-received requests, and in doing so uses a
		 * different PEM header than the one we default to using.  So
		 * turn any "NEW CERTIFICATE REQUEST" notes into "CERTIFICATE
		 * REQUEST". */
		while ((p = strstr(csr, "NEW CERTIFICATE REQUEST")) != NULL) {
			memmove(p, p + 4, strlen(p + 4) + 1);
		}
	}

	if (k5 || (kpname != NULL) || (ktname != NULL)) {
		kret = krb5_init_context(&ctx);
		if (kret != 0) {
			printf("Error initializing Kerberos: %s.\n",
			       error_message(kret));
			return CM_STATUS_UNCONFIGURED;
		}
		if (ktname != NULL) {
			kret = krb5_kt_resolve(ctx, ktname, &keytab);
		} else {
			kret = krb5_kt_default(ctx, &keytab);
		}
		if (kret != 0) {
			printf("Error resolving keytab: %s.\n",
			       error_message(kret));
			return CM_STATUS_UNCONFIGURED;
		}
		princ = NULL;
		if (kpname != NULL) {
			kret = krb5_parse_name(ctx, kpname, &princ);
			if (kret != 0) {
				printf("Error parsing \"%s\": %s.\n", kpname,
				       error_message(kret));
				return CM_STATUS_UNCONFIGURED;
			}
		}
		memset(&creds, 0, sizeof(creds));
		kret = krb5_get_init_creds_keytab(ctx, &creds, princ, keytab,
						  0, NULL, NULL);
		if (kret != 0) {
			printf("Error obtaining initial credentials: %s.\n",
			       error_message(kret));
			return CM_STATUS_UNREACHABLE;
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
			return CM_STATUS_UNREACHABLE;
		}
		kret = krb5_cc_store_cred(ctx, ccache, &creds);
		if (kret != 0) {
			printf("Error storing creds in credential cache: %s.\n",
			       error_message(kret));
			return CM_STATUS_UNREACHABLE;
		}
		k5 = TRUE;
	}

	if (server != NULL) {
		xmlrpc_server_info_disallow_auth_basic(&xenv, server);
		if (xenv.fault_occurred) {
			printf("Fault %d turning off basic auth: (%s).\n",
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
		(*xmlrpc_curl_transport_ops.create)(&xenv, 0,
						    PACKAGE_NAME,
						    PACKAGE_VERSION,
						    &xparams, sizeof(xparams),
						    &xtransport);
		if (xtransport != NULL) {
			memset(&cparams, 0, sizeof(cparams));
			cparams.transportOpsP = &xmlrpc_curl_transport_ops;
			cparams.transportP = xtransport;
			if (xenv.fault_occurred) {
				printf("Fault %d: (%s).\n",
				       xenv.fault_code, xenv.fault_string);
				xmlrpc_env_clean(&xenv);
			}
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
