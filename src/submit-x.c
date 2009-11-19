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

#include "submit-e.h"

#define REQ_DATA \
	"-----BEGIN NEW CERTIFICATE REQUEST-----\n" \
	"MIIC+jCCAeICAQAwFTETMBEGA1UEAxMKQm9iIEplbnNlbjCCASIwDQYJKoZIhvcN\n" \
	"AQEBBQADggEPADCCAQoCggEBAMeBHVwuakwxp4OsPT+ooghzyr5SsyKylKJ+QP4B\n" \
	"nQzxNSmT3O+ubtRqgv/1Rekj30Z56QMX3D9cgJfdRCmSTQ6JLpubgX1DZtgyHq4j\n" \
	"nUtiYsObzQ83+OXlO/kUItGVJa2308+rAQ6FkpI8S0WwiXgfZIZmbIjghkpfj+XT\n" \
	"PtjVsBwKVxr39++Hq0zA+1YzKPZEe+mU0C8s7zh0tzEiXVEcOnwLL25QpEVDUVxd\n" \
	"HKHBfnVOmsN9ju9BO48b+zIIB5qtSSir+jTs9+JqRX00nsPXVonhXMHOxOjc9pMJ\n" \
	"V3D8wIfXzeW10xNA3YYCi66XiZTicfsFV8Z47Mrq0yytCe0CAwEAAaCBnzATBgkq\n" \
	"hkiG9w0BCRQxBhMEQmFiczCBhwYJKoZIhvcNAQkOMXoweDB2BgNVHREBAQAEbDBq\n" \
	"gRBiYWJzQGV4YW1wbGUuY29toCMGCisGAQQBgjcUAgOgFQwTYmplbnNlbkBFWEFN\n" \
	"UExFLkNPTaAxBgYrBgEFAgKgJzAloA0bC0VYQU1QTEUuQ09NoRQwEqADAgEBoQsw\n" \
	"CRsHYmplbnNlbjANBgkqhkiG9w0BAQsFAAOCAQEAOi7Jd5CTTZvCye9iep8R7hMJ\n" \
	"DK45btHEiNB9SEqhVcpIhTPh+6Q/1NtuLYGbk0MSe8ocqCO0g2x9kANsVTH4FBOz\n" \
	"RU9nbucOQpwrWtmOjzJAth04WSIhVQfTTL0ihTxRS2QmPrs/W3rNTWbTsKIwv7ta\n" \
	"8REWElKQjvkt9ejWbIsp70eOaQKFjgA5W69wjguKdRbs9H66CqIdlYK4GMpOO8pH\n" \
	"7keIGHRzSc3SEs0H2RchLgaX922o0CDsg28mbvUDFL2bbQy0kqyzKGdMuwwMMlO9\n" \
	"L7bOVSOHtpWw2ScQlN+Y3ljPAOZ2F1FdloCtozBJju5CyIrGOqCj8kiOWh3zSw==\n" \
	"-----END NEW CERTIFICATE REQUEST-----\n"

int
main(int argc, char **argv)
{
	const char *uri;
	xmlrpc_env xenv;
	xmlrpc_server_info *server;
	xmlrpc_client *client;
	xmlrpc_value *req, *params, *arg, *results;
	struct xmlrpc_clientparms cparams;
	struct xmlrpc_curl_xportparms xparams;
	xmlrpc_client_transport *xtransport;
	xmlrpc_bool boo;
	int i, ret;
	const char *s;

	memset(&xenv, 0, sizeof(xenv));
	xmlrpc_env_init(&xenv);
	xmlrpc_client_setup_global_const(&xenv);

	uri = "http://localhost:51235/"; /* XXX - certmaster default */
	server = xmlrpc_server_info_new(&xenv, uri);
	results = NULL;
	ret = STATUS_UNREACHABLE;

	if (server != NULL) {
		xmlrpc_server_info_set_user(&xenv, server, "", "");
		if (xenv.fault_occurred) {
			printf("Fault %d: (%s).\n",
			       xenv.fault_code, xenv.fault_string);
			xmlrpc_env_clean(&xenv);
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
					req = xmlrpc_string_new(&xenv,
								REQ_DATA);
					if (req != NULL) {
						xmlrpc_array_append_item(&xenv,
									 params,
									 req);
					}
					xmlrpc_client_call2(&xenv,
							    client,
							    server,
							    "wait_for_cert",
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
							ret = STATUS_ISSUED;
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
