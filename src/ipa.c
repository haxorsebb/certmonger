/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014 Red Hat, Inc.
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
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include <xmlrpc-c/client.h>
#include <xmlrpc-c/transport.h>

#include <ldap.h>
#include <krb5.h>

#include "store.h"
#include "submit-e.h"
#include "submit-u.h"
#include "submit-x.h"
#include "util.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

static void
help(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-h serverHost] "
		"[-H xmlrpcUri] "
		"[-L ldapUri] "
		"[-b basedn] "
		"[-c cafile] "
		"[-C capath] "
		"[-K] "
		"[-t keytab] "
		"[-k submitterPrincipal] "
		"[-P principalOfRequest] "
		"[-d IPA domain name] "
		"[csrfile]\n",
		strchr(argv0, '/') ?
		strrchr(argv0, '/') + 1 :
		argv0);
}

static int
interact(LDAP *ld, unsigned flags, void *defaults, void *sasl_interact)
{
	return 0;
}

int
main(int argc, char **argv)
{
	int i, c, make_keytab_ccache = TRUE, rc, three;
	const char *host = NULL, *domain = NULL, *cainfo = NULL, *capath = NULL;
	const char *ktname = NULL, *kpname = NULL, *realm = NULL, *args[2];
	char *csr, *p, uri[LINE_MAX], *s, *reqprinc = NULL, *ipaconfig, *kerr;
	const char *xmlrpc_uri = NULL, *ldap_uri = NULL, *server = NULL;
	struct cm_submit_x_context *ctx;
	const char *mode = CM_OP_SUBMIT;
	LDAP *ld = NULL;
	LDAPMessage *lresult = NULL, *lmsg = NULL;
	char ldn[LINE_MAX], lfilter[LINE_MAX], *basedn = NULL;
	char *lattrs[2] = {"caCertificate;binary", NULL};
	char *lncattrs[2] = {"defaultNamingContext", NULL};
	const char *ldefaults[] = {"meh"};
	const char *relativedn = "cn=cacert,cn=ipa,cn=etc";
	struct berval **lbvalues, *lbv;
	unsigned char *bv_val;
	const char *lb64, *pem;
	krb5_error_code kret;

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif

	if (getenv(CM_SUBMIT_OPERATION_ENV) != NULL) {
		mode = getenv(CM_SUBMIT_OPERATION_ENV);
	}
	if (strcasecmp(mode, CM_OP_IDENTIFY) == 0) {
		printf("IPA (%s %s)\n", PACKAGE_NAME, PACKAGE_VERSION);
		return 0;
	} else
	if (strcasecmp(mode, CM_OP_FETCH_ENROLL_REQUIREMENTS) == 0) {
		printf("%s\n", CM_SUBMIT_REQ_PRINCIPAL_ENV);
		printf("%s\n", CM_SUBMIT_REQ_SUBJECT_ENV);
		return 0;
	} else
	if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
	    (strcasecmp(mode, CM_OP_POLL) == 0) ||
	    (strcasecmp(mode, CM_OP_FETCH_ROOTS) == 0)) {
		/* fall through */
	} else {
		/* unsupported request */
		return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
	}

	while ((c = getopt(argc, argv, "h:d:H:L:C:c:t:Kk:P:b:")) != -1) {
		switch (c) {
		case 'h':
			host = optarg;
			break;
		case 'd':
			domain = strdup(optarg);
			break;
		case 'H':
			xmlrpc_uri = optarg;
			break;
		case 'L':
			ldap_uri = optarg;
			break;
		case 'b':
			basedn = strdup(optarg);
			break;
		case 'C':
			capath = optarg;
			break;
		case 'c':
			cainfo = optarg;
			break;
		case 't':
			ktname = optarg;
			if (!make_keytab_ccache) {
				printf(_("The -t option can not be used with "
					 "the -K option.\n"));
				goto help;
			}
			break;
		case 'k':
			kpname = optarg;
			if (!make_keytab_ccache) {
				printf(_("The -k option can not be used with "
					 "the -K option.\n"));
				goto help;
			}
			break;
		case 'K':
			make_keytab_ccache = FALSE;
			if ((kpname != NULL) || (ktname != NULL)) {
				printf(_("The -K option can not be used with "
					 "either the -k or the -t option.\n"));
				goto help;
			}
			break;
		case 'P':
			reqprinc = optarg;
			break;
		help:
		default:
			help(argv[0]);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
			break;
		}
	}

	umask(S_IRWXG | S_IRWXO);

	/* Start backfilling defaults, both hard-coded and from the IPA
	 * configuration. */
	if (cainfo == NULL) {
		cainfo = "/etc/ipa/ca.crt";
	}
	if ((host == NULL) || (xmlrpc_uri == NULL) || (ldap_uri == NULL) ||
	    (basedn == NULL)) {
		ipaconfig = read_config_file("/etc/ipa/default.conf");
		if (ipaconfig != NULL) {
			if (xmlrpc_uri == NULL) {
				xmlrpc_uri = get_config_entry(ipaconfig,
							      "global",
							      "xmlrpc_uri");
			}
			if (ldap_uri == NULL) {
				/* Preferred, but likely to only be set on a
				 * server. */
				ldap_uri = get_config_entry(ipaconfig,
							    "global",
							    "ldap_uri");
			}
			if (basedn == NULL) {
				basedn = get_config_entry(ipaconfig,
							  "global",
							  "basedn");
			}
			if (host == NULL) {
				/* Preferred, but not always set. */
				host = get_config_entry(ipaconfig,
							"global",
							"host");
			}
			if (server == NULL) {
				/* Deprecated, but could be set if "host" is
				 * not. */
				server = get_config_entry(ipaconfig,
							  "global",
							  "server");
			}
			if (domain == NULL) {
				domain = get_config_entry(ipaconfig,
							"global",
							"domain");
			}
		}
	}
	csr = NULL;
	memset(uri, '\0', sizeof(uri));
	memset(ldn, '\0', sizeof(ldn));

	if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
	    (strcasecmp(mode, CM_OP_POLL) == 0)) {
		/* For SUBMIT/POLL, we need a requested-for principal name and
		 * the URI of the XML-RPC server on the CA. */
		if ((reqprinc == NULL) &&
		    (getenv(CM_SUBMIT_REQ_PRINCIPAL_ENV) != NULL)) {
			/* If it's multi-valued, just use the first one. */
			reqprinc = strdup(getenv(CM_SUBMIT_REQ_PRINCIPAL_ENV));
			if (reqprinc != NULL) {
				reqprinc[strcspn(reqprinc, "\r\n")] = '\0';
			}
		}
		if ((reqprinc == NULL) || (strlen(reqprinc) == 0)) {
			printf(_("Unable to determine principal name for "
				 "signing request.\n"));
			help(argv[0]);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		if (xmlrpc_uri != NULL) {
			snprintf(uri, sizeof(uri), "%s", xmlrpc_uri);
		} else
		if (host != NULL) {
			snprintf(uri, sizeof(uri),
				 "https://%s/ipa/xml", host);
		} else
		if (server != NULL) {
			snprintf(uri, sizeof(uri),
				 "https://%s/ipa/xml", server);
		}
		if (strlen(uri) == 0) {
#if 0
			printf(_("Unable to determine hostname of "
				 "CA.\n"));
#endif
			printf(_("Unable to determine location of "
				 "CA's XMLRPC server.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}

		/* Read the CSR from the environment, or from the file named on
		 * the command-line. */
		if (optind < argc) {
			csr = cm_submit_u_from_file(argv[optind++]);
		} else {
			csr = getenv(CM_SUBMIT_CSR_ENV);
			if (csr != NULL) {
				csr = strdup(csr);
			}
		}
		if ((csr == NULL) || (strlen(csr) == 0)) {
			printf(_("Unable to read signing request.\n"));
			help(argv[0]);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}

		/* Change the CSR from the format we get it in to the one the
		 * server expects.  IPA just wants base64-encoded binary data,
		 * no whitepace. */
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

	/* Setup a ccache unless we're told to use the default one. */
	if (make_keytab_ccache &&
	    ((kret = cm_submit_x_make_ccache(ktname, kpname, &kerr)) != 0)) {
		fprintf(stderr, "Error setting up ccache at the client: %s.\n",
			kerr);
		if (ktname == NULL) {
			if (kpname == NULL) {
				printf(_("Error setting up ccache for "
					 "\"host\" service on client using "
					 "default keytab: %s.\n"), kerr);
			} else {
				printf(_("Error setting up ccache for "
					 "\"%s\" on client using "
					 "default keytab: %s.\n"),
					 kpname, kerr);
			}
		} else {
			if (kpname == NULL) {
				printf(_("Error setting up ccache for "
					 "\"host\" service on client using "
					 "keytab \"%s\": %s.\n"), ktname, kerr);
			} else {
				printf(_("Error setting up ccache for "
					 "\"%s\" on client using keytab "
					 "\"%s\": %s.\n"),
					 kpname, ktname, kerr);
			}
		}
		switch (kret) {
		case KRB5_KDC_UNREACH:
		case KRB5_REALM_CANT_RESOLVE:
			return CM_SUBMIT_STATUS_UNREACHABLE;
			break;
		default:
			return CM_SUBMIT_STATUS_UNCONFIGURED;
			break;
		}
	}

	if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
	    (strcasecmp(mode, CM_OP_POLL) == 0)) {
		/* Prepare to make an XML-RPC request. */
		ctx = cm_submit_x_init(NULL, uri, "cert_request",
				       cainfo, capath,
				       cm_submit_x_negotiate_on,
				       cm_submit_x_delegate_on);
		if (ctx == NULL) {
			fprintf(stderr, "Error setting up for XMLRPC to %s on "
				"the client.\n", uri);
			printf(_("Error setting up for XMLRPC on the client.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}

		/* Add the CSR contents as the sole unnamed argument. */
		args[0] = csr;
		args[1] = NULL;
		cm_submit_x_add_arg_as(ctx, args);
		/* Add the principal name named argument. */
		cm_submit_x_add_named_arg_s(ctx, "principal", reqprinc);
		/* Tell the server to add entries for a principal if one
		 * doesn't exist yet. */
		cm_submit_x_add_named_arg_b(ctx, "add", 1);

		/* Submit the request. */
		fprintf(stderr, "Submitting request to \"%s\".\n", uri);
		cm_submit_x_run(ctx);

		/* Check the results. */
		if (cm_submit_x_faulted(ctx) == 0) {
			i = cm_submit_x_fault_code(ctx);
			/* Interpret the error.  See errors.py to get the
			 * classifications. */
			switch (i / 1000) {
			case 2: /* authorization error - permanent */
			case 3: /* invocation error - permanent */
				printf("Server at %s denied our request, "
				       "giving up: %d (%s).\n", uri, i,
				       cm_submit_x_fault_text(ctx));
				return CM_SUBMIT_STATUS_REJECTED;
				break;
			case 1: /* authentication error - transient? */
			case 4: /* execution error - transient? */
			case 5: /* generic error - transient? */
			default:
				printf("Server at %s failed request, "
				       "will retry: %d (%s).\n", uri, i,
				       cm_submit_x_fault_text(ctx));
				return CM_SUBMIT_STATUS_UNREACHABLE;
				break;
			}
		} else
		if (cm_submit_x_has_results(ctx) == 0) {
			if (cm_submit_x_get_named_s(ctx, "certificate",
						    &s) == 0) {
				/* If we got a certificate, we're probably
				 * okay. */
				fprintf(stderr, "Certificate: \"%s\"\n", s);
				s = cm_submit_u_base64_from_text(s);
				if (s == NULL) {
					printf("Out of memory parsing server "
					       "response, will retry.\n");
					return CM_SUBMIT_STATUS_UNREACHABLE;
				}
				s = cm_submit_u_pem_from_base64("CERTIFICATE",
								FALSE, s);
				if (s != NULL) {
					printf("%s", s);
				}
				return CM_SUBMIT_STATUS_ISSUED;
			} else {
				return CM_SUBMIT_STATUS_REJECTED;
			}
		} else {
			/* No useful response, no fault.  Try again, from
			 * scratch, later. */
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
	} else
	if (strcasecmp(mode, CM_OP_FETCH_ROOTS) == 0) {
		/* Read our realm name from our ccache. */
		realm = cm_submit_x_ccache_realm(&kerr);
		/* Prepare to perform an LDAP search. */
		if (ldap_uri != NULL) {
			snprintf(uri, sizeof(uri), "%s", ldap_uri);
		} else
		if (host != NULL) {
			snprintf(uri, sizeof(uri), "ldap://%s/", host);
		} else
		if (server != NULL) {
			snprintf(uri, sizeof(uri), "ldap://%s/", server);
		}
		if (strlen(uri) == 0) {
			printf(_("Unable to determine location of "
				 "IPA LDAP server.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		/* Connect and authenticate. */
		ld = NULL;
		rc = ldap_initialize(&ld, uri);
		if (rc != LDAP_SUCCESS) {
			fprintf(stderr, "Error initializing: %s.",
				ldap_err2string(rc));
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		three = 3;
		rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &three);
		if (rc != LDAP_SUCCESS) {
			fprintf(stderr, "Error initializing: %s.",
				ldap_err2string(rc));
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		rc = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI",
						  NULL, NULL,
						  LDAP_SASL_QUIET,
						  &interact, ldefaults);
		if (rc != LDAP_SUCCESS) {
			fprintf(stderr, "Error binding: %s.",
				ldap_err2string(rc));
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		/* If we don't have a base DN to search yet, look for a default
		 * that we can use. */
		if (basedn == NULL) {
			rc = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE,
					       NULL, lncattrs, 0, NULL, NULL, NULL,
					       1, &lresult);
			if (rc != LDAP_SUCCESS) {
				fprintf(stderr, "Error searching root DSE: %s.",
					ldap_err2string(rc));
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			for (lmsg = ldap_first_entry(ld, lresult);
			     lmsg != NULL;
			     lmsg = ldap_next_entry(ld, lmsg)) {
				lbvalues = ldap_get_values_len(ld, lmsg,
							       lncattrs[0]);
				if (lbvalues == NULL) {
					continue;
				}
				for (i = 0; lbvalues[i] != NULL; i++) {
					c = lbvalues[i]->bv_len;
					basedn = malloc(c + 1);
					if (basedn != NULL) {
						memcpy(basedn,
						       lbvalues[0]->bv_val,
						       c);
						basedn[c] = '\0';
						break;
					}
				}
			}
			ldap_msgfree(lresult);
		}
		if (basedn == NULL) {
			printf(_("Unable to determine base DN of "
				 "domain information on IPA server.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		snprintf(lfilter, sizeof(lfilter), "(%s=*)", lattrs[0]);
		snprintf(ldn, sizeof(ldn), "%s,%s",
			 relativedn, basedn);
		rc = ldap_search_ext_s(ld, ldn, LDAP_SCOPE_SUBTREE,
				       lfilter, lattrs, 0, NULL, NULL, NULL,
				       LDAP_NO_LIMIT, &lresult);
		if (rc != LDAP_SUCCESS) {
			fprintf(stderr, "Error searching '%s': %s.",
				ldn, ldap_err2string(rc));
			return CM_SUBMIT_STATUS_ISSUED;
		}
		for (lmsg = ldap_first_entry(ld, lresult);
		     lmsg != NULL;
		     lmsg = ldap_next_entry(ld, lmsg)) {
			lbvalues = ldap_get_values_len(ld, lmsg, lattrs[0]);
			for (i = 0;
			     (lbvalues != NULL) && (lbvalues[i] != NULL);
			     i++) {
				lbv = lbvalues[i];
				bv_val = (unsigned char *) lbv->bv_val,
				lb64 = cm_store_base64_from_bin(NULL,
								bv_val,
								lbv->bv_len);
				pem = cm_submit_u_pem_from_base64("CERTIFICATE",
								  FALSE, lb64);
				if (realm != NULL) {
					printf("%s ", realm);
				}
				printf("%s\n%s", "IPA CA", pem);
			}
		}
		ldap_msgfree(lresult);
		return CM_SUBMIT_STATUS_ISSUED;
	}

	return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
}
