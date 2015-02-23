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

#include "srvloc.h"
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

/* Connect and authenticate to a specific directory server. */
static LDAP *
cm_open_ldap(const char *uri)
{
	LDAP *ld;
	int rc, three;
	const char *ldefaults[] = {"meh"};

	ld = NULL;
	rc = ldap_initialize(&ld, uri);
	if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "Error initializing \"%s\": %s.\n",
			uri, ldap_err2string(rc));
		return NULL;
	}
	three = 3;
	rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &three);
	if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "Error initializing \"%s\": %s.\n",
			uri, ldap_err2string(rc));
		return NULL;
	}
	rc = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI",
					  NULL, NULL,
					  LDAP_SASL_QUIET,
					  &interact, ldefaults);
	if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "Error binding to \"%s\": %s.\n",
			uri, ldap_err2string(rc));
		return NULL;
	}
	return ld;
}

/* Connect and authenticate to the domain's directory server. */
static int
cm_open_any_ldap(const char *server,
		 int ldap_uri_cmd, const char *ldap_uri,
		 const char *host,
		 const char *domain,
		 char *uri,
		 size_t uri_len,
		 LDAP **ld)
{
	struct cm_srvloc *srvlocs, *srv;

	*ld = NULL;
	/* Prepare to perform an LDAP search. */
	if ((server != NULL) && !ldap_uri_cmd) {
		snprintf(uri, uri_len, "ldap://%s/", server);
	} else
	if (ldap_uri != NULL) {
		snprintf(uri, uri_len, "%s", ldap_uri);
	} else
	if (host != NULL) {
		snprintf(uri, uri_len, "ldap://%s/", host);
	}
	/* Connect and authenticate. */
	if (strlen(uri) != 0) {
		*ld = cm_open_ldap(uri);
	}
	if ((*ld == NULL) &&
	    (cm_srvloc_resolve(NULL, "_ldap._tcp", domain,
			       &srvlocs) == 0)) {
		for (srv = srvlocs;
		     (srv != NULL) && (*ld == NULL);
		     srv = srv->next) {
			if (srv->port != 0) {
				snprintf(uri, uri_len,
					 "ldap://%s:%d/", srv->host,
					 srv->port);
			} else {
				snprintf(uri, uri_len,
					 "ldap://%s/", srv->host);
			}
			*ld = cm_open_ldap(uri);
		}
	}
	if (strlen(uri) == 0) {
		printf(_("Unable to determine location of "
			 "IPA LDAP server.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if (*ld == NULL) {
		printf(_("Unable to contact an IPA LDAP server.\n"));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	return 0;
}

/* Choose a default base DN for the domain. */
static int
cm_find_default_naming_context(LDAP *ld, char **basedn)
{
	LDAPMessage *lresult = NULL, *lmsg = NULL;
	char *lncattrs[2] = {"defaultNamingContext", NULL};
	struct berval **lbvalues;
	int i, c, rc;

	*basedn = NULL;
	rc = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE,
			       NULL, lncattrs, 0, NULL, NULL, NULL,
			       1, &lresult);
	if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "Error searching root DSE: %s.\n",
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
			*basedn = malloc(c + 1);
			if (*basedn != NULL) {
				memcpy(*basedn,
				       lbvalues[0]->bv_val,
				       c);
				(*basedn)[c] = '\0';
				break;
			}
		}
	}
	ldap_msgfree(lresult);
	return 0;
}

static int
cm_locate_xmlrpc_service(const char *server,
			 int ldap_uri_cmd, const char *ldap_uri,
			 const char *host,
			 const char *domain,
			 char *basedn,
			 const char *service,
			 char ***uris)
{
	LDAP *ld;
	LDAPMessage *lresult = NULL, *lmsg = NULL;
	LDAPDN rdn;
	struct berval *lbv;
	char *lattrs[2] = {"cn", NULL};
	const char *relativedn = "cn=masters,cn=ipa,cn=etc", *dn;
	char ldn[LINE_MAX], lfilter[LINE_MAX], uri[LINE_MAX] = "", **list;
	int i, j, rc, n;
	unsigned int flags;

	*uris = NULL;

	/* Prepare to perform an LDAP search. */
	i = cm_open_any_ldap(server, ldap_uri_cmd, ldap_uri, host, domain,
			     uri, sizeof(uri), &ld);
	if (i != 0) {
		return i;
	}
	/* If we don't have a base DN to search yet, look for a default
	 * that we can use. */
	if (basedn == NULL) {
		i = cm_find_default_naming_context(ld, &basedn);
		if (i != 0) {
			return i;
		}
	}
	if (basedn == NULL) {
		printf(_("Unable to determine base DN of "
			 "domain information on IPA server.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	/* Now look up the names of the master CAs. */
	snprintf(lfilter, sizeof(lfilter),
		 "(&"
		 "(objectClass=ipaConfigObject)"
		 "(cn=%s)"
		 "(ipaConfigString=enabledService)"
		 ")", service);
	snprintf(ldn, sizeof(ldn), "%s,%s", relativedn, basedn);
	free(basedn);
	rc = ldap_search_ext_s(ld, ldn, LDAP_SCOPE_SUBTREE,
			       lfilter, lattrs, 0, NULL, NULL, NULL,
			       LDAP_NO_LIMIT, &lresult);
	if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "Error searching '%s': %s.\n",
			ldn, ldap_err2string(rc));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	/* Read their parents' for "cn" values. */
	n = ldap_count_entries(ld, lresult);
	if (n == 0) {
		fprintf(stderr, "No CA masters found.\n");
		ldap_msgfree(lresult);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	list = talloc_array_ptrtype(NULL, list, n + 2);
	if (list == NULL) {
		fprintf(stderr, "Out of memory.\n");
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	i = 0;
	for (lmsg = ldap_first_entry(ld, lresult);
	     lmsg != NULL;
	     lmsg = ldap_next_entry(ld, lmsg)) {
		dn = ldap_get_dn(ld, lmsg);
		if (dn != NULL) {
			if (ldap_str2dn(dn, &rdn, 0) == 0) {
				lbv = NULL;
				flags = 0;
				/* Dig out the CN value of the second RDN.  The
				 * more correct thing to do would be to
				 * construct the parent DN, do a base search
				 * against it, and read its attribute normally,
				 * but that could become time-consuming, so for
				 * now do it a bit lazily. */
				if ((rdn != NULL) && (rdn[0] != NULL) &&
				    (rdn[1] != NULL)) {
					for (j = 0; rdn[1][j] != NULL; j++) {
						lbv = &rdn[1][j]->la_attr;
						if ((lbv->bv_len == 2) &&
						    (((lbv->bv_val[0] == 'c') ||
						      (lbv->bv_val[0] == 'C')) &&
						     ((lbv->bv_val[1] == 'n') ||
						      (lbv->bv_val[1] == 'N')))) {
							lbv = &rdn[1][j]->la_value;
							flags = rdn[1][j]->la_flags;
							break;
						}
						if ((lbv->bv_len == 3) &&
						    (((lbv->bv_val[0] == 'c') ||
						      (lbv->bv_val[0] == 'C')) &&
						     ((lbv->bv_val[1] == 'n') ||
						      (lbv->bv_val[1] == 'N')) &&
						     ((lbv->bv_val[2] == '\0')))) {
							lbv = &rdn[1][j]->la_value;
							flags = rdn[1][j]->la_flags;
							break;
						}
						lbv = NULL;
					}
				}
				if (lbv != NULL) {
					switch (flags & 0x0f) {
					case LDAP_AVA_STRING:
						list[i] = talloc_asprintf(list,
									  "https://%.*s/ipa/xml",
									  (int) lbv->bv_len,
									  lbv->bv_val);
						if (list[i] != NULL) {
							i++;
						}
						break;
					case LDAP_AVA_BINARY:
						break;
					}
				}
				ldap_dnfree(rdn);
			}
		}
	}
	ldap_msgfree(lresult);
	if (i == 0) {
		free(list);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	list[i] = NULL;
	*uris = list;
	return CM_SUBMIT_STATUS_ISSUED;
}

/* Make an XML-RPC request to the "cert_request" method. */
static int
submit_or_poll_uri(const char *uri, const char *cainfo, const char *capath,
	           const char *csr, const char *reqprinc)
{
	struct cm_submit_x_context *ctx;
	const char *args[2];
	char *s, *p;
	int i;

	if ((uri == NULL) || (strlen(uri) == 0)) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

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
			p = cm_submit_u_pem_from_base64("CERTIFICATE",
							FALSE, s);
			if (p != NULL) {
				printf("%s", p);
			}
			free(s);
			free(p);
			return CM_SUBMIT_STATUS_ISSUED;
		} else {
			return CM_SUBMIT_STATUS_REJECTED;
		}
	} else {
		/* No useful response, no fault.  Try again, from
		 * scratch, later. */
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
}

static int
submit_or_poll(const char *uri, const char *cainfo, const char *capath,
	       const char *server, int ldap_uri_cmd, const char *ldap_uri,
	       const char *host, const char *domain, char *basedn,
	       const char *csr, const char *reqprinc)
{
	int i, u;
	char **uris;

	i = submit_or_poll_uri(uri, cainfo, capath, csr, reqprinc);
	if ((i == CM_SUBMIT_STATUS_UNREACHABLE) ||
	    (i == CM_SUBMIT_STATUS_UNCONFIGURED)) {
		u = cm_locate_xmlrpc_service(server, ldap_uri_cmd, ldap_uri,
					     host, domain, basedn, "CA", &uris);
		if ((u == 0) && (uris != NULL)) {
			for (u = 0; uris[u] != NULL; u++) {
				if (strcmp(uris[u], uri) == 0) {
					continue;
				}
				i = submit_or_poll_uri(uris[u], cainfo, capath,
						       csr, reqprinc);
				if ((i != CM_SUBMIT_STATUS_UNREACHABLE) &&
				    (i != CM_SUBMIT_STATUS_UNCONFIGURED)) {
					talloc_free(uris);
					return i;
				}
			}
			talloc_free(uris);
		}
	}
	return i;
}

static int
fetch_roots(const char *server, int ldap_uri_cmd, const char *ldap_uri,
	    const char *host, const char *domain, char *basedn)
{
	char *realm = NULL;
	LDAP *ld = NULL;
	LDAPMessage *lresult = NULL, *lmsg = NULL;
	char *lattrs[2] = {"caCertificate;binary", NULL};
	const char *relativedn = "cn=cacert,cn=ipa,cn=etc";
	char ldn[LINE_MAX], lfilter[LINE_MAX], uri[LINE_MAX] = "", *kerr = NULL;
	struct berval **lbvalues, *lbv;
	unsigned char *bv_val;
	const char *lb64;
	char *pem;
	int i, rc;

	/* Prepare to perform an LDAP search. */
	i = cm_open_any_ldap(server, ldap_uri_cmd, ldap_uri, host, domain,
			     uri, sizeof(uri), &ld);
	if (i != 0) {
		return i;
	}
	/* If we don't have a base DN to search yet, look for a default
	 * that we can use. */
	if (basedn == NULL) {
		i = cm_find_default_naming_context(ld, &basedn);
		if (i != 0) {
			return i;
		}
	}
	if (basedn == NULL) {
		printf(_("Unable to determine base DN of "
			 "domain information on IPA server.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	/* Now look up the root certificates for the domain. */
	snprintf(lfilter, sizeof(lfilter), "(%s=*)", lattrs[0]);
	snprintf(ldn, sizeof(ldn), "%s,%s", relativedn, basedn);
	free(basedn);
	rc = ldap_search_ext_s(ld, ldn, LDAP_SCOPE_SUBTREE,
			       lfilter, lattrs, 0, NULL, NULL, NULL,
			       LDAP_NO_LIMIT, &lresult);
	if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "Error searching '%s': %s.\n",
			ldn, ldap_err2string(rc));
		return CM_SUBMIT_STATUS_ISSUED;
	}
	/* Read our realm name from our ccache. */
	realm = cm_submit_x_ccache_realm(&kerr);
	/* Read all of the certificates. */
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
			free(pem);
		}
	}
	ldap_msgfree(lresult);
	free(realm);
	free(kerr);
	return CM_SUBMIT_STATUS_ISSUED;
}

int
main(int argc, char **argv)
{
	int c, make_keytab_ccache = TRUE;
	const char *host = NULL, *domain = NULL, *cainfo = NULL, *capath = NULL;
	const char *ktname = NULL, *kpname = NULL;
	char *csr, *p, uri[LINE_MAX], *reqprinc = NULL, *ipaconfig, *kerr;
	const char *xmlrpc_uri = NULL, *ldap_uri = NULL, *server = NULL;
	int xmlrpc_uri_cmd = 0, ldap_uri_cmd = 0;
	const char *mode = CM_OP_SUBMIT;
	char ldn[LINE_MAX], *basedn = NULL;
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
			xmlrpc_uri_cmd++;
			break;
		case 'L':
			ldap_uri = optarg;
			ldap_uri_cmd++;
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
		if ((server != NULL) && !xmlrpc_uri_cmd) {
			snprintf(uri, sizeof(uri),
				 "https://%s/ipa/xml", server);
		} else
		if (xmlrpc_uri != NULL) {
			snprintf(uri, sizeof(uri), "%s", xmlrpc_uri);
		} else
		if (host != NULL) {
			snprintf(uri, sizeof(uri),
				 "https://%s/ipa/xml", host);
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
	} else
	if (strcasecmp(mode, CM_OP_FETCH_ROOTS) == 0) {
		/* Stop now if we don't have an IPA domain name. */
		if (domain == NULL) {
			printf(_("No IPA domain configured, and none "
			         "specified.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
	}

	/* Setup a ccache unless we're told to use the default one. */
	kerr = NULL;
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
		free(kerr);
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
		return submit_or_poll(uri, cainfo, capath,
				      server, ldap_uri_cmd, ldap_uri,
				      host, domain, basedn,
				      csr, reqprinc);
	} else
	if (strcasecmp(mode, CM_OP_FETCH_ROOTS) == 0) {
		return fetch_roots(server, ldap_uri_cmd, ldap_uri, host,
				   domain, basedn);
	}

	return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
}
