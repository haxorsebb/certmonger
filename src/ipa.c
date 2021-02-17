/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014,2015 Red Hat, Inc.
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
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include <jansson.h>

#include <ldap.h>
#include <krb5.h>

#include <popt.h>

#include "log.h"
#include "srvloc.h"
#include "store.h"
#include "submit-e.h"
#include "submit-u.h"
#include "submit-h.h"
#include "util.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

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
cm_submit_ccache_realm(char **msg)
{
	krb5_context ctx;
	krb5_ccache ccache;
	krb5_principal princ;
	krb5_error_code kret;
	krb5_data *data;
	char *ret;

	if (msg != NULL) {
		*msg = NULL;
	}

	kret = krb5_init_context(&ctx);
	if (kret != 0) {
		fprintf(stderr, "Error initializing Kerberos: %s.\n",
			ret = get_error_message(ctx, kret));
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return NULL;
	}
	kret = krb5_cc_default(ctx, &ccache);
	if (kret != 0) {
		fprintf(stderr, "Error resolving default ccache: %s.\n",
			ret = get_error_message(ctx, kret));
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return NULL;
	}
	kret = krb5_cc_get_principal(ctx, ccache, &princ);
	if (kret != 0) {
		fprintf(stderr, "Error reading default principal: %s.\n",
			ret = get_error_message(ctx, kret));
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return NULL;
	}
	data = krb5_princ_realm(ctx, princ);
	if (data == NULL) {
		fprintf(stderr, "Error retrieving principal realm.\n");
		if (msg != NULL) {
			*msg = "Error retrieving principal realm.\n";
		}
		return NULL;
	}
	ret = malloc(data->length + 1);
	if (ret == NULL) {
		fprintf(stderr, "Out of memory for principal realm.\n");
		if (msg != NULL) {
			*msg = "Out of memory for principal realm.\n";
		}
		return NULL;
	}
	memcpy(ret, data->data, data->length);
	ret[data->length] = '\0';
	return ret;
}

krb5_error_code
cm_submit_make_ccache(const char *ktname, const char *principal, char **msg)
{
	krb5_context ctx;
	krb5_keytab keytab;
	krb5_ccache ccache;
	krb5_creds creds;
	krb5_principal princ;
	krb5_error_code kret;
	krb5_get_init_creds_opt gicopts, *gicoptsp;
	char *ret;

	if (msg != NULL) {
		*msg = NULL;
	}

	kret = krb5_init_context(&ctx);
	if (kret != 0) {
		ret = get_error_message(ctx, kret);
		fprintf(stderr, "Error initializing Kerberos: %s.\n", ret);
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return kret;
	}
	if (ktname != NULL) {
		kret = krb5_kt_resolve(ctx, ktname, &keytab);
	} else {
		kret = krb5_kt_default(ctx, &keytab);
	}
	if (kret != 0) {
		fprintf(stderr, "Error resolving keytab: %s.\n",
			ret = get_error_message(ctx, kret));
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return kret;
	}
	princ = NULL;
	if (principal != NULL) {
		kret = krb5_parse_name(ctx, principal, &princ);
		if (kret != 0) {
			fprintf(stderr, "Error parsing \"%s\": %s.\n",
				principal, ret = get_error_message(ctx, kret));
			if (msg != NULL) {
				*msg = ret;
			} else {
				free(ret);
			}
			return kret;
		}
	} else {
		kret = krb5_sname_to_principal(ctx, NULL, NULL,
					       KRB5_NT_SRV_HST, &princ);
		if (kret != 0) {
			fprintf(stderr, "Error building client name: %s.\n",
				ret = get_error_message(ctx, kret));
			if (msg != NULL) {
				*msg = ret;
			} else {
				free(ret);
			}
			return kret;
		}
	}
	memset(&creds, 0, sizeof(creds));
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
	memset(&gicopts, 0, sizeof(gicopts));
	gicoptsp = NULL;
	kret = krb5_get_init_creds_opt_alloc(ctx, &gicoptsp);
	if (kret != 0) {
		fprintf(stderr, "Internal error: %s.\n",
			ret = get_error_message(ctx, kret));
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return kret;
	}
#else
	krb5_get_init_creds_opt_init(&gicopts);
	gicoptsp = &gicopts;
#endif
	krb5_get_init_creds_opt_set_forwardable(gicoptsp, 1);
	kret = krb5_get_init_creds_keytab(ctx, &creds, princ, keytab,
					  0, NULL, gicoptsp);
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
	krb5_get_init_creds_opt_free(ctx, gicoptsp);
#endif
	if (kret != 0) {
		fprintf(stderr, "Error obtaining initial credentials: %s.\n",
			ret = get_error_message(ctx, kret));
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return kret;
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
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return kret;
	}
	kret = krb5_cc_store_cred(ctx, ccache, &creds);
	if (kret != 0) {
		fprintf(stderr,
			"Error storing creds in credential cache: %s.\n",
			ret = get_error_message(ctx, kret));
		if (msg != NULL) {
			*msg = ret;
		} else {
			free(ret);
		}
		return kret;
	}
	krb5_cc_close(ctx, ccache);
	krb5_kt_close(ctx, keytab);
	krb5_free_principal(ctx, princ);
	krb5_free_context(ctx);
	putenv("KRB5CCNAME=MEMORY:" PACKAGE_NAME "_submit");
	return 0;
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
		/* There should be only one defaultNamingContext so once we
		 * have a value we're done. */
		if (*basedn != NULL) {
			break;
		}
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
cm_locate_jsonrpc_service(const char *server,
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
	const char *relativedn = "cn=masters,cn=ipa,cn=etc";
	char *dn;
	char ldn[LINE_MAX], lfilter[LINE_MAX], uri[LINE_MAX] = "", **list;
	int i, j, rc, n;
	unsigned int flags;
	int rval = 0;
	int alloc_basedn = 0;

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
			rval = i;
			goto done;
		}
		alloc_basedn = 1;
	}
	if (basedn == NULL) {
		printf(_("Unable to determine base DN of "
			 "domain information on IPA server.\n"));
		rval = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto done;
	}
	/* Now look up the names of the master CAs. */
	snprintf(lfilter, sizeof(lfilter),
		 "(&"
		 "(objectClass=ipaConfigObject)"
		 "(cn=%s)"
		 "(ipaConfigString=enabledService)"
		 ")", service);
	snprintf(ldn, sizeof(ldn), "%s,%s", relativedn, basedn);
	if (alloc_basedn) {
		free(basedn);
	}
	rc = ldap_search_ext_s(ld, ldn, LDAP_SCOPE_SUBTREE,
			       lfilter, lattrs, 0, NULL, NULL, NULL,
			       LDAP_NO_LIMIT, &lresult);
	if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "Error searching '%s': %s.\n",
			ldn, ldap_err2string(rc));
		rval = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto done;
	}
	/* Read their parents' for "cn" values. */
	n = ldap_count_entries(ld, lresult);
	if (n == 0) {
		fprintf(stderr, "No CA masters found.\n");
		ldap_msgfree(lresult);
		rval = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto done;
	}
	list = talloc_array_ptrtype(NULL, list, n + 2);
	if (list == NULL) {
		fprintf(stderr, "Out of memory.\n");
		rval = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto done;
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
									  "https://%.*s/ipa/json",
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
		ldap_memfree(dn);
	}
	ldap_msgfree(lresult);
	if (i == 0) {
		free(list);
		rval = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto done;
	}
	list[i] = NULL;
	*uris = list;
	rval = CM_SUBMIT_STATUS_ISSUED;

done:
	if (ld) {
		ldap_unbind_ext(ld, NULL, NULL);
	}

	return rval;
}

/*
 * Parse the JSON response from the IPA server.
 *
 * It will return one of three types of values:
 * 
 * < 0 is failure to parse JSON output
 * 0 is success, no errors were found
 * > 0 is the IPA API error code
 */
static int
parse_json_result(const char *result, char **error_message) {
	json_error_t j_error;

	json_t *j_root = NULL;
	json_t *j_error_obj = NULL;

	int error_code = 0;
	char * message = NULL;

	j_root = json_loads(result, 0, &j_error);
	if (!j_root) {
		cm_log(0, "Parsing JSON-RPC response failed: %s\n", j_error.text);
		return -1;
	}

	j_error_obj = json_object_get(j_root, "error");
	if (!j_error_obj || json_is_null(j_error_obj)) {
		json_decref(j_root);
		return 0;  // no errors
	}

	if (json_unpack_ex(j_error_obj, &j_error, 0, "{s:i, s:s}",
					   "code", &error_code,
					   "message", &message) != 0) {
		cm_log(0, "Failed extracting error from JSON-RPC response: %s\n", j_error.text);
		json_decref(j_root);
		return -1;
	}

	cm_log(0, "JSON-RPC error: %d: %s\n", error_code, message);
	*error_message = strdup(message);
	json_decref(j_root);
	return error_code;
}

/* Make an XML-RPC request to the "cert_request" method. */
static int
submit_or_poll_uri(const char *uri, const char *cainfo, const char *capath,
		   const char *uid, const char *pwd, const char *csr,
		   const char *reqprinc, const char *profile,
		   const char *issuer, int verbose)
{
	void *ctx;
	struct cm_submit_h_context *hctx;
	char *s, *p;
	int i;
	json_t *json_req = NULL;
	json_error_t j_error;
	const char *results = NULL;
	char *json_str = NULL;
	char *error_message = NULL;
	char *referer = NULL;
	int rval = 0;
	json_t *j_root = NULL;
	json_t *j_result_outer = NULL;
	json_t *j_result = NULL;
	json_t *j_cert = NULL;
	const char *certificate = NULL;

	if ((uri == NULL) || (strlen(uri) == 0)) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	ctx = talloc_new(NULL);

	referer = talloc_asprintf(ctx, "%s", uri);

	/* Prepare to make a JSON-RPC request. */
submit:
	json_req = json_pack_ex(&j_error, 0,
							"{s:s, s:[[s], {s:s, s:s*, s:s*, s:b}]}",
							"method", "cert_request",
							"params",
							csr,
							"principal", reqprinc,
							"profile_id", profile,
							"cacn", issuer,
							"add", 1);
	if (!json_req) {
		cm_log(0, "json_pack_ex() failed: %s\n", j_error.text);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	json_str = json_dumps(json_req, 0);
	json_decref(json_req);
	if (!json_str) {
		cm_log(0, "json_dumps() failed\n");
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	hctx = cm_submit_h_init(ctx, "POST", uri, json_str,
				       "application/json", "application/json",
				       referer, cainfo, capath,
				       NULL, NULL, NULL, 
				       cm_submit_h_negotiate_on,
				       cm_submit_h_delegate_off,
				       cm_submit_h_clientauth_off,
				       cm_submit_h_env_modify_off,
				       verbose > 1 ?
				       cm_submit_h_curl_verbose_on :
				       cm_submit_h_curl_verbose_off);
	free(json_str);

	if (hctx == NULL) {
		fprintf(stderr, "Error setting up JSON-RPC to %s on "
			"the client.\n", uri);
		printf(_("Error setting up for JSON-RPC on the client.\n"));
		rval = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto cleanup;
	}

	/* Submit the request. */
	fprintf(stderr, "Submitting request to \"%s\".\n", uri);
	cm_submit_h_run(hctx);

	/* Check the results. */

	results = cm_submit_h_results(hctx, NULL);
	cm_log(1, "%s\n", results);
	if (cm_submit_h_response_code(hctx) != 200) {
		cm_log(0, "JSON-RPC call failed with HTTP status code: %d\n",
				  cm_submit_h_response_code(hctx));
		cm_log(0, "code = %d, code_text = \"%s\"\n",
			cm_submit_h_result_code(hctx), cm_submit_h_result_code_text(hctx));
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto cleanup;
	}
	i = parse_json_result(results, &error_message);
	if (i < 0) {
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto cleanup;
	}
	if (i > 0) {
		/* Interpret the error.  See errors.py to get the
		 * classifications. */
		switch (i / 1000) {
		case 2: /* authorization error - permanent */
		case 3: /* invocation error - permanent */
			if ((i == 3005) && (issuer != NULL)) {
				/* Most likely the server didn't understand the
				 * "cacn" argument.  At least, at this
				 * point.  Randomly dropping arguments is not
				 * really an extensible solution, though. */
				issuer = NULL;
				goto submit;
			}
			if ((i == 3005) && (profile != NULL)) {
				/* Most likely the server didn't understand the
				 * "profile_id" argument.  At least, at this
				 * point.  Randomly dropping arguments is not
				 * really an extensible solution, though. */
				profile = NULL;
				goto submit;
			}
			printf("Server at %s denied our request, "
			       "giving up: %d (%s).\n", uri, i,
			       error_message);
			rval = CM_SUBMIT_STATUS_REJECTED;
			goto cleanup;
			break;
		case 1: /* authentication error - transient? */
		case 4: /* execution error - transient? */
		case 5: /* generic error - transient? */
		default:
			printf("Server at %s failed request, "
			       "will retry: %d (%s).\n", uri, i,
			       error_message);
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			goto cleanup;
			break;
		}
	} else {
		j_root = json_loads(results, 0, &j_error);
		if (!j_root) {
			cm_log(0, "Parsing JSON-RPC response failed: %s\n", j_error.text);
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			goto cleanup;
		}

		j_result_outer = json_object_get(j_root, "result");
		if (!j_result_outer) {
			cm_log(0, "Parsing JSON-RPC response failed, no outer result\n");
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			goto cleanup;
		}

		j_result = json_object_get(j_result_outer, "result");
		if (!j_result) {
			cm_log(0, "Parsing JSON-RPC response failed, no inner result\n");
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			goto cleanup;
		}

		j_cert = json_object_get(j_result, "certificate");
		if (!j_cert) {
			cm_log(0, "Parsing JSON-RPC response failed, no certificate\n");
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			goto cleanup;
		}
		certificate = json_string_value(j_cert);

		if (certificate) {
			/* If we got a certificate, we're probably
			 * okay. */
			fprintf(stderr, "Certificate: \"%s\"\n", certificate);
			s = cm_submit_u_base64_from_text(certificate);
			if (s == NULL) {
				printf("Out of memory parsing server "
				       "response, will retry.\n");
				rval = CM_SUBMIT_STATUS_UNREACHABLE;
				goto cleanup;
			}
			p = cm_submit_u_pem_from_base64("CERTIFICATE",
							FALSE, s);
			if (p != NULL) {
				printf("%s", p);
			}
			free(s);
			free(p);
			rval = CM_SUBMIT_STATUS_ISSUED;
			goto cleanup;
		} else {
			rval = CM_SUBMIT_STATUS_REJECTED;
		}
	}

cleanup:
	free(error_message);
	json_decref(j_root);
	cm_submit_h_cleanup(hctx);
	talloc_free(ctx);

	return rval;
}

static int
submit_or_poll(const char *uri, const char *cainfo, const char *capath,
	       const char *server, int ldap_uri_cmd, const char *ldap_uri,
	       const char *host, const char *domain, char *basedn,
	       const char *uid, const char *pwd, const char *csr,
	       const char *reqprinc, const char *profile, const char *issuer,
	       int verbose)
{
	int i, u;
	char **uris;

	i = submit_or_poll_uri(uri, cainfo, capath, uid, pwd, csr, reqprinc,
			       profile, issuer, verbose);
	if ((i == CM_SUBMIT_STATUS_UNREACHABLE) ||
	    (i == CM_SUBMIT_STATUS_UNCONFIGURED)) {
		u = cm_locate_jsonrpc_service(server, ldap_uri_cmd, ldap_uri,
					     host, domain, basedn, "CA", &uris);
		if ((u == 0) && (uris != NULL)) {
			for (u = 0; uris[u] != NULL; u++) {
				if (strcmp(uris[u], uri) == 0) {
					continue;
				}
				i = submit_or_poll_uri(uris[u], cainfo, capath,
						       uid, pwd, csr, reqprinc,
						       profile, issuer, verbose);
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
	    const char *host, const char *uid, const char *pwd,
	    const char *domain, char *basedn)
{
	char *realm = NULL;
	LDAP *ld = NULL;
	LDAPMessage *lresult = NULL, *lmsg = NULL;
	char *lattrs[2] = {"caCertificate;binary", NULL};
	const char *relativedn = "cn=certificates,cn=ipa,cn=etc";
	const char *relativecompatdn = "cn=cacert,cn=ipa,cn=etc";
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
			free(basedn);
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
	rc = ldap_search_ext_s(ld, ldn, LDAP_SCOPE_SUBTREE,
			       lfilter, lattrs, 0, NULL, NULL, NULL,
			       LDAP_NO_LIMIT, &lresult);
    if (rc == LDAP_SUCCESS && ldap_count_entries(ld, lresult) == 0) {
		/* Fall back to the old location */
		snprintf(ldn, sizeof(ldn), "%s,%s", relativecompatdn, basedn);
		rc = ldap_search_ext_s(ld, ldn, LDAP_SCOPE_SUBTREE,
				       lfilter, lattrs, 0, NULL, NULL, NULL,
				       LDAP_NO_LIMIT, &lresult);
	}
	free(basedn);
	if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "Error searching '%s': %s.\n",
			ldn, ldap_err2string(rc));
		return CM_SUBMIT_STATUS_ISSUED;
	}
	/* Read our realm name from our ccache. */
	realm = cm_submit_ccache_realm(&kerr);
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
	if (ld) {
		ldap_unbind_ext(ld, NULL, NULL);
	}
	return CM_SUBMIT_STATUS_ISSUED;
}

int
main(int argc, const char **argv)
{
	int c, make_keytab_ccache = TRUE;
	const char *host = NULL, *domain = NULL, *cainfo = NULL, *capath = NULL;
	const char *ktname = NULL, *kpname = NULL;
	char *csr, *p, uri[LINE_MAX], *reqprinc = NULL, *ipaconfig, *kerr;
	char *uid = NULL, *pwd = NULL, *pwdfile = NULL;
	const char *xmlrpc_uri = NULL, *ldap_uri = NULL, *server = NULL, *csrfile;
	const char *jsonrpc_uri = NULL;
	int jsonrpc_uri_cmd = 0, ldap_uri_cmd = 0, verbose = 0;
	const char *mode = CM_OP_SUBMIT;
	char ldn[LINE_MAX], *basedn = NULL, *profile = NULL, *issuer = NULL;
	krb5_error_code kret;
	poptContext pctx;
	struct poptOption popts[] = {
		{"host", 'h', POPT_ARG_STRING, &host, 0, "IPA server hostname", "HOSTNAME"},
		{"domain", 'd', POPT_ARG_STRING, &domain, 0, "IPA domain name", "NAME"},
		{"xmlrpc-url", 'H', POPT_ARG_STRING, NULL, 'H', "IPA XMLRPC service location", "URL"},
		{"jsonrpc-url", 'J', POPT_ARG_STRING, NULL, 'J', "IPA JSON-RPC service location", "URL"},
		{"ldap-url", 'L', POPT_ARG_STRING, NULL, 'L', "IPA LDAP service location", "URL"},
		{"capath", 'C', POPT_ARG_STRING, &capath, 0, NULL, "DIRECTORY"},
		{"cafile", 'c', POPT_ARG_STRING, &cainfo, 0, NULL, "FILENAME"},
		{"keytab-name", 't', POPT_ARG_STRING, NULL, 't', "location of credentials to use for authenticating to server", "KEYTAB"},
		{"submitter-principal", 'k', POPT_ARG_STRING, &kpname, 'k', "principal name to use for authenticating to server", "PRINCIPAL"},
		{"use-ccache-creds", 'K', POPT_ARG_NONE, NULL, 'K', "use default ccache instead of creating a new one using keytab", NULL},
		{"uid", 'u', POPT_ARG_STRING, &uid, 0, "authenticate to server using Basic authentication", "USERNAME"},
		{"pwd", 'W', POPT_ARG_STRING, &pwd, 0, "password to use when using Basic authentication", "PASSWORD"},
		{"pwdfile", 'w', POPT_ARG_STRING, &pwdfile, 0, "read password from file for Basic authentication", "FILENAME"},
		{"principal-of-request", 'P', POPT_ARG_STRING, &reqprinc, 0, "principal name in signing request", "PRINCIPAL"},
		{"profile", 'T', POPT_ARG_STRING, &profile, 0, "request enrollment using the specified profile", "NAME"},
		{"issuer", 'X', POPT_ARG_STRING, &issuer, 0, "request enrollment using the specified CA", "NAME"},
		{"basedn", 'b', POPT_ARG_STRING, &basedn, 0, "IPA domain LDAP base DN", "DN"},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

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

	pctx = poptGetContext(argv[0], argc, argv, popts, 0);
	if (pctx == NULL) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	poptSetOtherOptionHelp(pctx, "[options] [csrfile]");
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 'H': /* XMLRPC URI kept for backwards compatibility */
		case 'J':
			jsonrpc_uri = poptGetOptArg(pctx);
			jsonrpc_uri_cmd++;
			break;
		case 'L':
			ldap_uri = poptGetOptArg(pctx);
			ldap_uri_cmd++;
			break;
		case 't':
			ktname = poptGetOptArg(pctx);
			if (!make_keytab_ccache) {
				printf(_("The -t option can not be used with "
					 "the -K option.\n"));
				poptPrintUsage(pctx, stdout, 0);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			break;
		case 'k':
			kpname = poptGetOptArg(pctx);
			if (!make_keytab_ccache) {
				printf(_("The -k option can not be used with "
					 "the -K option.\n"));
				poptPrintUsage(pctx, stdout, 0);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			break;
		case 'K':
			make_keytab_ccache = FALSE;
			if ((kpname != NULL) || (ktname != NULL)) {
				printf(_("The -K option can not be used with "
					 "either the -k or the -t option.\n"));
				poptPrintUsage(pctx, stdout, 0);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			break;
		case 'v':
			verbose++;
			break;
		}
	}
	if (c != -1) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	umask(S_IRWXG | S_IRWXO);
	if (isatty(STDERR_FILENO))
		cm_log_set_method(cm_log_stderr);
	else
		cm_log_set_method(cm_log_syslog);
	cm_log_set_level(verbose);

	/* Start backfilling defaults, both hard-coded and from the IPA
	 * configuration. */
	if (cainfo == NULL) {
		struct stat st;
		if (stat("/etc/ipa/ca.crt", &st) == 0) {
			cainfo = "/etc/ipa/ca.crt";
		}
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
			if (jsonrpc_uri == NULL) {
				jsonrpc_uri = get_config_entry(ipaconfig,
							      "global",
							      "jsonrpc_uri");
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
	free(ipaconfig);
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
			poptPrintUsage(pctx, stdout, 0);
			free(reqprinc);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		if ((profile == NULL) &&
		    (getenv(CM_SUBMIT_PROFILE_ENV) != NULL)) {
			profile = strdup(getenv(CM_SUBMIT_PROFILE_ENV));
		}
		if ((issuer == NULL) &&
		    (getenv(CM_SUBMIT_ISSUER_ENV) != NULL)) {
			issuer = strdup(getenv(CM_SUBMIT_ISSUER_ENV));
		}
		if ((server != NULL) && !jsonrpc_uri_cmd) {
			snprintf(uri, sizeof(uri),
				 "https://%s/ipa/json", server);
		} else
		if (jsonrpc_uri != NULL) {
			snprintf(uri, sizeof(uri), "%s", jsonrpc_uri);
		} else
		if (xmlrpc_uri != NULL) {
			/* strip off the trailing xml and replace with json */
			if ((strlen(xmlrpc_uri) + 1) > sizeof(uri)) {
				printf(_("xmlrpc_uri is longer than %ld.\n"), sizeof(uri) - 2);
				return CM_SUBMIT_STATUS_UNCONFIGURED;
			}
			snprintf(uri, strlen(xmlrpc_uri) - 2, "%s", xmlrpc_uri);
			strcat(uri, "json");
		} else
		if (host != NULL) {
			snprintf(uri, sizeof(uri),
				 "https://%s/ipa/json", host);
		}

		/* Read the CSR from the environment, or from the file named on
		 * the command-line. */
		csrfile = poptGetArg(pctx);
		if (csrfile != NULL) {
			csr = cm_submit_u_from_file(csrfile);
		} else {
			csr = getenv(CM_SUBMIT_CSR_ENV);
			if (csr != NULL) {
				csr = strdup(csr);
			}
		}
		if ((csr == NULL) || (strlen(csr) == 0)) {
			if (csrfile != NULL) {
				printf(_("Unable to read signing request from file \"%s\".\n"),
				       csrfile);
			} else {
				printf(_("Unable to read signing request from environment variable \"%s\".\n"),
				       CM_SUBMIT_CSR_ENV);
			}
			free(csr);
			free(profile);
			free(issuer);
			free(reqprinc);
			poptPrintUsage(pctx, stdout, 0);
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

	/* If we're supposed to read a password from a file, read it now. */
	if ((pwdfile != NULL) && (pwd == NULL)) {
		pwd = cm_submit_u_from_file(pwdfile);
		if (pwd == NULL) {
			fprintf(stderr,
				"Error reading password from \"%s\": %s.\n",
				pwdfile, strerror(errno));
			free(csr);
			free(profile);
			free(issuer);
			free(reqprinc);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
	}

	/* If we're using Basic auth, make sure we don't try to set up a
	 * ccache. */
	if ((uid != NULL) && (pwd != NULL)) {
		make_keytab_ccache = FALSE;
	} else {
		if ((uid != NULL) || (pwd != NULL)) {
			fprintf(stderr,
				"Both -u and -W/-w options should be specified.\n");
			free(csr);
			free(profile);
			free(issuer);
			free(reqprinc);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
	}

	/* Setup a ccache unless we're told to use the default one. */
	kerr = NULL;
	if (make_keytab_ccache &&
	    ((kret = cm_submit_make_ccache(ktname, kpname, &kerr)) != 0)) {
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
		free(csr);
		free(profile);
		free(issuer);
		free(reqprinc);
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
		int ret;
		ret = submit_or_poll(uri, cainfo, capath, server,
				      ldap_uri_cmd, ldap_uri, host, domain,
				      basedn, uid, pwd, csr, reqprinc, profile,
				      issuer, verbose);
		free(csr);
		free(profile);
		free(issuer);
		free(reqprinc);
		free(basedn);
		return ret;
	} else
	if (strcasecmp(mode, CM_OP_FETCH_ROOTS) == 0) {
		return fetch_roots(server, ldap_uri_cmd, ldap_uri, host,
				   uid, pwd, domain, basedn);
	}

	return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
}
