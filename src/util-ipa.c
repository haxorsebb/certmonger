/*
 * Copyright (C) 2024 Red Hat, Inc.
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

const char *
get_error_message(krb5_context ctx, krb5_error_code kcode)
{
	const char *ret;
#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
	const char *kret;
	kret = ctx ? krb5_get_error_message(ctx, kcode) : NULL;
	if (kret == NULL) {
		ret = error_message(kcode);
	} else {
		ret = strdup(kret);
		krb5_free_error_message(ctx, kret);
	}
	return ret;
#else
	ret = error_message(kcode);
	return strdup(ret);
#endif
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
			ret = (char *)get_error_message(ctx, kret));
		if (msg != NULL) {
			*msg = (char *)ret;
		} else {
			free(ret);
		}
		return NULL;
	}
	kret = krb5_cc_default(ctx, &ccache);
	if (kret != 0) {
		fprintf(stderr, "Error resolving default ccache: %s.\n",
			ret = (char *)get_error_message(ctx, kret));
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
			ret = (char *)get_error_message(ctx, kret));
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
			*msg = strdup("Error retrieving principal realm.\n");
		}
		return NULL;
	}
	ret = malloc(data->length + 1);
	if (ret == NULL) {
		fprintf(stderr, "Out of memory for principal realm.\n");
		if (msg != NULL) {
			*msg = strdup("Out of memory for principal realm.\n");
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
		ret = (char *)get_error_message(ctx, kret);
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
			ret = (char *)get_error_message(ctx, kret));
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
				principal, ret = (char *)get_error_message(ctx, kret));
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
				ret = (char *)get_error_message(ctx, kret));
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
			ret = (char *)get_error_message(ctx, kret));
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
			ret = (char *)get_error_message(ctx, kret));
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
			ret = (char *)get_error_message(ctx, kret));
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
			ret = (char *)get_error_message(ctx, kret));
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

/*
 * Parse the JSON response from the IPA server.
 *
 * It will return one of three types of values:
 * 
 * < 0 is failure to parse JSON output
 * 0 is success, no errors were found
 * > 0 is the IPA API error code
 */
int
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
