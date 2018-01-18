/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014,2015,2017 Red Hat, Inc.
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
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include <ldap.h>

#include <talloc.h>

#include "certext.h"
#include "csrgen.h"
#include "csrgen-int.h"
#include "keygen.h"
#include "log.h"
#include "pin.h"
#include "prefs.h"
#include "prefs-o.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "util-m.h"
#include "util-o.h"
#include "util.h"

struct cm_csrgen_state {
	struct cm_csrgen_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};

static int
astring_type(const char *attr, const char *p, ssize_t n)
{
	unsigned int i;

	if ((strcasecmp(attr, "CN") != 0) &&
	    (strcasecmp(attr, "commonName") != 0)) {
		return MBSTRING_UTF8;
	}
	if (n < 0) {
		n = strlen(p);
	}
	for (i = 0; i < n; i++) {
		if ((p[i] & 0x80) != 0) {
			return MBSTRING_UTF8;
		}
	}
	return V_ASN1_PRINTABLESTRING;
}

static X509_NAME *
ldap_dn_to_X509_NAME(char *s) {
	LDAPDN dn = NULL;
	LDAPRDN rdn = NULL;
	LDAPAVA *attr = NULL;
	int ret = ldap_str2dn(s, &dn, LDAP_DN_FORMAT_LDAPV3);
	if (ret != LDAP_SUCCESS)
		return NULL;

	X509_NAME *x509name = X509_NAME_new();
	if (x509name == NULL)
		return NULL;

	for (int i = 0; dn[i] != NULL; i++) {
		rdn = dn[i];
		int set = 0; // add next AVA in new RDN
		for (int j = 0; rdn[j] != NULL; j++) {
			attr = rdn[j];

			// process attribute type
			ASN1_OBJECT *obj = OBJ_txt2obj(
				attr->la_attr.bv_val,
				0 /* allow dotted OIDs */);
			if (obj == NULL) {
				// OpenSSL requires upper-cased short names
				// i.e. "CN", "O", etc.
				// Convert to upper and try again.
				char *attr_upper = str_to_upper(attr->la_attr.bv_val);
				if (attr_upper != NULL) {
					obj = OBJ_txt2obj(attr_upper, 0);
					free(attr_upper);
				}
			}

			if (obj == NULL) {
				cm_log(
					0,
					"Unrecognised attribute type: (%s). Continuing.\n",
					attr->la_attr.bv_val);
			} else {
				ret = X509_NAME_add_entry_by_OBJ(
					x509name,
					obj,
					astring_type(
						attr->la_attr.bv_val,
						attr->la_value.bv_val,
						attr->la_value.bv_len),
					(unsigned char *) attr->la_value.bv_val,
					attr->la_value.bv_len,
					-1, // append to RDN
					set);
				if (ret == 1) {
					set = -1; // add next AVA to previous RDN
				} else {
					cm_log(
						0,
						"Failed to add AVA to CSR: (%s=%s). Continuing.\n",
						attr->la_attr.bv_val,
						attr->la_value.bv_val);
				}
			}
		}
	}
	ldap_dnfree(dn);
	return x509name;
}

/* Create a single-AVA X509_NAME, with given string as CN */
static X509_NAME *
cn_to_X509_NAME(const char *s) {
	X509_NAME *n = X509_NAME_new();
	if (n != NULL) {
		X509_NAME_add_entry_by_txt(
			n,
			"CN",
			astring_type("CN", s, -1),
			(unsigned char *) s,
			-1 /* compute value length internally */,
			-1, 0);
	}
	return n;
}

static int
cm_csrgen_o_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	struct cm_pin_cb_data cb_data;
	FILE *keyfp, *status;
	X509_REQ *req;
	X509_NAME *subject;
	const X509_ALGOR *sig_alg;
	X509 *minicert;
	ASN1_INTEGER *serial, *version;
	ASN1_GENERALIZEDTIME *notBefore = NULL, *notAfter = NULL;
	NETSCAPE_SPKI spki;
	NETSCAPE_SPKAC spkac;
	EVP_PKEY *pkey;
	BIGNUM *serialbn;
	char buf[LINE_MAX], *s, *nickname, *pin, *password, *filename;
	unsigned char *extensions, *upassword, *bmp, *name, *up, *uq, md[CM_DIGEST_MAX];
	char *spkidec, *mcb64, *nows;
	const char *default_cn = CM_DEFAULT_CERT_SUBJECT_CN, *spkihex = NULL;
	const unsigned char *nametmp;
	struct tm *now;
	time_t nowt;
	size_t extensions_len;
	ssize_t len;
	unsigned int bmpcount, mdlen;
	long error;
	int i;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if ((entry->cm_key_next_marker != NULL) &&
	    (strlen(entry->cm_key_next_marker) > 0)) {
		filename = util_build_next_filename(entry->cm_key_storage_location, entry->cm_key_next_marker);
		if (filename == NULL) {
			cm_log(1, "Error opening key file \"%s\" "
			       "for reading: %s.\n",
			       filename, strerror(errno));
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
	} else {
		filename = entry->cm_key_storage_location;
	}
	keyfp = fopen(filename, "r");
	if (keyfp == NULL) {
		if (errno != ENOENT) {
			cm_log(1, "Error opening key file \"%s\" "
			       "for reading: %s.\n",
			       filename, strerror(errno));
		}
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	util_set_fd_entry_key_owner(fileno(keyfp), filename, entry);
	if (filename != entry->cm_key_storage_location) {
		free(filename);
	}
	filename = NULL;
	util_o_init();
	ERR_load_crypto_strings();
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		cm_log(1, "Internal error generating CSR.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	if (cm_pin_read_for_key(entry, &pin) != 0) {
		cm_log(1, "Internal error reading key encryption PIN.\n");
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}
	memset(&cb_data, 0, sizeof(cb_data));
	cb_data.entry = entry;
	cb_data.n_attempts = 0;
	pkey = PEM_read_PrivateKey(keyfp, NULL,
				   cm_pin_read_for_key_ossl_cb, &cb_data);
	if (pkey == NULL) {
		error = errno;
		cm_log(1, "Error reading private key '%s': %s.\n",
		       entry->cm_key_storage_location, strerror(error));
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		_exit(CM_SUB_STATUS_ERROR_AUTH); /* XXX */
	} else {
		if ((pin != NULL) &&
		    (strlen(pin) > 0) &&
		    (cb_data.n_attempts == 0)) {
			cm_log(1, "PIN was not needed to read private "
			       "key '%s', though one was provided. "
			       "Treating this as an error.\n",
			       entry->cm_key_storage_location);
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(CM_SUB_STATUS_ERROR_AUTH); /* XXX */
		}
	}
	if (pkey != NULL) {
		req = X509_REQ_new();
		if (req != NULL) {
			subject = NULL;
			if ((entry->cm_template_subject_der != NULL) &&
			    (strlen(entry->cm_template_subject_der) != 0)) {
				i = strlen(entry->cm_template_subject_der);
				name = malloc(i);
				if (name != NULL) {
					i = cm_store_hex_to_bin(entry->cm_template_subject_der,
								name, i);
					nametmp = name;
					subject = d2i_X509_NAME(NULL, &nametmp, i);
				}
			}
			if ((subject == NULL) &&
			    (entry->cm_template_subject != NULL) &&
			    (strlen(entry->cm_template_subject) != 0)) {
				subject = ldap_dn_to_X509_NAME(entry->cm_template_subject);

				if (subject == NULL) {
					subject = cn_to_X509_NAME(entry->cm_template_subject);
				}
			}
			if (subject == NULL) {
				subject = cn_to_X509_NAME(default_cn);
			}
			if (subject != NULL) {
				util_X509_REQ_set_subject_name(req, subject);
			}
			X509_REQ_set_pubkey(req, pkey);
			X509_REQ_set_version(req, SEC_CERTIFICATE_REQUEST_VERSION);
			/* Add attributes. */
			extensions = NULL;
			cm_certext_build_csr_extensions(entry, NULL,
							&extensions,
							&extensions_len);
			if ((extensions != NULL) &&
			    (extensions_len> 0)) {
				X509_REQ_add1_attr_by_NID(req,
							  NID_ext_req,
							  V_ASN1_SEQUENCE,
							  extensions,
							  extensions_len);
				talloc_free(extensions);
			}
			if (entry->cm_cert_nickname != NULL) {
				nickname = entry->cm_cert_nickname;
			} else
			if (entry->cm_key_nickname != NULL) {
				nickname = entry->cm_key_nickname;
			} else {
				nickname = entry->cm_nickname;
			}
			if ((nickname != NULL) &&
			    (cm_store_utf8_to_bmp_string(nickname, &bmp,
							 &bmpcount) == 0)) {
				X509_REQ_add1_attr_by_NID(req,
							  NID_friendlyName,
							  V_ASN1_BMPSTRING,
							  bmp,
							  bmpcount);
				free(bmp);
			}
			error = cm_csrgen_read_challenge_password(entry,
								  &password);
			if (error != 0) {
				cm_log(1, "Error reading challenge password: %s.\n",
				       strerror(error));
				while ((error = ERR_get_error()) != 0) {
					ERR_error_string_n(error, buf, sizeof(buf));
					cm_log(1, "%s\n", buf);
				}
				_exit(CM_SUB_STATUS_ERROR_AUTH); /* XXX */
			}
			upassword = (unsigned char *) password;
			if (password != NULL) {
				X509_REQ_add1_attr_by_NID(req,
							  NID_pkcs9_challengePassword,
							  V_ASN1_PRINTABLESTRING,
							  upassword,
							  strlen(password));
			}
			X509_REQ_sign(req, pkey, cm_prefs_ossl_hash());
			PEM_write_X509_REQ_NEW(status, req);
			/* Generate the SPKAC. */
			memset(&spkac, 0, sizeof(spkac));
			spkac.challenge = util_ASN1_IA5STRING_new();
			if (password != NULL) {
				ASN1_STRING_set(spkac.challenge,
						password, strlen(password));
			} else {
				ASN1_STRING_set(spkac.challenge,
						"", 0);
			}
			memset(&spki, 0, sizeof(spki));
			spki.spkac = &spkac;
			util_X509_REQ_get0_signature(req, NULL, &sig_alg);
			util_NETSCAPE_SPKI_set_sig_alg(&spki, sig_alg);
			spki.signature = util_ASN1_BIT_STRING_new();
			NETSCAPE_SPKI_set_pubkey(&spki, pkey);
			NETSCAPE_SPKI_sign(&spki, pkey, cm_prefs_ossl_hash());
			s = NETSCAPE_SPKI_b64_encode(&spki);
			if (s != NULL) {
				fprintf(status, "%s", s);
			}
			/* Generate the SCEP transaction identifier. */
			spkidec = NULL;
			len = i2d_PUBKEY(pkey, NULL);
			if (len > 0) {
				up = malloc(len);
				if (up != NULL) {
					uq = up;
					if (i2d_PUBKEY(pkey, &uq) == len) {
						if (EVP_Digest(up, uq - up, md, &mdlen, cm_prefs_ossl_hash(), NULL)) {
							spkihex = cm_store_hex_from_bin(NULL, md, mdlen);
							if (spkihex != NULL) {
								spkidec = util_dec_from_hex(spkihex);
							}
						}
					}
					free(up);
				}
			}
			fprintf(status, "\n%s\n", spkidec ? spkidec : "");
			/* Generate a "mini" certificate. */
			minicert = X509_new();
			if (minicert == NULL) {
				cm_log(1, "Out of memory creating mini certificate.\n");
				_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			}
			nowt = time(NULL);
			now = gmtime(&nowt);
			nows = talloc_asprintf(entry, "%04d%02d%02d000000Z",
					       now->tm_year + 1900, now->tm_mon + 1, now->tm_mday);
			notBefore = util_ASN1_GENERALIZEDTIME_new();
			ASN1_GENERALIZEDTIME_set_string(notBefore, nows);
			util_X509_set1_notBefore(minicert, notBefore);
			nows = talloc_asprintf(entry, "%04d%02d%02d000000Z",
					       now->tm_year + 1900 + 100, now->tm_mon + 1, now->tm_mday);
			notAfter = util_ASN1_GENERALIZEDTIME_new();
			ASN1_GENERALIZEDTIME_set_string(notAfter, nows);
			util_X509_set1_notAfter(minicert, notAfter);
			util_X509_set_issuer_name(minicert, subject);
			util_X509_set_subject_name(minicert, subject);
			version = util_ASN1_INTEGER_new();
			if (version == NULL) {
				cm_log(1, "Out of memory creating mini certificate.\n");
				_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			}
			ASN1_INTEGER_set(version, cm_csrgen_version_for_testing_minicerts);
			util_X509_set1_version(minicert, version);
			serial = util_ASN1_INTEGER_new();
			if (serial == NULL) {
				cm_log(1, "Out of memory creating mini certificate.\n");
				_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			}
			serialbn = NULL;
			if ((spkidec != NULL) && (BN_dec2bn(&serialbn, spkidec) != 0)) {
				if (BN_to_ASN1_INTEGER(serialbn, serial) != serial) {
					cm_log(1, "Error setting serial number.\n");
					_exit(CM_SUB_STATUS_INTERNAL_ERROR);
				}
			} else {
				ASN1_INTEGER_set(serial, 1);
			}
			X509_set_serialNumber(minicert, serial);
			X509_set_pubkey(minicert, pkey);
			X509_sign(minicert, pkey, cm_prefs_ossl_hash());
			len = i2d_X509(minicert, NULL);
			mcb64 = NULL;
			if (len > 0) {
				up = malloc(len);
				if (up != NULL) {
					uq = up;
					if (i2d_X509(minicert, &uq) == len) {
						mcb64 = cm_store_base64_from_bin(entry,
										 up,
										 uq - up);
					}
				}
			}
			fprintf(status, "%s\n", mcb64 ? mcb64 : "");
		} else {
			cm_log(1, "Error creating template certificate.\n");
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
	}
	while ((error = ERR_get_error()) != 0) {
		ERR_error_string_n(error, buf, sizeof(buf));
		cm_log(1, "%s\n", buf);
	}
	free(spkidec);
	fclose(status);
	fclose(keyfp);
	_exit(0);
}

/* Check if a CSR is ready. */
static int
cm_csrgen_o_ready(struct cm_csrgen_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_csrgen_o_get_fd(struct cm_csrgen_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Save the CSR to the entry. */
static int
cm_csrgen_o_save_csr(struct cm_csrgen_state *state)
{
	int status;
	char *p, *q;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
		return -1;
	}
	talloc_free(state->entry->cm_csr);
	state->entry->cm_csr =
		talloc_strdup(state->entry,
			      cm_subproc_get_msg(state->subproc, NULL));
	if (state->entry->cm_csr == NULL) {
		return ENOMEM;
	}
	p = strstr(state->entry->cm_csr, "-----END");
	if (p != NULL) {
		p = strstr(p, "REQUEST-----");
		if (p != NULL) {
			p += strcspn(p, "\r\n");
			q = p + strspn(p, "\r\n");
			p = q + strcspn(q, "\r\n");
			state->entry->cm_spkac = talloc_strndup(state->entry, q, p - q);
			if (state->entry->cm_spkac == NULL) {
				return ENOMEM;
			}
			*q = '\0';
			q = p + strspn(p, "\r\n");
			p = q + strcspn(q, "\r\n");
			if (p > q) {
				state->entry->cm_scep_tx = talloc_strndup(state->entry, q, p - q);
				if (state->entry->cm_scep_tx == NULL) {
					return ENOMEM;
				}
			}
			*q = '\0';
			q = p + strspn(p, "\r\n");
			p = q + strcspn(q, "\r\n");
			if (p > q) {
				state->entry->cm_minicert = talloc_strndup(state->entry, q, p - q);
				if (state->entry->cm_minicert == NULL) {
					return ENOMEM;
				}
			}
			state->entry->cm_scep_nonce = NULL;
			state->entry->cm_scep_last_nonce = NULL;
			state->entry->cm_scep_req = NULL;
			state->entry->cm_scep_req_next = NULL;
			state->entry->cm_scep_gic = NULL;
			state->entry->cm_scep_gic_next = NULL;
		}
	}
	return 0;
}

/* Check if we need a PIN (or a new PIN) to access the key information. */
static int
cm_csrgen_o_need_pin(struct cm_csrgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to access the key information. */
static int
cm_csrgen_o_need_token(struct cm_csrgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Clean up after CSR generation. */
static void
cm_csrgen_o_done(struct cm_csrgen_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start CSR generation using template information in the entry. */
struct cm_csrgen_state *
cm_csrgen_o_start(struct cm_store_entry *entry)
{
	struct cm_csrgen_state *state;
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = &cm_csrgen_o_ready;
		state->pvt.get_fd = &cm_csrgen_o_get_fd;
		state->pvt.save_csr = &cm_csrgen_o_save_csr;
		state->pvt.need_pin = &cm_csrgen_o_need_pin;
		state->pvt.need_token = &cm_csrgen_o_need_token;
		state->pvt.done = &cm_csrgen_o_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_csrgen_o_main, state,
						  NULL, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
