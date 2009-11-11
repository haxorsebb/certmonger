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
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <talloc.h>

#include "certext.h"
#include "csrgen.h"
#include "csrgen-int.h"
#include "keygen.h"
#include "log.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"

struct cm_csrgen_state {
	struct cm_csrgen_state_pvt pvt;
	struct cm_subproc_state *subproc;
};

static int
cm_csrgen_o_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	FILE *keyfp, *status;
	X509 *x;
	X509_REQ *req;
	RSA *rsa;
	EVP_PKEY *pkey;
	char buf[LINE_MAX], *p, *q, *s, *nickname;
	unsigned char *extensions, *unickname;
	const char *default_cn = CM_DEFAULT_CERT_SUBJECT_CN;
	size_t extensions_len;
	long error;
	int i;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(1);
	}
	keyfp = fopen(entry->cm_key_storage_location, "r");
	if (keyfp == NULL) {
		fprintf(status, "Error opening key file \"%s\" for reading.\n",
			entry->cm_key_storage_location);
		cm_log(1, "Error opening key file \"%s\" for reading.\n",
		       entry->cm_key_storage_location);
		_exit(2);
	}
	OpenSSL_add_ssl_algorithms();
	ERR_load_crypto_strings();
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		fprintf(status, "Internal error generating CSR.\n");
		cm_log(1, "Internal error generating CSR.\n");
		_exit(2);
	}
	rsa = PEM_read_RSAPrivateKey(keyfp, NULL, NULL, NULL);
	if (rsa != NULL) {
		EVP_PKEY_assign_RSA(pkey, rsa); /* pkey owns rsa now */
		x = X509_new();
		if (x != NULL) {
			if (entry->cm_template_subject != NULL) {
				/* This isn't really correct, but it will
				 * probably do for now. */
				p = entry->cm_template_subject;
				q = p + strcspn(p, ",");
				while (*p != '\0') {
					if ((s = memchr(p, '=', q - p)) != NULL) {
						*s = '\0';
						for (i = 0; p[i] != '\0'; i++) {
							p[i] = toupper(p[i]);
						}
						X509_NAME_add_entry_by_txt(x->cert_info->subject,
									   p, MBSTRING_UTF8,
									   (unsigned char *) (s + 1), q - s - 1,
									   -1, 0);
						*s = '=';
					} else {
						X509_NAME_add_entry_by_txt(x->cert_info->subject,
									   "CN", MBSTRING_UTF8,
									   (unsigned char *) p, q - p,
									   -1, 0);
					}
					p = q + strspn(q, ",");
					q = p + strcspn(p, ",");
				}
			} else {
				X509_NAME_add_entry_by_txt(x->cert_info->subject,
							   "CN", MBSTRING_UTF8,
							   (const unsigned char *) default_cn,
							   strlen(default_cn),
							   -1, 0);
			}
			X509_set_pubkey(x, pkey);
			req = X509_to_X509_REQ(x, pkey, EVP_sha256()); /* XXX */
			if (req != NULL) {
				/* Add attributes. */
				extensions = NULL;
				cm_certext_build_csr_extensions(entry,
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
				} else {
					nickname = entry->cm_id;
				}
				unickname = (unsigned char *) nickname;
				if (nickname != NULL) {
					X509_REQ_add1_attr_by_NID(req,
								  NID_friendlyName,
								  V_ASN1_PRINTABLESTRING,
								  unickname,
								  strlen(nickname));
				}
				X509_REQ_sign(req, pkey, EVP_sha256()); /* XXX */
				PEM_write_X509_REQ_NEW(status, req);
			} else {
				fprintf(status,
					"Error converting template certificate "
					"into a CSR.\n");
				cm_log(1,
				       "Error converting template certificate "
				       "into a CSR.\n");
				while ((error = ERR_get_error()) != 0) {
					ERR_error_string_n(error, buf,
							   sizeof(buf));
					cm_log(1, "%s\n", buf);
				}
				_exit(2);
			}
		} else {
			fprintf(status,
				"Error creating template certificate.\n");
			cm_log(1, "Error creating template certificate.\n");
			while ((error = ERR_get_error()) != 0) {
				ERR_error_string_n(error, buf, sizeof(buf));
				cm_log(1, "%s\n", buf);
			}
			_exit(2);
		}
	} else {
		error = errno;
		fprintf(status, "Error reading private key '%s': %s.\n",
		        entry->cm_key_storage_location, strerror(error));
		cm_log(1, "Error reading private key '%s': %s.\n",
		       entry->cm_key_storage_location, strerror(error));
		while ((error = ERR_get_error()) != 0) {
			ERR_error_string_n(error, buf, sizeof(buf));
			cm_log(1, "%s\n", buf);
		}
		_exit(2);
	}
	while ((error = ERR_get_error()) != 0) {
		ERR_error_string_n(error, buf, sizeof(buf));
		cm_log(1, "%s\n", buf);
	}
	fflush(status);
	fclose(status);
	fclose(keyfp);
	return 0;
}

/* Check if a CSR is ready. */
static int
cm_csrgen_o_ready(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_csrgen_o_get_fd(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Save the CSR to the entry. */
static int
cm_csrgen_o_save_csr(struct cm_store_entry *entry,
		     struct cm_csrgen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
		return -1;
	}
	talloc_free(entry->cm_csr);
	entry->cm_csr = talloc_strdup(entry,
				      cm_subproc_get_msg(entry,
				     			 state->subproc,
							 NULL));
	if (entry->cm_csr == NULL) {
		return ENOMEM;
	}
	return 0;
}

/* Clean up after CSR generation. */
static void
cm_csrgen_o_done(struct cm_store_entry *entry, struct cm_csrgen_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
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
		state->pvt.done = &cm_csrgen_o_done;
		state->subproc = cm_subproc_start(cm_csrgen_o_main,
						  NULL, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
