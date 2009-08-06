#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "log.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"

struct cm_submit_state {
	X509 *cert;
};

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_start(struct cm_store_entry *entry)
{
	struct cm_submit_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_file) {
		cm_log(1, "Wrong submission method: only keys stored "
		       "in files can be used.\n");
		return NULL;
	}
	if (entry->cm_cert_storage_type != cm_cert_storage_file) {
		cm_log(1, "Wrong submission method: only certificates stored "
		       "in files can be used.\n");
		return NULL;
	}
	state = malloc(sizeof(*state));
	if (state == NULL) {
		cm_log(1, "Out of memory.\n");
		return NULL;
	}
	state->cert = NULL;
	return state;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_submit_get_fd(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return -1; /* caller is going to have to poll */
}

/* Check if the CSR was received by the CA yet. */
int
cm_submit_sent(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	return 0;
}

/* Save CA-specific identifier for our submitted request. */
int
cm_submit_save_ca_cookie(struct cm_store_entry *entry,
			 struct cm_submit_state *state)
{
	free(entry->cm_ca_cookie);
	entry->cm_ca_cookie = strdup(entry->cm_key_storage_location);
	if (entry->cm_ca_cookie == NULL) {
		cm_log(1, "Out of memory.\n");
		return ENOMEM;
	}
	return 0;
}

/* Pick up after a CSR has been "submitted", in case we haven't yet gotten a
 * decision about it. */
struct cm_submit_state *
cm_submit_resume(struct cm_store_entry *entry)
{
	struct cm_submit_state *state;
	state = cm_submit_start(entry);
	cm_submit_save_ca_cookie(entry, state);
	return state;
}

/* Check if an attempt to get status has succeeded. */
int
cm_submit_status_ready(struct cm_store_entry *entry,
		       struct cm_submit_state *state)
{
	return 0;
}

/* Check if the certificate was issued. */
int
cm_submit_issued(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	FILE *keyfp;
	RSA *rsa;
	EVP_PKEY *pkey;
	X509_REQ *req;
	X509 *cert;
	BIO *bio;
	int status;
	OpenSSL_add_ssl_algorithms();
	status = -1;
	keyfp = fopen(entry->cm_key_storage_location, "r");
	if (keyfp != NULL) {
		pkey = EVP_PKEY_new();
		if (pkey != NULL) {
			rsa = d2i_RSAPrivateKey_fp(keyfp, &rsa);
			if (rsa != NULL) {
				EVP_PKEY_assign_RSA(pkey, rsa);
				bio = BIO_new_mem_buf(entry->cm_csr,
						      strlen(entry->cm_csr));
				if (bio != NULL) {
					req = d2i_X509_REQ_bio(bio, &req);
					if (req != NULL) {
						cert = X509_REQ_to_X509(req, 30,
									pkey);
						X509_sign(cert, pkey,
							  EVP_sha256());
						status = 0;
					} else {
						cm_log(1, "Error reading "
						       "signing request.\n");
					}
					BIO_free(bio);
				} else {
					cm_log(1, "Error parsing signing "
					       "request.\n");
				}
				RSA_free(rsa);
			} else {
				cm_log(1, "Error reading private key from "
				       "'%s': %s.\n",
				       entry->cm_key_storage_location,
				       strerror(errno));
			}
			EVP_PKEY_free(pkey);
		} else {
			cm_log(1, "Internal error.\n");
		}
		fclose(keyfp);
	} else {
		cm_log(1, "Error opening '%s': %s.\n",
		       entry->cm_key_storage_location, strerror(errno));
	}
	return status;
}

/* Check if we need to make another request to actually retrieve the cert. */
int
cm_submit_needs_retrieval(struct cm_store_entry *entry,
			  struct cm_submit_state *state)
{
	return -1; /* already have data, no additional retrieval step needed */
}

/* Save the certificate to the location specified in the entry. */
int
cm_submit_save_cert(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	FILE *fp;
	fp = fopen(entry->cm_cert_storage_location, "w");
	if (fp == NULL) {
		cm_log(1, "Error opening '%s': %s.\n",
		       entry->cm_cert_storage_location, strerror(errno));
		return -1;
	} else {
		i2d_X509_fp(fp, state->cert);
		fclose(fp);
	}
	return 0;
}

/* Done talking to the CA. */
void
cm_submit_done(struct cm_store_entry *entry, struct cm_submit_state *state)
{
	if (state->cert != NULL) {
		X509_free(state->cert);
	}
	free(state);
}
