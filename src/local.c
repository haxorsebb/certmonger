/*
 * Copyright (C) 2014,2015 Red Hat, Inc.
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

#include <dbus/dbus.h>

#include <krb5.h>

#include <secoid.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <talloc.h>

#include <popt.h>

#include "env.h"
#include "log.h"
#include "prefs.h"
#include "prefs-o.h"
#include "store.h"
#include "submit-e.h"
#include "submit-o.h"
#include "submit-u.h"
#include "util.h"
#include "util-o.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

#define CONSTANTCN "Local Signing Authority"
static unsigned char uuid[16];

static void
set_ca_extensions(void *parent, X509_REQ *req, EVP_PKEY *key)
{
	STACK_OF(X509_EXTENSION) *exts;
	BASIC_CONSTRAINTS basic;
	AUTHORITY_KEYID akid;
	ASN1_OCTET_STRING *skid;
	ASN1_BIT_STRING *ku;
	unsigned char *p, *q, md[CM_DIGEST_MAX];
	unsigned int mdlen;
	long len;

	exts = sk_X509_EXTENSION_new(NULL);

	memset(&basic, 0, sizeof(basic));
	basic.ca = 1;
	X509V3_add1_i2d(&exts, NID_basic_constraints, &basic, TRUE, 0);

	len = i2d_PUBKEY(key, NULL);
	p = malloc(len);
	q = p;
	len = i2d_PUBKEY(key, &q);
	if (EVP_Digest(p, len, md, &mdlen, EVP_sha1(), NULL)) {
		skid = M_ASN1_OCTET_STRING_new();
		M_ASN1_OCTET_STRING_set(skid, md, mdlen);
		memset(&akid, 0, sizeof(akid));
		akid.keyid = skid;
		X509V3_add1_i2d(&exts, NID_subject_key_identifier, skid, 0, 0);
		X509V3_add1_i2d(&exts, NID_authority_key_identifier, &akid, 0, 0);
	}

	ku = M_ASN1_BIT_STRING_new();
	ASN1_BIT_STRING_set_bit(ku, 0, 1);
	ASN1_BIT_STRING_set_bit(ku, 5, 1);
	ASN1_BIT_STRING_set_bit(ku, 6, 1);
	X509V3_add1_i2d(&exts, NID_key_usage, ku, TRUE, 0);

	X509_REQ_add_extensions(req, exts);
}

static char *
make_ca_csr(void *parent, EVP_PKEY *key, X509 *oldcert)
{
	X509_REQ *req;
	X509_NAME *subject;
	BIO *bio;
	char *cn, *ret = NULL;
	unsigned char *bmp;
	unsigned int bmplen;
	long len;

	req = X509_REQ_new();
	if (req != NULL) {
		if ((oldcert != NULL) &&
		    (oldcert->cert_info->subject != NULL)) {
			X509_REQ_set_subject_name(req,
						  oldcert->cert_info->subject);
		} else {
			subject = X509_NAME_new();
			if (subject != NULL) {
				X509_NAME_add_entry_by_txt(subject, "CN",
							   MBSTRING_UTF8,
							   (unsigned char *) CONSTANTCN,
							   strlen(CONSTANTCN),
							   -1, 0);
				cn = talloc_asprintf(parent,
						     "%.02x%.02x%.02x%.02x-"
						     "%.02x%.02x%.02x%.02x-"
						     "%.02x%.02x%.02x%.02x-"
						     "%.02x%.02x%.02x%.02x",
						     (unsigned char) uuid[0],
						     (unsigned char) uuid[1],
						     (unsigned char) uuid[2],
						     (unsigned char) uuid[3],
						     (unsigned char) uuid[4],
						     (unsigned char) uuid[5],
						     (unsigned char) uuid[6],
						     (unsigned char) uuid[7],
						     (unsigned char) uuid[8],
						     (unsigned char) uuid[9],
						     (unsigned char) uuid[10],
						     (unsigned char) uuid[11],
						     (unsigned char) uuid[12],
						     (unsigned char) uuid[13],
						     (unsigned char) uuid[14],
						     (unsigned char) uuid[15]);
				X509_NAME_add_entry_by_txt(subject, "CN",
							   MBSTRING_UTF8,
							   (unsigned char *) cn,
							   strlen(cn), -1, 0);
				X509_REQ_set_subject_name(req, subject);
			}
		}
		X509_REQ_set_pubkey(req, key);
		set_ca_extensions(parent, req, key);
		if (cm_store_utf8_to_bmp_string(CONSTANTCN, &bmp,
						&bmplen) == 0) {
			X509_REQ_add1_attr_by_NID(req,
						  NID_friendlyName,
						  V_ASN1_BMPSTRING,
						  bmp,
						  bmplen);
			free(bmp);
		}
		X509_REQ_sign(req, key, cm_prefs_ossl_hash());
		bio = BIO_new(BIO_s_mem());
		if (PEM_write_bio_X509_REQ(bio, req)) {
			len = BIO_get_mem_data(bio, &ret);
			if (ret != NULL) {
				ret = talloc_strndup(parent, ret, len);
				cm_log(3, "New CA signing request \"%s\".\n",
				       ret);
			}
		} else {
			cm_log(1, "Error encoding CA signing request.\n");
		}
	}
	return ret;
}

static int
get_signer_info(void *parent, char *localdir, X509 ***roots,
		X509 **signer_cert, EVP_PKEY **signer_key)
{
	FILE *fp;
	char *creds, *hexserial = NULL, *serial, buf[LINE_MAX], *csr;
	STACK_OF(X509) *cas = NULL;
	PKCS12 *p12 = NULL;
	BIGNUM *exponent = NULL;
	RSA *rsa;
	dbus_bool_t save = FALSE;
	time_t now, then, life, lifedelta;
	int i;

	*roots = NULL;
	*signer_cert = NULL;
	*signer_key = NULL;

	/* Read our signer creds. */
	creds = talloc_asprintf(parent, "%s/%s", localdir, "creds");
	fp = fopen(creds, "r");
	if ((fp == NULL) && (errno != ENOENT)) {
		cm_log(1, "Error reading '%s': %s.\n", creds,
		       strerror(errno));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	if (fp != NULL) {
		p12 = d2i_PKCS12_fp(fp, NULL);
		if (p12 == NULL) {
			cm_log(0, "Bad data in '%s'.\n", creds);
		}
		fclose(fp);
	} else {
		p12 = NULL;
		save = TRUE;
	}
	if ((p12 != NULL) &&
	    !PKCS12_parse(p12, "", signer_key, signer_cert, &cas)) {
		cm_log(1, "Trouble parsing signer data.\n");
		save = TRUE;
	}

	/* Read the desired lifetime. */
	now = time(NULL);
	if (cm_submit_u_delta_from_string(cm_prefs_local_validity_period(),
					  now, &lifedelta) == 0) {
		life = lifedelta;
	} else {
		if (cm_submit_u_delta_from_string(CM_DEFAULT_CERT_LIFETIME, now,
						  &lifedelta) == 0) {
			life = lifedelta;
		} else {
			life = 365 * 24 * 60 * 60;
		}
	}

	/* If we already have a signer certificate, check how much time it has
	 * left. */
	if (*signer_cert != NULL) {
		if (cas == NULL) {
			cas = sk_X509_new(X509_cmp);
			if (cas == NULL) {
				cm_log(1, "Out of memory.\n");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
		}
		then = now + (life / 2);
		if ((X509_cmp_time(X509_get_notBefore(*signer_cert), &now) > 0) ||
		    (X509_cmp_time(X509_get_notAfter(*signer_cert), &then) < 0)) {
			cm_log(1, "CA certificate needs to be replaced.\n");
			sk_X509_push(cas, *signer_cert);
			*signer_key = NULL;
		}
	} else {
		cm_log(1, "CA certificate needs to be generated.\n");
	}

	/* If we need to generate or replace either, do both. */
	if ((*signer_key == NULL) || (*signer_cert == NULL)) {
		/* Read the next-to-be-used serial number. */
		serial = talloc_asprintf(parent, "%s/%s",
					 localdir, "/serial");
		fp = fopen(serial, "r");
		if ((fp == NULL) && (errno != ENOENT)) {
			cm_log(1, "Error reading '%s': %s.\n", serial,
			       strerror(errno));
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		if (fp != NULL) {
			if (fgets(buf, sizeof(buf), fp) == NULL) {
				cm_log(0, "Bad data in '%s'.\n", serial);
			} else {
				buf[strcspn(buf, "\r\n")] = '\0';
				hexserial = talloc_strdup(parent, buf);
				cm_log(1, "Read serial number '%s'.\n",
				       hexserial);
			}
			fclose(fp);
		}
		if (hexserial == NULL) {
			hexserial = cm_store_hex_from_bin(parent, uuid,
							  sizeof(uuid));
			if (strchr("89abcdefABCDEF", hexserial[0]) != NULL) {
				hexserial = talloc_asprintf(parent, "00%s",
							    hexserial);
			}
			cm_log(3, "Using serial number '%s'.\n", hexserial);
		}
		/* Generate a new key.  For now at least, generate RSA of the
		 * default size with the default exponent. */
		exponent = BN_new();
		if (exponent == NULL) {
			cm_log(1, "Error setting up exponent.\n");
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		BN_set_word(exponent, CM_DEFAULT_RSA_EXPONENT);
		rsa = RSA_new();
		if (rsa == NULL) {
			cm_log(1, "Error allocating new RSA key.\n");
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
	retry_gen:
		if (RSA_generate_key_ex(rsa, CM_DEFAULT_PUBKEY_SIZE, exponent,
					NULL) != 1) {
			cm_log(1, "Error generating key.\n");
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		if (RSA_check_key(rsa) != 1) { /* should be unnecessary */
			cm_log(1, "Key fails checks.  Retrying.\n");
			goto retry_gen;
		}
		*signer_key = EVP_PKEY_new();
		EVP_PKEY_set1_RSA(*signer_key, rsa);
		/* Build a suitable CA signing request. */
		csr = make_ca_csr(parent, *signer_key, *signer_cert);
		if (csr == NULL) {
			cm_log(1, "Error generating CA signing request.\n");
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		/* Sign it. */
		if (cm_submit_o_sign(parent, csr, NULL, *signer_key, hexserial,
				     time(NULL), life, signer_cert) == 0) {
			save = TRUE;
		} else {
			*signer_key = NULL;
			*signer_cert = NULL;
			save = FALSE;
		}
	}
	/* Save our signer creds. */
	if (save) {
		/* Roll the serial number up. */
		hexserial = cm_store_increment_serial(parent, hexserial);
		if (hexserial == NULL) {
			cm_log(1, "Error incrementing '%s'.\n", hexserial);
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		/* Save the next serial number. */
		serial = talloc_asprintf(parent, "%s/%s", localdir, "/serial");
		fp = fopen(serial, "w");
		if (fp == NULL) {
			cm_log(1, "Error writing '%s': %s.\n", serial,
			       strerror(errno));
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		fprintf(fp, "%s\n", hexserial);
		if (ferror(fp)) {
			cm_log(1, "Error writing '%s': %s.\n", serial,
			       strerror(errno));
			fclose(fp);
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		fclose(fp);
		cm_log(3, "Wrote serial number '%s'.\n", hexserial);
		/* Save the new creds. */
		fp = fopen(creds, "w");
		if (fp == NULL) {
			cm_log(1, "Error preparing to write '%s': %s.\n",
			       creds, strerror(errno));
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		p12 = PKCS12_create(NULL, CONSTANTCN, *signer_key, *signer_cert,
				    cas, 0, 0, 0, 0, 0);
		if (p12 != NULL) {
			if (!i2d_PKCS12_fp(fp, p12)) {
				fclose(fp);
				cm_log(1, "Error writing PKCS12 bundle'.\n");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
		} else {
			cm_log(1, "Error creating PKCS12 bundle'.\n");
		}
		fclose(fp);

	}
	if (cas != NULL) {
		*roots = talloc_array_ptrtype(parent, *roots, sk_X509_num(cas) + 1);
		if (*roots != NULL) {
			for (i = 0; i < sk_X509_num(cas); i++) {
				(*roots)[i] = sk_X509_value(cas, i);
			}
			(*roots)[i] = NULL;
		}
	}
	return CM_SUBMIT_STATUS_ISSUED;
}

static int
local_lock(void *parent, const char *localdir)
{
	char *lockfile;
	int lfd;

	lockfile = talloc_asprintf(parent, "%s/lock", localdir);
	cm_log(2, "Obtaining data lock.\n");
	lfd = open(lockfile, O_RDWR | O_CREAT,
		   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (lfd == -1) {
		fprintf(stderr, "Error opening lockfile \"%s\": %s\n",
			lockfile, strerror(errno));
		exit(CM_SUBMIT_STATUS_UNREACHABLE);
	}
	if (lockf(lfd, F_LOCK, 0) != 0) {
		fprintf(stderr, "Error locking lockfile \"%s\": %s\n",
			lockfile, strerror(errno));
		close(lfd);
		exit(CM_SUBMIT_STATUS_UNREACHABLE);
	}
	return lfd;
}

int
main(int argc, const char **argv)
{
	int i, c, verbose = 0, lfd = -1;
	void *parent;
	const char *mode = CM_OP_SUBMIT, *csrfile;
	char *csr, *localdir = NULL, *hexserial = NULL, *serial, buf[LINE_MAX];
	FILE *fp;
	X509 **roots = NULL, *signer = NULL, *cert = NULL;
	EVP_PKEY *key = NULL;
	time_t now;
	poptContext pctx;
	const struct poptOption popts[] = {
		{"ca-data-directory", 'd', POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &localdir, 0, "storage location for the CA's data", "DIRECTORY"},
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
		printf("%s (%s %s)\n", CONSTANTCN,
		       PACKAGE_NAME, PACKAGE_VERSION);
		return 0;
	} else
	if (strcasecmp(mode, CM_OP_FETCH_ENROLL_REQUIREMENTS) == 0) {
		return 0;
	} else
	if (strcasecmp(mode, CM_OP_FETCH_ROOTS) == 0) {
		/* fall through */
	} else
	if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
	    (strcasecmp(mode, CM_OP_POLL) == 0)) {
		/* fall through */
	} else {
		/* unsupported request */
		return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
	}

	localdir = getenv(CM_STORE_LOCAL_CA_DIRECTORY_ENV);
	if (localdir == NULL) {
		localdir = cm_env_local_ca_dir();
	}
	pctx = poptGetContext(argv[0], argc, argv, popts, 0);
	if (pctx == NULL) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	poptSetOtherOptionHelp(pctx, "[options...] [csrfile]");
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	umask(S_IRWXG | S_IRWXO);

	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(verbose);

	if (localdir == NULL) {
		poptPrintUsage(pctx, stdout, 0);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	csr = NULL;
	parent = talloc_init(CONSTANTCN);
	util_o_init();
#ifdef HAVE_UUID
	if (cm_submit_uuid_new(uuid) == 0) {
		/* we're good */
	} else
#endif
	if (!RAND_pseudo_bytes(uuid, sizeof(uuid))) {
		/* Try again sometime later. */
		cm_log(1, "Error generating UUID.\n");
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}

	if (strcasecmp(mode, CM_OP_FETCH_ROOTS) == 0) {
		/* Take the lock. */
		lfd = local_lock(parent, localdir);
		/* Read the signer information. */
		i = get_signer_info(parent, localdir, &roots,
				    &signer, &key);
		if ((i != 0) || (signer == NULL)) {
			cm_log(1, "Error reading signer info.\n");
			/* Try again sometime later. */
			return i ? i : CM_SUBMIT_STATUS_UNREACHABLE;
		}
		printf("%s\n", CONSTANTCN);
		if (!PEM_write_X509(stdout, signer)) {
			/* Well, try again sometime later. */
			cm_log(1, "Error outputting certificate.\n");
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		for (i = 0; (roots != NULL) && (roots[i] != NULL); i++) {
			printf("%s %d\n", CONSTANTCN, i + 2);
			if (!PEM_write_X509(stdout, roots[i])) {
				/* Well, try again sometime later. */
				cm_log(1, "Error outputting certificate.\n");
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
		}
		/* All done. */
		close(lfd);
		return CM_SUBMIT_STATUS_ISSUED;
	} else
	if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
	    (strcasecmp(mode, CM_OP_POLL) == 0)) {
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
			printf(_("Unable to read signing request.\n"));
			cm_log(1, "Unable to read signing request.\n");
			poptPrintUsage(pctx, stdout, 0);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		/* Take the lock. */
		lfd = local_lock(parent, localdir);
		/* Read in the signer information. */
		i = get_signer_info(parent, localdir, &roots,
				    &signer, &key);
		if ((i != 0) || (signer == NULL)) {
			cm_log(1, "Error reading signer info.\n");
			/* Try again sometime later. */
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		/* Read the next-to-be-used serial number. */
		serial = talloc_asprintf(parent, "%s/%s", localdir, "/serial");
		fp = fopen(serial, "r");
		if ((fp == NULL) && (errno != ENOENT)) {
			cm_log(1, "Error reading '%s': %s.\n", serial,
			       strerror(errno));
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		if (fp != NULL) {
			if (fgets(buf, sizeof(buf), fp) == NULL) {
				fclose(fp);
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			buf[strcspn(buf, "\r\n")] = '\0';
			hexserial = talloc_strdup(parent, buf);
			cm_log(3, "Read serial number '%s'.\n", hexserial);
		}
		if (hexserial == NULL) {
			hexserial = cm_store_hex_from_bin(parent, uuid,
							  sizeof(uuid));
			if (strchr("89abcdefABCDEF", hexserial[0]) != NULL) {
				hexserial = talloc_asprintf(parent, "00%s",
							    hexserial);
			}
			cm_log(3, "Using serial number '%s'.\n", hexserial);
		}
		now = time(NULL);
		/* Actually sign the request. */
		i = cm_submit_o_sign(parent, csr, signer, key, hexserial,
				     now, 0, &cert);
		if ((i == 0) && (cert != NULL)) {
			/* Roll the serial number up. */
			hexserial = cm_store_increment_serial(parent,
							      hexserial);
			if (hexserial == NULL) {
				cm_log(1, "Error incrementing '%s'.\n",
				       hexserial);
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			/* Save the next serial number. */
			fp = fopen(serial, "w");
			if (fp == NULL) {
				cm_log(1, "Error writing '%s': %s.\n", serial,
				       strerror(errno));
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			fprintf(fp, "%s\n", hexserial);
			if (ferror(fp)) {
				cm_log(1, "Error writing '%s': %s.\n", serial,
				       strerror(errno));
				fclose(fp);
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			fclose(fp);
			cm_log(3, "Wrote serial number '%s'.\n", hexserial);
			/* Okay, now provide the certificate. */
			if (!PEM_write_X509(stdout, cert)) {
				cm_log(1, "Error outputting certificate: %s.\n",
				       strerror(errno));
				/* Well, try again sometime later. */
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
		}
		close(lfd);
		return i;
	}

	return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
}
