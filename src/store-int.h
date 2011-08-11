/*
 * Copyright (C) 2009,2010 Red Hat, Inc.
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

#ifndef cmstore_int_h
#define cmstore_int_h

#include <time.h>

struct cm_store_entry {
	/* Store-private data - usually an identifier for the nonvolatile
	 * saved copy, might be other stuff. */
	void *cm_store_private;
	/* A unique identifier. */
	char *cm_id;
	/* Type of key pair to generate [or use default settings] RSA,2048 */
	struct cm_key_type {
		enum cm_key_algorithm {
			cm_key_unspecified = 0,
			cm_key_rsa = 1,
		} cm_key_algorithm, cm_key_gen_algorithm;
		int cm_key_size, cm_key_gen_size;
	} cm_key_type;
	/* Location of key pair [use-once default] NSS,/etc/pki/nssdb */
	enum cm_key_storage_type {
		cm_key_storage_none = 0,
		cm_key_storage_file,
		cm_key_storage_nssdb,
	} cm_key_storage_type;
	char *cm_key_storage_location;
	char *cm_key_token;
	char *cm_key_nickname;
	char *cm_key_pin;
	char *cm_key_pin_file;
	/* Location of certificate [use-once default]
	 * NSS,/etc/pki/nssdb,Server-Cert-default */
	enum cm_cert_storage_type {
		cm_cert_storage_file = 0,
		cm_cert_storage_nssdb,
	} cm_cert_storage_type;
	char *cm_cert_storage_location;
	char *cm_cert_token;
	char *cm_cert_nickname;
	/* Cached certificate issuer/serial/subject/spki/expiration */
	char *cm_cert_issuer;
	char *cm_cert_serial;
	char *cm_cert_subject;
	char *cm_cert_spki;
	time_t cm_cert_not_before;
	time_t cm_cert_not_after;
	char **cm_cert_hostname;
	char **cm_cert_email;
	char **cm_cert_principal;
	char *cm_cert_ku;
	char *cm_cert_eku;
	time_t cm_last_expiration_check;
	/* How to notify administrator: syslog(LOG_AUTHPRIV?), mail to root@? */
	enum cm_notification_method {
		cm_notification_unspecified,
		cm_notification_syslog,
		cm_notification_email,
		cm_notification_stdout,	/* for testing _ONLY_ */
	} cm_notification_method;
	char *cm_notification_destination;
	/* CSR template information [or imported from existing certificate]
	   * subject (cn=host name)
	   * subjectaltname
	   *  email
	   *  principal name
	   * ku, eku */
	char *cm_template_subject;
	char **cm_template_hostname;
	char **cm_template_email;
	char **cm_template_principal;
	char *cm_template_ku;
	char *cm_template_eku;
	/* The CSR, base64-encoded. */
	char *cm_csr;
	/* Our idea of the state of the cert. */
	enum cm_state {
		CM_INVALID,
		CM_NEED_KEY_PAIR, CM_GENERATING_KEY_PAIR,
		CM_NEED_KEY_GEN_PIN, CM_NEED_KEY_GEN_TOKEN, CM_HAVE_KEY_PAIR,
		CM_NEED_KEYINFO, CM_READING_KEYINFO,
		CM_NEED_KEYINFO_READ_PIN, CM_NEED_KEYINFO_READ_TOKEN,
		CM_HAVE_KEYINFO,
		CM_NEED_CSR, CM_GENERATING_CSR, CM_NEED_CSR_GEN_PIN,
		CM_NEED_CSR_GEN_TOKEN,
		CM_HAVE_CSR, CM_NEED_TO_SUBMIT, CM_SUBMITTING,
		CM_NEED_CA, CM_CA_UNREACHABLE, CM_CA_UNCONFIGURED,
		CM_CA_REJECTED, CM_CA_WORKING,
		CM_NEED_TO_SAVE_CERT, CM_SAVING_CERT,
		CM_NEED_TO_READ_CERT, CM_READING_CERT,
		CM_SAVED_CERT,
		CM_MONITORING, CM_NEED_TO_NOTIFY, CM_NOTIFYING,
		CM_NEED_GUIDANCE,
		CM_NEWLY_ADDED,
		CM_NEWLY_ADDED_START_READING_KEYINFO,
		CM_NEWLY_ADDED_READING_KEYINFO,
		CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN,
		CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN,
		CM_NEWLY_ADDED_START_READING_CERT,
		CM_NEWLY_ADDED_READING_CERT,
		CM_NEWLY_ADDED_DECIDING,
	} cm_state;
	/* Whether to autorenew-at-expiration */
	unsigned int cm_autorenew:1;
	/* Whether to start monitoring at issue */
	unsigned int cm_monitor:1;
	/* Type and location of CA [or use default if NULL] */
	char *cm_ca_name;
	/* Date of submission for in-progress submissions. */
	time_t cm_submitted;
	/* Value of CA cookie for in-progress submissions. */
	char *cm_ca_cookie;
	/* An error message from the CA, hopefully a useful one. */
	char *cm_ca_error;
	/* The certificate, if we have one. */
	char *cm_cert;
};

struct cm_store_ca {
	/* Store-private data - usually an identifier for the nonvolatile
	 * saved copy, might be other stuff. */
	void *cm_store_private;
	/* A unique identifier or nickname. */
	char *cm_id;
	/* A list of issuer names.  If no CA is specified when we create a new
	 * request, and the certificate already exists and was issued by one of
	 * these names, we'll use this CA. */
	char **cm_ca_known_issuer_names;
	/* Whether or not this is the default, absent any matches with issuer
	 * names of other CAs. */
	int cm_ca_is_default:1;
	/* Type of CA.  Internal helpers can't be deleted and are handled by
	 * internal logic.  External helpers can be deleted, and call out to a
	 * helper to do the actual submission. */
	enum cm_ca_type {
		cm_ca_internal_self, cm_ca_external,
	} cm_ca_type;
	char *cm_ca_internal_serial;
	int cm_ca_internal_force_issue_time:1;
	time_t cm_ca_internal_issue_time;
	char *cm_ca_external_helper;
};

const char *cm_store_state_as_string(enum cm_state state);
enum cm_state cm_store_state_from_string(const char *name);

struct cm_store_entry *cm_store_files_entry_read(void *parent,
						 const char *filename);
struct cm_store_ca *cm_store_files_ca_read(void *parent,
					   const char *filename);
#endif
