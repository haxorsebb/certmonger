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

#ifndef cmstore_int_h
#define cmstore_int_h

#include <sys/stat.h>
#include <time.h>

struct cm_store_entry {
	/* Per-instance unique identifier. */
	char *cm_busname;
	/* Store-private data - usually an identifier for the nonvolatile
	 * saved copy, might be other stuff. */
	void *cm_store_private;
	/* A persistent unique identifier or nickname. */
	char *cm_nickname;
	/* Type of key pair to generate [or use default settings] RSA,2048 */
	struct cm_key_type {
		enum cm_key_algorithm {
			cm_key_unspecified = 0,
			cm_key_rsa = 1,
#ifdef CM_ENABLE_DSA
			cm_key_dsa,
#endif
#ifdef CM_ENABLE_EC
			cm_key_ecdsa,
#endif
		} cm_key_algorithm, cm_key_gen_algorithm;
		int cm_key_size, cm_key_gen_size;
	} cm_key_type, cm_key_next_type;
	char *cm_key_next_marker;
	unsigned int cm_key_preserve: 1;
	time_t cm_key_generated_date, cm_key_next_generated_date;
	unsigned int cm_key_issued_count;
	unsigned int cm_key_requested_count, cm_key_next_requested_count;
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
	char *cm_key_owner;
	mode_t cm_key_perms;
	/* Cached plain public key (used for computing subject and authority key IDs) */
	char *cm_key_pubkey, *cm_key_next_pubkey;
	/* Cached public key info (used in signing requests when using NSS) */
	char *cm_key_pubkey_info, *cm_key_next_pubkey_info;
	/* Location of certificate [use-once default]
	 * NSS,/etc/pki/nssdb,Server-Cert-default */
	enum cm_cert_storage_type {
		cm_cert_storage_file = 0,
		cm_cert_storage_nssdb,
	} cm_cert_storage_type;
	char *cm_cert_storage_location;
	char *cm_cert_token;
	char *cm_cert_nickname;
	char *cm_cert_owner;
	mode_t cm_cert_perms;
	/* Cached certificate issuer/serial/subject/spki/expiration */
	char *cm_cert_issuer_der;
	char *cm_cert_issuer;
	char *cm_cert_serial;
	char *cm_cert_subject_der;
	char *cm_cert_subject;
	char *cm_cert_spki;
	time_t cm_cert_not_before;
	time_t cm_cert_not_after;
	char **cm_cert_hostname;
	char **cm_cert_email;
	char **cm_cert_principal;
	char **cm_cert_ipaddress;
	char *cm_cert_ku;
	char *cm_cert_eku;
	unsigned int cm_cert_is_ca: 1;
	int cm_cert_ca_path_length;
	char **cm_cert_crl_distribution_point;
	char **cm_cert_freshest_crl;
	char **cm_cert_ocsp_location;
	char *cm_cert_ns_comment;
	char *cm_cert_profile;
	char *cm_cert_ns_certtype;
	unsigned int cm_cert_no_ocsp_check: 1;
	time_t cm_last_need_notify_check;
	time_t cm_last_need_enroll_check;
	/* How to notify administrator: syslog(LOG_AUTHPRIV?), mail to root@? */
	enum cm_notification_method {
		cm_notification_unspecified,
		cm_notification_none,
		cm_notification_syslog,
		cm_notification_email,
		cm_notification_command,
		cm_notification_stdout,	/* for testing _ONLY_ */
	} cm_notification_method;
	char *cm_notification_destination;
	/* CSR template information [or imported from existing certificate]
	   * subject (cn=host name)
	   * subjectaltname
	   *  hostname
	   *  email
	   *  principal name
	   *  IP address
	   * ku, eku
	   * is_ca, ca_path_length
	   * crl_distribution_points
	   * freshest_crl
	   * aia_ocsp_locations
	   * nscomment
	   * template
	   */
	char *cm_template_subject_der;
	char *cm_template_subject;
	char **cm_template_hostname;
	char **cm_template_email;
	char **cm_template_principal;
	char **cm_template_ipaddress;
	char *cm_template_ku;
	char *cm_template_eku;
	unsigned int cm_template_is_ca: 1;
	int cm_template_ca_path_length;
	char **cm_template_crl_distribution_point;
	char **cm_template_freshest_crl;
	char **cm_template_ocsp_location;
	char *cm_template_ns_comment;
	char *cm_template_profile;
	char *cm_template_ns_certtype;
	unsigned int cm_template_no_ocsp_check: 1;
	/* A challenge password, which may be included (in cleartext form!) in
	 * a CSR. */
	char *cm_template_challenge_password;
	char *cm_template_challenge_password_file;
	/* The CSR, base64-encoded. */
	char *cm_csr;
	/* The SPKAC, base64-encoded. */
	char *cm_spkac;
	/* An SCEP transaction number corresponding to this CSR and signing request. */
	char *cm_scep_tx;
	/* An SCEP nonce. */
	char *cm_scep_nonce, *cm_scep_last_nonce;
	/* An SCEP PKCSReq message, signed with our current key, and possibly
	 * the next key. */
	char *cm_scep_req, *cm_scep_req_next;
	/* An SCEP GetInitialCert message, signed with our current key, and
	 * possibly the next key. */
	char *cm_scep_gic, *cm_scep_gic_next;
	/* A minimal self-signed certificate. */
	char *cm_minicert;
	/* Our idea of the state of the cert. */
	enum cm_state {
		CM_NEED_KEY_PAIR, CM_GENERATING_KEY_PAIR,
		CM_NEED_KEY_GEN_PERMS,
		CM_NEED_KEY_GEN_PIN, CM_NEED_KEY_GEN_TOKEN, CM_HAVE_KEY_PAIR,
		CM_NEED_KEYINFO, CM_READING_KEYINFO,
		CM_NEED_KEYINFO_READ_PIN, CM_NEED_KEYINFO_READ_TOKEN,
		CM_HAVE_KEYINFO,
		CM_NEED_CSR, CM_GENERATING_CSR, CM_NEED_CSR_GEN_PIN,
		CM_NEED_CSR_GEN_TOKEN, CM_HAVE_CSR,
		CM_NEED_SCEP_DATA, CM_GENERATING_SCEP_DATA,
		CM_NEED_SCEP_GEN_PIN, CM_NEED_SCEP_GEN_TOKEN,
		CM_NEED_SCEP_ENCRYPTION_CERT, CM_NEED_SCEP_RSA_CLIENT_KEY,
		CM_HAVE_SCEP_DATA,
		CM_NEED_TO_SUBMIT, CM_SUBMITTING,
		CM_NEED_CA, CM_CA_UNREACHABLE, CM_CA_UNCONFIGURED,
		CM_CA_REJECTED, CM_CA_WORKING,
		CM_NEED_TO_SAVE_CERT, CM_PRE_SAVE_CERT,
		CM_START_SAVING_CERT, CM_SAVING_CERT,
		CM_NEED_CERTSAVE_PERMS,
		CM_NEED_CERTSAVE_TOKEN, CM_NEED_CERTSAVE_PIN,
		CM_NEED_TO_SAVE_CA_CERTS,
		CM_START_SAVING_CA_CERTS, CM_SAVING_CA_CERTS,
		CM_NEED_CA_CERT_SAVE_PERMS,
		CM_NEED_TO_SAVE_ONLY_CA_CERTS,
		CM_START_SAVING_ONLY_CA_CERTS, CM_SAVING_ONLY_CA_CERTS,
		CM_NEED_ONLY_CA_CERT_SAVE_PERMS,
		CM_NEED_TO_READ_CERT, CM_READING_CERT,
		CM_SAVED_CERT, CM_POST_SAVED_CERT,
		CM_MONITORING,
		CM_NEED_TO_NOTIFY_VALIDITY, CM_NOTIFYING_VALIDITY,
		CM_NEED_TO_NOTIFY_REJECTION, CM_NOTIFYING_REJECTION,
		CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED,
		CM_NOTIFYING_ISSUED_SAVE_FAILED,
		CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED,
		CM_NOTIFYING_ISSUED_CA_SAVE_FAILED,
		CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED,
		CM_NOTIFYING_ONLY_CA_SAVE_FAILED,
		CM_NEED_TO_NOTIFY_ISSUED_SAVED, CM_NOTIFYING_ISSUED_SAVED,
		CM_NEED_GUIDANCE,
		CM_NEWLY_ADDED,
		CM_NEWLY_ADDED_START_READING_KEYINFO,
		CM_NEWLY_ADDED_READING_KEYINFO,
		CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN,
		CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN,
		CM_NEWLY_ADDED_START_READING_CERT,
		CM_NEWLY_ADDED_READING_CERT,
		CM_NEWLY_ADDED_DECIDING,
		CM_INVALID,
	} cm_state;
	/* Whether to autorenew-at-expiration */
	unsigned int cm_autorenew:1;
	/* Whether to start monitoring at issue */
	unsigned int cm_monitor:1;
	/* Type and location of CA [or use default if NULL] */
	char *cm_ca_nickname;
	/* Date of submission for in-progress submissions. */
	time_t cm_submitted;
	/* Value of CA cookie for in-progress submissions. */
	char *cm_ca_cookie;
	/* An error message from the CA, hopefully a useful one. */
	char *cm_ca_error;
	/* The certificate, if we have one. */
	char *cm_cert;
	/* Certificates between ours and the CA's root, if there are any. */
	struct cm_nickcert {
		char *cm_nickname;	/* Suggested nickname. */
		char *cm_cert;		/* PEM-format certificate. */
	} **cm_cert_chain;
	/* Per-certificate CA certificate list, if for some reason we're
	 * tracking CA certificates for just this certificate instead of as
	 * part of the metadata we keep about the CA. */
	struct cm_nickcert **cm_cert_roots;
	/* A command to run before we save the certificate. */
	char *cm_pre_certsave_command;
	/* The UID of the user as whom we run the above command. */
	char *cm_pre_certsave_uid;
	/* A command to run after we save the certificate. */
	char *cm_post_certsave_command;
	/* The UID of the user as whom we run the above command. */
	char *cm_post_certsave_uid;
	/* Initially-empty lists of places where we the CA's roots, the CA's
	 * other roots, and the CA's other certs and our chain. */
	char **cm_root_cert_store_files;
	char **cm_other_root_cert_store_files;
	char **cm_other_cert_store_files;
	char **cm_root_cert_store_nssdbs;
	char **cm_other_root_cert_store_nssdbs;
	char **cm_other_cert_store_nssdbs;
};

struct cm_store_ca {
	/* Per-instance unique identifier. */
	char *cm_busname;
	/* Store-private data - usually an identifier for the nonvolatile
	 * saved copy, might be other stuff. */
	void *cm_store_private;
	/* A persistent unique identifier or nickname. */
	char *cm_nickname;
	/* What the helper suggests it be called. */
	char *cm_ca_aka;
	/* We have multiple state machines. */
	enum cm_ca_phase {
		cm_ca_phase_identify = 0,
		cm_ca_phase_certs,
		cm_ca_phase_profiles,
		cm_ca_phase_default_profile,
		cm_ca_phase_enroll_reqs,
		cm_ca_phase_renew_reqs,
		cm_ca_phase_capabilities,
		cm_ca_phase_encryption_certs,
		cm_ca_phase_invalid,
	} cm_ca_phase;
	/* Data refresh state. */
	enum cm_ca_phase_state {
		CM_CA_IDLE = 0,
		CM_CA_NEED_TO_REFRESH,
		CM_CA_REFRESHING,
		CM_CA_DATA_UNREACHABLE,
		CM_CA_NEED_TO_SAVE_DATA,
		CM_CA_PRE_SAVE_DATA,
		CM_CA_START_SAVING_DATA,
		CM_CA_SAVING_DATA,
		CM_CA_NEED_POST_SAVE_DATA,
		CM_CA_POST_SAVE_DATA,
		CM_CA_SAVED_DATA,
		CM_CA_NEED_TO_ANALYZE,
		CM_CA_ANALYZING,
		CM_CA_DISABLED,
	} cm_ca_state[cm_ca_phase_invalid];
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
	/* An error message from the CA, hopefully a useful one. */
	char *cm_ca_error;
	/* "The" root, at the top of the chain of trust. */
	struct cm_nickcert **cm_ca_root_certs;
	/* A possibly-empty list of other trusted roots, for whatever reason. */
	struct cm_nickcert **cm_ca_other_root_certs;
	/* A possibly-empty list of other certificates which we might need when
	 * constructing chains.  If our issuer isn't self-signed, then it
	 * should show up in this list. */
	struct cm_nickcert **cm_ca_other_certs;
	/* A list of attributes which the CA requires us to supply with
	 * requests for new certificates, which we should in turn require of
	 * our clients. */
	char **cm_ca_required_enroll_attributes;
	char **cm_ca_required_renewal_attributes;
	/* A list of enrollment profiles which are supported, and a default. */
	char **cm_ca_profiles;
	char *cm_ca_default_profile;
	/* A command to run before we save data to wherever it goes. */
	char *cm_ca_pre_save_command;
	/* The UID of the user as whom we run the above command. */
	char *cm_ca_pre_save_uid;
	/* A command to run after we save data to wherever it goes. */
	char *cm_ca_post_save_command;
	/* The UID of the user as whom we run the above command. */
	char *cm_ca_post_save_uid;
	/* Initially-empty lists of places where we store our roots, other
	 * roots, and other certs. */
	char **cm_ca_root_cert_store_files;
	char **cm_ca_other_root_cert_store_files;
	char **cm_ca_other_cert_store_files;
	char **cm_ca_root_cert_store_nssdbs;
	char **cm_ca_other_root_cert_store_nssdbs;
	char **cm_ca_other_cert_store_nssdbs;
	/* CA capabilities.  Currently only ever SCEP capabilities. */
	char **cm_ca_capabilities;
	/* An SCEP CA identifier, for use in gathering an RA (and possibly a
	 * CA) certificate. */
	char *cm_ca_scep_ca_identifier;
	/* The CA's SCEP RA certificate, used for encrypting requests to it.
	 * Currently only used for SCEP. */
	char *cm_ca_encryption_cert;
	/* The CA's SCEP CA certificate, if it's different from the RA's
	 * certificate.  Currently only used for SCEP. */
	char *cm_ca_encryption_issuer_cert;
	/* The CA's SCEP certificate pool, used for other SCEP-related
	 * certificates.  A concatenated list of PEM-format certificates, since
	 * we don't need anything more complicated than that in order to verify
	 * the chain on signed data coming from the RA. */
	char *cm_ca_encryption_cert_pool;
};

const char *cm_store_state_as_string(enum cm_state state);
enum cm_state cm_store_state_from_string(const char *name);
const char *cm_store_ca_state_as_string(enum cm_ca_phase_state state);
enum cm_ca_phase_state cm_store_ca_state_from_string(const char *name);
const char *cm_store_ca_phase_as_string(enum cm_ca_phase phase);
enum cm_ca_phase cm_store_ca_phase_from_string(const char *name);

char *cm_store_entry_next_busname(void *parent);
struct cm_store_entry *cm_store_files_entry_read(void *parent,
						 const char *filename);
char *cm_store_ca_next_busname(void *parent);
struct cm_store_ca *cm_store_files_ca_read(void *parent, const char *filename);
#endif
