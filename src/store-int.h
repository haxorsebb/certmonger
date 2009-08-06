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
	int cm_key_type_default:1;
	struct cm_key_type {
		enum cm_key_algorithm {
			cm_key_rsa = 0,
		} cm_key_algorithm;
		int cm_key_size;
	} cm_key_type;
	/* Location of key pair [use-once default] NSS,/etc/pki/nssdb */
	int cm_key_storage_default:1;
	enum cm_key_storage_type {
		cm_key_storage_file = 0,
	} cm_key_storage_type;
	char *cm_key_storage_location;
	/* Location of certificate [use-once default]
	 * NSS,/etc/pki/nssdb,Server-Cert-default */
	int cm_cert_storage_default:1;
	enum cm_cert_storage_type {
		cm_cert_storage_file = 0,
	} cm_cert_storage_type;
	char *cm_cert_storage_location;
	char *cm_cert_nickname;
	/* Cached certificate issuer/serial/subject/spki/expiration */
	char *cm_issuer;
	char *cm_serial;
	char *cm_subject;
	char *cm_spki;
	time_t cm_expiration;
	char *cm_email;
	char *cm_principal;
	char *cm_ku;
	char *cm_eku;
	/* Interesting TTL values [or use default settings]
	   30*24*60*60,7*24*60*60,3*24*60*60,2*24*60*60,1*24*60*60 */
	int cm_ttls_default:1;
	int cm_n_ttls;
	time_t *cm_ttls;
	/* How to notify administrator [or use default settings]
	   syslog(LOG_AUTHPRIV?) or mail to root@? */
	int cm_notification_default:1;
	enum cm_notification_method {
		cm_notification_syslog = 0,
		cm_notification_email,
	} cm_notification_method;
	char *cm_notification_destination;
	/* CSR template information [or imported from existing certificate]
	   * subject (cn=host name)
	   * subjectaltname
	   *  email
	   *  principal name
	   * ku, eku */
	int cm_template_default:1;
	char *cm_template_subject;
	char *cm_template_email;
	char *cm_template_principal;
	char *cm_template_ku;
	char *cm_template_eku;
	/* The CSR, base64-encoded. */
	char *cm_csr;
	/* Our idea of the state of the cert. */
	enum cm_state {
		CM_INVALID,
		CM_NEED_KEY_PAIR, CM_GENERATING_KEY_PAIR, CM_HAVE_KEY_PAIR,
		CM_NEED_CSR, CM_GENERATING_CSR, CM_HAVE_CSR,
		CM_NEED_TO_SUBMIT, CM_SUBMITTING, CM_HAVE_SUBMITTED,
		CM_NEED_CA_STATUS, CM_POLLING_CA_STATUS, CM_RETRIEVING_CERT,
		CM_MONITORING,
		CM_NEED_GUIDANCE,
	} cm_state;
	/* Whether to autorenew-at-expiration [or use default settings] */
	int cm_autorenew_default:1;
	int cm_autorenew:1;
	/* Whether to start monitoring at issue [or use default settings] */
	int cm_monitor_default:1;
	int cm_monitor:1;
	/* Type and location of CA [or use default settings] */
	int cm_ca_default:1;
	enum cm_ca_type {
		cm_ca_files = 0,
	} cm_ca_type;
	char *cm_ca_location;
	/* Date of submission for in-progress submissions. */
	time_t cm_submitted;
	/* Value of CA cookie for in-progress submissions. */
	char *cm_ca_cookie;
	/* The certificate, if we have one. */
	char *cm_cert;
};

const char *cm_store_state_as_string(enum cm_state state);
enum cm_state cm_store_state_from_string(const char *name);

#endif
