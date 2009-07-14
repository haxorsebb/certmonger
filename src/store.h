#ifndef cmstore_h
#define cmstore_h

struct cm_store_entry {
	/* Store-private data - usually an identifier for the nonvolatile
	 * saved copy, might be other stuff. */
	void *cm_store_private;
	/* Type of key pair to generate [or use default settings] RSA,2048 */
	int cm_key_type_default;
	struct cm_key_type {
		enum cm_key_algorithm {
			cm_key_rsa = 0,
		} cm_key_algorithm;
		int cm_key_size;
	} cm_key_type;
	/* Location of key pair [use-once default] NSS,/etc/pki/nssdb */
	int cm_key_storage_default;
	char *cm_key_storage_type;
	char *cm_key_storage_location;
	/* Location of certificate [use-once default]
	 * NSS,/etc/pki/nssdb,Server-Cert-default */
	int cm_cert_storage_default;
	char *cm_cert_storage_type;
	char *cm_cert_storage_location;
	char *cm_cert_nickname;
	/* Cached certificate issuer/serial/subject/spki/expiration */
	char *cm_issuer;
	char *serial;
	char *cm_subject;
	char *cm_spki;
	char *cm_expiration;
	/* Interesting TTL values [or use default settings]
	   30*24*60*60,7*24*60*60,3*24*60*60,2*24*60*60,1*24*60*60 */
	int cm_ttls_default;
	int cm_n_ttls;
	time_t *cm_ttls;
	/* How to notify administrator [or use default settings]
	   syslog(LOG_AUTHPRIV?) or mail to root@? */
	int cm_notification_default;
	char *cm_notification_method;
	char *cm_notification_destination;
	/* CSR template information [or import from existing certificate]
	   * subject (cn=host name)
	   * email
	   * principal name
	   * ku, eku */
	int cm_template_default;
	char *cm_template_subject;
	char *cm_template_email;
	char *cm_template_principal;
	char *cm_template_ku;
	char *cm_template_eku;
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
	int cm_autorenew_default;
	int cm_autorenew;
	/* Whether to start monitoring at issue [or use default settings] */
	int cm_monitor_default;
	int cm_monitor;
	/* Type and location of CA [or use default settings] */
	int cm_ca_default;
	char *cm_ca_type;
	char *cm_ca_location;
	/* Value of CA cookie for in-progress submissions. */
	char *cm_ca_cookie;
	/* Date of submission for in-progress submissions. */
	time_t cm_submitted;
};

/* Generic routines. */
struct cm_store_entry *cm_store_entry_new();
void cm_store_entry_free(struct cm_store_entry *entry);
void cm_store_entry_freev(struct cm_store_entry **entry);
int cm_store_entry_save(struct cm_store_entry *entry);

/* Store-specific bits. */
struct cm_store_entry *cm_store_get_defaults();
struct cm_store_entry **cm_store_get_entries();

#endif
