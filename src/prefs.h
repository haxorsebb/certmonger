/*
 * Copyright (C) 2010,2012,2014 Red Hat, Inc.
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

#ifndef cmprefs_h
#define cmprefs_h

enum cm_prefs_cipher {
	cm_prefs_aes128,
	cm_prefs_aes256,
};

enum cm_prefs_digest {
	cm_prefs_sha256,
	cm_prefs_sha384,
	cm_prefs_sha512,
	cm_prefs_sha1,
};

enum cm_notification_method;
enum cm_key_storage_type;
enum cm_cert_storage_type;

enum cm_key_algorithm cm_prefs_preferred_key_algorithm(void);
enum cm_prefs_cipher cm_prefs_preferred_cipher(void);
enum cm_prefs_digest cm_prefs_preferred_digest(void);
int cm_prefs_notify_ttls(const time_t **ttls, unsigned int *n_ttls);
int cm_prefs_enroll_ttls(const time_t **ttls, unsigned int *n_ttls);
enum cm_notification_method cm_prefs_notification_method(void);
const char *cm_prefs_notification_destination(void);
const char *cm_prefs_default_ca(void);
const char *cm_prefs_validity_period(void);
int cm_prefs_monitor(void);
int cm_prefs_autorenew(void);
int cm_prefs_populate_unique_id(void);
const char *cm_prefs_nss_ca_trust(void);
const char *cm_prefs_nss_other_trust(void);

const char *cm_prefs_dogtag_ee_url(void);
const char *cm_prefs_dogtag_agent_url(void);
const char *cm_prefs_dogtag_profile(void);
int cm_prefs_dogtag_renew(void);
const char *cm_prefs_dogtag_ca_info(void);
const char *cm_prefs_dogtag_ca_path(void);
const char *cm_prefs_dogtag_ssldir(void);
const char *cm_prefs_dogtag_sslcert(void);
const char *cm_prefs_dogtag_sslkey(void);
const char *cm_prefs_dogtag_sslpinfile(void);

#endif
