/*
 * Copyright (C) 2009,2011,2012,2014 Red Hat, Inc.
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

#ifndef cmtdbus_h
#define cmtdbus_h

#define CM_DBUS_BASE_INTERFACE CM_DBUS_NAME
#define CM_DBUS_DEFAULT_BUS cm_tdbus_system
#define CM_DBUS_CA_PATH CM_DBUS_BASE_PATH "/cas"
#define CM_DBUS_CA_INTERFACE CM_DBUS_BASE_INTERFACE ".ca"
#define CM_DBUS_REQUEST_PATH CM_DBUS_BASE_PATH "/requests"
#define CM_DBUS_REQUEST_INTERFACE CM_DBUS_BASE_INTERFACE ".request"
#define CM_DBUS_ERROR_BASE CM_DBUS_BASE_INTERFACE
#define CM_DBUS_ERROR_CA CM_DBUS_ERROR_BASE ".ca"
#define CM_DBUS_ERROR_REQUEST CM_DBUS_ERROR_BASE ".request"
#define CM_DBUS_ERROR_BASE_INTERNAL CM_DBUS_ERROR_BASE ".internal"
#define CM_DBUS_ERROR_BASE_MISSING_ARG CM_DBUS_ERROR_BASE ".missing_arg"
#define CM_DBUS_ERROR_BASE_BAD_ARG CM_DBUS_ERROR_BASE ".bad_arg"
#define CM_DBUS_ERROR_BASE_DUPLICATE CM_DBUS_ERROR_BASE ".duplicate"
#define CM_DBUS_ERROR_BASE_NO_SUCH_ENTRY CM_DBUS_ERROR_BASE ".no_such_entry"
#define CM_DBUS_ERROR_CA_INTERNAL CM_DBUS_ERROR_CA ".internal"
#define CM_DBUS_ERROR_REQUEST_INTERNAL CM_DBUS_ERROR_REQUEST ".internal"
#define CM_DBUS_ERROR_REQUEST_BAD_ARG CM_DBUS_ERROR_REQUEST ".bad_arg"

#define CM_DBUS_PROP_NICKNAME "nickname"
#define CM_DBUS_PROP_AUTORENEW "autorenew"
#define CM_DBUS_PROP_CERT "cert"
#define CM_DBUS_PROP_CERT_CHAIN "cert-chain"
#define CM_DBUS_PROP_CERT_PRESAVE_COMMAND "cert-presave-command"
#define CM_DBUS_PROP_CERT_PRESAVE_UID "cert-presave-uid"
#define CM_DBUS_PROP_CERT_POSTSAVE_COMMAND "cert-postsave-command"
#define CM_DBUS_PROP_CERT_POSTSAVE_UID "cert-postsave-uid"
#define CM_DBUS_PROP_CERT_ISSUER "issuer"
#define CM_DBUS_PROP_CERT_SERIAL "serial"
#define CM_DBUS_PROP_CERT_SUBJECT "subject"
#define CM_DBUS_PROP_CERT_EMAIL "email"
#define CM_DBUS_PROP_CERT_KU "ku"
#define CM_DBUS_PROP_CERT_EKU "eku"
#define CM_DBUS_PROP_CERT_HOSTNAME "hostname"
#define CM_DBUS_PROP_CERT_PRINCIPAL "principal"
#define CM_DBUS_PROP_CERT_LAST_CHECKED "last-checked"
#define CM_DBUS_PROP_CERT_LOCATION_TYPE "cert-storage"
#define CM_DBUS_PROP_CERT_LOCATION_FILE "cert-file"
#define CM_DBUS_PROP_CERT_LOCATION_DATABASE "cert-database"
#define CM_DBUS_PROP_CERT_LOCATION_NICKNAME "cert-nickname"
#define CM_DBUS_PROP_CERT_LOCATION_TOKEN "cert-token"
#define CM_DBUS_PROP_CSR "csr"
#define CM_DBUS_PROP_TEMPLATE_SUBJECT "template-subject"
#define CM_DBUS_PROP_TEMPLATE_EMAIL "template-email"
#define CM_DBUS_PROP_TEMPLATE_KU "template-ku"
#define CM_DBUS_PROP_TEMPLATE_EKU "template-eku"
#define CM_DBUS_PROP_TEMPLATE_HOSTNAME "template-hostname"
#define CM_DBUS_PROP_TEMPLATE_PRINCIPAL "template-principal"
#define CM_DBUS_PROP_KEY_LOCATION_TYPE "key-storage"
#define CM_DBUS_PROP_KEY_LOCATION_FILE "key-file"
#define CM_DBUS_PROP_KEY_LOCATION_DATABASE "key-database"
#define CM_DBUS_PROP_KEY_LOCATION_NICKNAME "key-nickname"
#define CM_DBUS_PROP_KEY_LOCATION_TOKEN "key-token"
#define CM_DBUS_PROP_KEY_TYPE "key-type"
#define CM_DBUS_PROP_KEY_SIZE "key-size"
#define CM_DBUS_PROP_MONITORING "monitoring"
#define CM_DBUS_PROP_NOTIFICATION_TYPE "notification-type"
#define CM_DBUS_PROP_NOTIFICATION_SYSLOG_PRIORITY "notification-syslog-priority"
#define CM_DBUS_PROP_NOTIFICATION_EMAIL "notification-email"
#define CM_DBUS_PROP_NOTIFICATION_COMMAND "notification-command"
#define CM_DBUS_PROP_KEY_PIN_FILE "key-pin-file"
#define CM_DBUS_PROP_KEY_PIN "key-pin"
#define CM_DBUS_PROP_STATUS "status"
#define CM_DBUS_PROP_STUCK "stuck"
#define CM_DBUS_PROP_CA "ca"
#define CM_DBUS_PROP_CA_PROFILE "ca-profile"
#define CM_DBUS_PROP_CA_COOKIE "ca-cookie"
#define CM_DBUS_PROP_CA_ERROR "ca-error"
#define CM_DBUS_PROP_SUBMITTED_DATE "submitted-date"
#define CM_DBUS_PROP_IS_DEFAULT "is-default"
#define CM_DBUS_PROP_EXTERNAL_HELPER "external-helper"
#define CM_DBUS_PROP_ISSUER_NAMES "issuer-names"
#define CM_DBUS_PROP_TEMPLATE_IP_ADDRESS "template-ip-address"
#define CM_DBUS_PROP_TEMPLATE_IS_CA "template-is-ca"
#define CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH "template-ca-path-length"
#define CM_DBUS_PROP_TEMPLATE_OCSP "template-ocsp"
#define CM_DBUS_PROP_TEMPLATE_CRL_DP "template-crldp"
#define CM_DBUS_PROP_TEMPLATE_FRESHEST_CRL "template-freshest-crl"
#define CM_DBUS_PROP_TEMPLATE_NS_COMMENT "template-ns-comment"
#define CM_DBUS_PROP_TEMPLATE_PROFILE "template-profile"
#define CM_DBUS_SIGNAL_REQUEST_CERT_SAVED "SavedCertificate"
#define CM_DBUS_PROP_CA_PRESAVE_COMMAND "ca-presave-command"
#define CM_DBUS_PROP_CA_PRESAVE_UID "ca-presave-uid"
#define CM_DBUS_PROP_CA_POSTSAVE_COMMAND "ca-postsave-command"
#define CM_DBUS_PROP_CA_POSTSAVE_UID "ca-postsave-uid"
#define CM_DBUS_PROP_ROOT_CERTS "root-certs"
#define CM_DBUS_PROP_OTHER_ROOT_CERTS "root-other-certs"
#define CM_DBUS_PROP_OTHER_CERTS "other-certs"
#define CM_DBUS_PROP_ROOT_CERT_FILES "root-cert-files"
#define CM_DBUS_PROP_OTHER_ROOT_CERT_FILES "root-other-cert-files"
#define CM_DBUS_PROP_OTHER_CERT_FILES "other-cert-files"
#define CM_DBUS_PROP_ROOT_CERT_NSSDBS "root-cert-nssdbs"
#define CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS "root-other-cert-nssdbs"
#define CM_DBUS_PROP_OTHER_CERT_NSSDBS "other-cert-nssdbs"
#define CM_DBUS_PROP_SUPPORTED_PROFILES "supported-profiles"
#define CM_DBUS_PROP_DEFAULT_PROFILE "default-profile"
#define CM_DBUS_PROP_REQUIRED_ENROLL_ATTRIBUTES "required-enroll-attributes"
#define CM_DBUS_PROP_REQUIRED_RENEW_ATTRIBUTES "required-renew-attributes"
#define CM_DBUS_PROP_AKA "aka"

enum cm_tdbus_type { cm_tdbus_system, cm_tdbus_session };
int cm_tdbus_setup(struct tevent_context *ec, enum cm_tdbus_type bus_type,
		   void *data, DBusError *error);

#endif
