/*
 * Copyright (C) 2009,2012 Red Hat, Inc.
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

#ifndef cmsubmite_h
#define cmsubmite_h

#define CM_DOGTAG_IPA_RENEW_AGENT_CA_NAME "dogtag-ipa-renew-agent"
#define CM_DOGTAG_IPA_RENEW_AGENT_HELPER_PATH \
	CM_DEFAULT_HELPER_PATH "/dogtag-ipa-renew-agent-submit"

enum cm_external_status {
	CM_STATUS_ISSUED = 0,
	CM_STATUS_WAIT = 1,
	CM_STATUS_REJECTED = 2,
	CM_STATUS_UNREACHABLE = 3,
	CM_STATUS_UNCONFIGURED = 4,
	CM_STATUS_WAIT_WITH_DELAY = 5,
	CM_STATUS_OPERATION_NOT_SUPPORTED = 6,
};
const char *cm_submit_e_status_text(enum cm_external_status status);

#define CM_SUBMIT_REQ_SUBJECT_ENV "CERTMONGER_REQ_SUBJECT"
#define CM_SUBMIT_REQ_HOSTNAME_ENV "CERTMONGER_REQ_HOSTNAME"
#define CM_SUBMIT_REQ_PRINCIPAL_ENV "CERTMONGER_REQ_PRINCIPAL"
#define CM_SUBMIT_REQ_EMAIL_ENV "CERTMONGER_REQ_EMAIL"
#define CM_SUBMIT_OPERATION_ENV "CERTMONGER_OPERATION"
#define CM_SUBMIT_CSR_ENV "CERTMONGER_CSR"
#define CM_SUBMIT_COOKIE_ENV "CERTMONGER_CA_COOKIE"
#define CM_SUBMIT_PROFILE_ENV "CERTMONGER_CA_PROFILE"
#define CM_SUBMIT_CERTIFICATE_ENV "CERTMONGER_CERTIFICATE"

#endif
