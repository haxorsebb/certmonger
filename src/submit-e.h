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

#ifndef cmsubmite_h
#define cmsubmite_h

enum cm_external_status {
	CM_STATUS_ISSUED = 0,
	CM_STATUS_WAIT = 1,
	CM_STATUS_REJECTED = 2,
	CM_STATUS_UNREACHABLE = 3,
};

#define CM_SUBMIT_REQ_SUBJECT_ENV "CERTMONGER_REQ_SUBJECT"
#define CM_SUBMIT_REQ_HOSTNAME_ENV "CERTMONGER_REQ_HOSTNAME"
#define CM_SUBMIT_REQ_PRINCIPAL_ENV "CERTMONGER_REQ_PRINCIPAL"
#define CM_SUBMIT_REQ_EMAIL_ENV "CERTMONGER_REQ_EMAIL"
#define CM_SUBMIT_OPERATION_ENV "CERTMONGER_OPERATION"
#define CM_SUBMIT_CSR_ENV "CERTMONGER_CSR"
#define CM_SUBMIT_COOKIE_ENV "CERTMONGER_CA_COOKIE"

#endif
