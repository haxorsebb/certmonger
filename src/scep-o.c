/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <openssl/objects.h>

#include "scep-o.h"

int
cm_scep_o_get_msgtype_nid(void)
{
	static int nid = -1;
	if (nid == -1) {
		nid = OBJ_create("2.16.840.1.113733.1.9.2", "scep-messageType", "id-scep-messageType");
	}
	return nid;
}

int
cm_scep_o_get_pkistatus_nid(void)
{
	static int nid = -1;
	if (nid == -1) {
		nid = OBJ_create("2.16.840.1.113733.1.9.3", "scep-pkiStatus", "id-scep-pkiStatus");
	}
	return nid;
}

int
cm_scep_o_get_failinfo_nid(void)
{
	static int nid = -1;
	if (nid == -1) {
		nid = OBJ_create("2.16.840.1.113733.1.9.4", "scep-failInfo", "id-scep-failInfo");
	}
	return nid;
}

int
cm_scep_o_get_sender_nonce_nid(void)
{
	static int nid = -1;
	if (nid == -1) {
		nid = OBJ_create("2.16.840.1.113733.1.9.5", "scep-senderNonce", "id-scep-senderNonce");
	}
	return nid;
}

int
cm_scep_o_get_recipient_nonce_nid(void)
{
	static int nid = -1;
	if (nid == -1) {
		nid = OBJ_create("2.16.840.1.113733.1.9.6", "scep-recipientNonce", "id-scep-recipientNonce");
	}
	return nid;
}

int
cm_scep_o_get_tx_nid(void)
{
	static int nid = -1;
	if (nid == -1) {
		nid = OBJ_create("2.16.840.1.113733.1.9.7", "scep-transId", "id-scep-transId");
	}
	return nid;
}
