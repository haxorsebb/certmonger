/*
 * Copyright (C) 2010,2014 Red Hat, Inc.
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

#include <nss.h>
#include <nss.h>
#include <keythi.h>
#include <secoidt.h>

#include "prefs.h"
#include "prefs-n.h"

unsigned int
cm_prefs_nss_sig_alg(SECKEYPrivateKey *pkey)
{
	switch (pkey->keyType) {
	case nullKey:
		switch (cm_prefs_preferred_digest()) {
		case cm_prefs_sha1:
			return SEC_OID_SHA1;
			break;
		case cm_prefs_sha256:
			return SEC_OID_SHA256;
			break;
		case cm_prefs_sha384:
			return SEC_OID_SHA384;
			break;
		case cm_prefs_sha512:
			return SEC_OID_SHA512;
			break;
		}
		return SEC_OID_SHA256;
		break;
	case rsaKey:
		switch (cm_prefs_preferred_digest()) {
		case cm_prefs_sha1:
			return SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION;
			break;
		case cm_prefs_sha256:
			return SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION;
			break;
		case cm_prefs_sha384:
			return SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION;
			break;
		case cm_prefs_sha512:
			return SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION;
			break;
		}
		return SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION;
		break;
	case rsaPssKey:
		return SEC_OID_PKCS1_RSA_PSS_SIGNATURE;
		break;
	case dsaKey:
		switch (cm_prefs_preferred_digest()) {
		case cm_prefs_sha1:
			return SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST;
			break;
		case cm_prefs_sha256:
			return SEC_OID_NIST_DSA_SIGNATURE_WITH_SHA256_DIGEST;
			break;
		case cm_prefs_sha384:
		case cm_prefs_sha512:
			break;
		}
		return SEC_OID_NIST_DSA_SIGNATURE_WITH_SHA256_DIGEST;
		break;
	case ecKey:
		switch (cm_prefs_preferred_digest()) {
		case cm_prefs_sha1:
			return SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE;
			break;
		case cm_prefs_sha256:
			return SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE;
			break;
		case cm_prefs_sha384:
			return SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE;
			break;
		case cm_prefs_sha512:
			return SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE;
			break;
		}
		return SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE;
		break;
	default:
		return SEC_OID_UNKNOWN;
		break;
	}
}
