/*
 * Copyright (C) 2010 Red Hat, Inc.
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

#include <keythi.h>

#include <openssl/evp.h>

#include "prefs.h"
#include "prefs-int.h"
#include "prefs-o.h"

const EVP_MD *
cm_prefs_ossl_hash(void)
{
	switch (cm_prefs_preferred_digest()) {
	case cm_prefs_sha1:
		return EVP_sha1();
		break;
	case cm_prefs_sha256:
		return EVP_sha256();
		break;
	case cm_prefs_sha384:
		return EVP_sha384();
		break;
	case cm_prefs_sha512:
		return EVP_sha512();
		break;
	}
	return EVP_sha256();
}

const EVP_CIPHER *
cm_prefs_ossl_cipher(void)
{
	switch (cm_prefs_preferred_cipher()) {
	case cm_prefs_aes128:
		return EVP_aes_128_cbc();
		break;
	case cm_prefs_aes256:
		return EVP_aes_256_cbc();
		break;
	}
	return EVP_aes_128_cbc();
}
