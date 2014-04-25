/*
 * Copyright (C) 2014 Red Hat, Inc.
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

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_GMP_H
#include <gmp.h>
#endif
#ifdef HAVE_OPENSSL
#include <openssl/bn.h>
#include <openssl/crypto.h>
#endif

#ifdef HAVE_GMP
char *
util_dec_from_hex(const char *hex)
{
	mpz_t m;
	char *ret;

	mpz_init(m);
	if (mpz_set_str(m, hex, 16) != 0) {
		return NULL;
	}
	ret = mpz_get_str(NULL, 10, m);
	mpz_clear(m);
	return ret;
}
#else
#ifdef HAVE_OPENSSL
#if defined(HAVE_DECL_OPENSSL_FREE) && HAVE_DECL_OPENSSL_FREE
static void
free_bn_bn2dec_result(void *p)
{
	OPENSSL_free(p);
}
#else
static void
free_bn_bn2dec_result(void *p)
{
	free(p);
}
#endif
char *
util_dec_from_hex(const char *hex)
{
	BIGNUM *bn = NULL;
	char *tmp, *ret = NULL;

	if (strlen(hex) > 0) {
		if (BN_hex2bn(&bn, hex) == 0) {
			return NULL;
		}
		tmp = BN_bn2dec(bn);
		BN_free(bn);
		if (tmp != NULL) {
			ret = strdup(tmp);
			free_bn_bn2dec_result(tmp);
		}
	} else {
		ret = strdup("");
	}
	return ret;
}
#endif
#endif
