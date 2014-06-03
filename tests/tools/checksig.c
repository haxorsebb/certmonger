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

#include "../../src/config.h"

#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include <nss.h>
#include <certt.h>
#include <certdb.h>
#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secport.h>

#include "../../src/log.h"
#include "../../src/store.h"
#include "../../src/store-int.h"

int
main(int argc, char **argv)
{
	int i;
	unsigned int len;
	unsigned char *p, *q, buf[LINE_MAX];
	SECItem encoded;
	CERTSignedData signed_data;
	CERTCertificate cert;
	SECKEYPublicKey *pubkey;
	CERTSubjectPublicKeyInfo *spki;

	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	p = NULL;
	len = 0;
	if (NSS_Initialize(".", NULL, NULL, NULL,
			   NSS_INIT_READONLY | NSS_INIT_NOCERTDB |
			   NSS_INIT_NOMODDB) != SECSuccess) {
		printf("error initializing NSS\n");
		return 1;
	}
	while ((i = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		q = realloc(p, len + i);
		if (q == NULL) {
			perror("malloc");
			free(p);
			return 1;
		}
		p = q;
		memcpy(p + len, buf, i);
		len += i;
	}
	memset(&encoded, 0, sizeof(encoded));
	encoded.data = p;
	encoded.len = len;
	memset(&signed_data, 0, sizeof(signed_data));
	if (SEC_ASN1DecodeItem(NULL, &signed_data,
			       CERT_SignedDataTemplate,
			       &encoded) != SECSuccess) {
		printf("error decoding certificate\n");
		return 1;
	}
	memset(&cert, 0, sizeof(cert));
	if (SEC_ASN1DecodeItem(NULL, &cert,
			       CERT_CertificateTemplate,
			       &signed_data.data) != SECSuccess) {
		printf("error decoding certificate data\n");
		return 1;
	}
	spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&cert.derPublicKey);
	if (spki == NULL) {
		printf("error decoding public key info\n");
		return 1;
	}
	pubkey = SECKEY_ExtractPublicKey(spki);
	if (pubkey == NULL) {
		printf("error finding public key\n");
		return 1;
	}
	if (VFY_VerifyDataWithAlgorithmID(signed_data.data.data,
					  signed_data.data.len,
					  pubkey,
					  &signed_data.signature,
					  &signed_data.signatureAlgorithm,
					  NULL,
					  NULL) != SECSuccess) {
		printf("error in verification: %s\n",
		       PR_ErrorToName(PORT_GetError()));
		return 1;
	}
	printf("verification OK\n");
	SECKEY_DestroyPublicKey(pubkey);
	SECKEY_DestroySubjectPublicKeyInfo(spki);
	NSS_Shutdown();
	return 0;
}
