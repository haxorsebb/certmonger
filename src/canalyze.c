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

#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <talloc.h>
#include <tevent.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prtime.h>
#include <secerr.h>

#include "canalyze.h"
#include "log.h"
#include "store-int.h"
#include "store.h"
#include "submit-e.h"
#include "subproc.h"

struct cm_ca_analyze_state {
	struct cm_subproc_state *subproc;
	long delay;
};

static PRTime
not_valid_after(PLArenaPool *arena, struct cm_nickcert *nc)
{
	CERTCertificate cert;
	CERTSignedData sdata;
	PRTime nvb, nva;
	const char *p, *q;
	char *pem;
	int length;

	p = strstr(nc->cm_cert, "-----BEGIN");
	if (p != NULL) {
		p += strcspn(p, "\r\n");
		p += strspn(p, "\r\n");
		q = strstr(p, "-----END");
	} else {
		p = nc->cm_cert;
		q = p + strlen(p);
	}
	pem = cm_store_base64_as_bin(nc, p, q - p, &length);
	if (pem != NULL) {
		memset(&sdata, 0, sizeof(sdata));
		memset(&cert, 0, sizeof(cert));
		if ((SEC_ASN1Decode(arena, &sdata,
				    SEC_ASN1_GET(CERT_SignedDataTemplate),
				    pem, length) != SECSuccess) ||
		    (SEC_ASN1Decode(arena, &cert,
				    SEC_ASN1_GET(CERT_CertificateTemplate),
				    (const char *) sdata.data.data,
				    sdata.data.len) != SECSuccess)) {
				cm_log(0, "Decoding error on \"%.*s\" "
				       "(%d bytes)!\n",
				       (int) (q - p), p, length);
				_exit(1);
			}
		if (CERT_GetCertTimes(&cert, &nvb, &nva) != SECSuccess) {
			cm_log(0, "Parsing error on \"%.*s\"!\n",
			       (int) (q - p), p);
			_exit(1);
		}
		if (nva < PR_Now()) {
			cm_log(1, "Certificate \"%s\" no longer valid.\n",
			       nc->cm_nickname);
			return 0;
		} else {
			cm_log(1, "Certificate \"%s\" valid for %llds.\n",
			       nc->cm_nickname,
			       (long long) ((nva - PR_Now()) / PR_USEC_PER_SEC));
			return nva;
		}
	}
	return 0;
}

static int
cm_ca_analyze_certs_main(int fd, struct cm_store_ca *ca,
			 struct cm_store_entry *e, void *data)
{
	PLArenaPool *arena;
	char *p;
	int i;
	PRTime result = 0, now, tmp;

	/* Walk the list of certificates we've retrieved, and print a number
	 * approximating the midpoint of time between now and the first of
	 * their not-valid-after dates. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(0, "Out of memory.\n");
		return 1;
	}
	for (i = 0;
	     (ca->cm_ca_root_certs != NULL) &&
	     (ca->cm_ca_root_certs[i] != NULL);
	     i++) {
		tmp = not_valid_after(arena, ca->cm_ca_root_certs[i]);
		result = result ?
			 (tmp ? ((result < tmp) ? result : tmp) : result) :
			 tmp;
		cm_log(3, "Running result is %lld.\n", (long long) result);
	}
	for (i = 0;
	     (ca->cm_ca_other_root_certs != NULL) &&
	     (ca->cm_ca_other_root_certs[i] != NULL);
	     i++) {
		tmp = not_valid_after(arena, ca->cm_ca_other_root_certs[i]);
		result = result ?
			 (tmp ? ((result < tmp) ? result : tmp) : result) :
			 tmp;
		cm_log(3, "Running result is %lld.\n", (long long) result);
	}
	for (i = 0;
	     (ca->cm_ca_other_certs != NULL) &&
	     (ca->cm_ca_other_certs[i] != NULL);
	     i++) {
		tmp = not_valid_after(arena, ca->cm_ca_other_certs[i]);
		result = result ?
			 (tmp ? ((result < tmp) ? result : tmp) : result) :
			 tmp;
		cm_log(3, "Running result is %lld.\n", (long long) result);
	}

	cm_log(3, "Final result is %lld.\n", (long long) result);
	now = PR_Now();
	if ((result != 0) && (result > now)) {
		result = (result - now) / PR_USEC_PER_SEC / 2;
	}

	p = talloc_asprintf(ca, "%lld", (long long) result);
	i = strlen(p);
	if (write(fd, p, strlen(p)) != i) {
		cm_log(0, "Error writing \"%s\" to pipe: %s.\n", p,
		       strerror(errno));
	}
	cm_log(3, "Time until refresh: %s.\n", p);

	talloc_free(p);
	PORT_FreeArena(arena, PR_TRUE);

	_exit(0);
}

static int
cm_ca_analyze_encryption_certs_main(int fd, struct cm_store_ca *ca,
				    struct cm_store_entry *e, void *data)
{
	PLArenaPool *arena;
	char *p;
	int i;
	PRTime result = 0, now, ratime, catime;
	struct cm_nickcert *racert, *cacert;

	if (ca->cm_ca_encryption_issuer_cert == NULL) {
		cacert = NULL;
	} else {
		cacert = talloc_ptrtype(ca, racert);
		cacert->cm_nickname = talloc_strdup(cacert, "CA certificate");
		cacert->cm_cert = ca->cm_ca_encryption_issuer_cert;
	}
	if (ca->cm_ca_encryption_cert == NULL) {
		racert = NULL;
	} else {
		racert = talloc_ptrtype(ca, racert);
		racert->cm_nickname = talloc_strdup(racert, cacert ?
						    "RA certificate" :
						    "CA certificate");
		racert->cm_cert = ca->cm_ca_encryption_cert;
	}

	/* Look at the RA and CA certificates, and print a number approximating
	 * the midpoint of time between now and the first of their
	 * not-valid-after dates. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(0, "Out of memory.\n");
		return 1;
	}
	now = PR_Now();
	ratime = CM_DELAY_CA_POLL_MAXIMUM;
	ratime *= PR_USEC_PER_SEC;
	ratime += now;
	if (racert != NULL) {
		ratime = not_valid_after(arena, racert);
	}
	catime = ratime;
	if (cacert != NULL) {
		catime = not_valid_after(arena, cacert);
	}
	if (ratime < catime) {
		result = ratime;
	} else {
		result = catime;
	}

	cm_log(3, "Result is %lld.\n", (long long) result);
	if ((result != 0) && (result > now)) {
		result = (result - now) / PR_USEC_PER_SEC / 2;
	}

	p = talloc_asprintf(ca, "%lld", (long long) result);
	i = strlen(p);
	if (write(fd, p, strlen(p)) != i) {
		cm_log(0, "Error writing \"%s\" to pipe: %s.\n", p,
		       strerror(errno));
	}

	talloc_free(p);
	PORT_FreeArena(arena, PR_TRUE);

	_exit(0);
}

struct cm_ca_analyze_state *
cm_ca_analyze_start_certs(struct cm_store_ca *ca)
{
	struct cm_ca_analyze_state *ret;

	ret = talloc_ptrtype(ca, ret);
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		ret->subproc = cm_subproc_start(&cm_ca_analyze_certs_main, ret,
						ca, NULL, ret);
	}
	return ret;
}

struct cm_ca_analyze_state *
cm_ca_analyze_start_encryption_certs(struct cm_store_ca *ca)
{
	struct cm_ca_analyze_state *ret;

	ret = talloc_ptrtype(ca, ret);
	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		ret->subproc = cm_subproc_start(&cm_ca_analyze_encryption_certs_main, ret,
						ca, NULL, ret);
	}
	return ret;
}

int
cm_ca_analyze_ready(struct cm_ca_analyze_state *state)
{
	int ready, length;
	const char *p;

	ready = cm_subproc_ready(state->subproc);
	if ((ready == 0) &&
	    (cm_subproc_get_exitstatus(state->subproc) == 0)) {
		p = cm_subproc_get_msg(state->subproc, &length);
		if (length > 0) {
			state->delay = atol(p);
		}
	}
	return ready;
}

long
cm_ca_analyze_get_delay(struct cm_ca_analyze_state *state)
{
	return state->delay;
}

int
cm_ca_analyze_get_fd(struct cm_ca_analyze_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

void
cm_ca_analyze_done(struct cm_ca_analyze_state *state)
{
	cm_subproc_done(state->subproc);
	talloc_free(state);
}
