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
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef CM_USE_IDN
#include <idna.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#endif
#ifdef HAVE_GMP
#include <gmp.h>
#endif

#include <talloc.h>

#include "srvloc.h"

#ifdef NS_MAXMSG
#define CM_MAXMSG NS_MAXMSG
#else
#define CM_MAXMSG 65535
#endif

#ifndef HAVE_NS_INITPARSE
int
cm_srvloc_resolve(void *parent, const char *name, const char *domain,
		  struct cm_srvloc **results)
{
	return -1;
}
#else
static int
cm_srvloc_priority_sort(const void *a, const void *b)
{
	const struct cm_srvloc *sa, *sb;

	sa = a;
	sb = b;
	return sa->priority - sb->priority;
}

static int
cm_srvloc_weight_sort(const void *a, const void *b)
{
	const struct cm_srvloc *sa, *sb;

	sa = a;
	sb = b;
	return sa->weight - sb->weight;
}

#ifdef HAVE_OPENSSL
static unsigned int
cm_srvloc_rand(unsigned int range)
{
	long long r;

	if (RAND_status() != 1) {
		return 0;
	}
	if (RAND_pseudo_bytes((unsigned char *) &r, sizeof(r)) == -1) {
		return 0;
	}
	if (r < 0) {
		r = -r;
	}
	return r % range;
}
#else
#ifdef HAVE_GMP
static unsigned int
cm_srvloc_rand(unsigned int range)
{
	static gmp_randstate_t state;
	static int initialized = 0;

	if (initialized == 0) {
		gmp_randinit_default(state);
		initialized++;
	}
	return gmp_urandomm_ui(state, range);
}
#else
static unsigned int
cm_srvloc_rand(unsigned int range)
{
	return 0;
}
#endif
#endif

static void
cm_srvloc_weigh(struct cm_srvloc *res, int n)
{
	int i, j, k, tweight;
	struct cm_srvloc tmp;
	long long r;

	qsort(res, n, sizeof(res[0]), cm_srvloc_weight_sort);
	for (i = 0; res[i].weight == 0; i++) {
		continue;
	}
	if (i == n) {
		return;
	}
	for (j = i; j < n - 1; j++) {
		tweight = 0;
		for (k = j; k < n; k++) {
			tweight += res[k].weight;
		}
		r = cm_srvloc_rand(tweight);
		tweight = 0;
		for (k = j; k < n; k++) {
			tweight += res[k].weight;
			if (tweight > r) {
				break;
			}
		}
		if (k >= n) {
			continue;
		}
		memcpy(&tmp, &res[j], sizeof(tmp));
		memcpy(&res[j], &res[k], sizeof(tmp));
		memcpy(&res[k], &tmp, sizeof(tmp));
	}
}

int
cm_srvloc_resolve(void *parent, const char *name, const char *udomain,
		  struct cm_srvloc **results)
{
	int i, j, n, hi, weights;
	unsigned char *answer;
	char *domain;
	size_t answer_len = CM_MAXMSG;
	struct cm_srvloc *res = NULL;
	ns_msg msg;
	ns_rr rr;

	*results = NULL;

	res_init();
	answer = talloc_zero_size(parent, answer_len + 1);
	if (answer == NULL) {
		return -1;
	}
#ifdef CM_USE_IDN
	if (idna_to_ascii_lz(udomain, &domain, 0) != IDNA_SUCCESS) {
		domain = strdup(udomain);
	}
#else
	domain = strdup(udomain);
#endif
	i = res_querydomain(name, domain, C_IN, T_SRV, answer, answer_len);
	if (i == -1) {
		return -1;
	}
	answer_len = i;
	memset(&msg, 0, sizeof(msg));
	if (ns_initparse(answer, answer_len, &msg) != 0) {
		return -1;
	}
	memset(&rr, 0, sizeof(rr));
	for (i = 0; ns_parserr(&msg, ns_s_an, i, &rr) == 0; i++) {
		continue;
	}
	if (i == 0) {
		return -1;
	}
	n = i;
	res = talloc_array_ptrtype(parent, res, i);
	if (res == NULL) {
		return -1;
	}
	memset(res, 0, sizeof(*res) * i);
	for (i = 0, j = 0; i < n; i++) {
		if (ns_parserr(&msg, ns_s_an, i, &rr) != 0) {
			continue;
		}
		if (rr.rdlength < 6) {
			continue;
		}
		res[j].host = talloc_size(res, answer_len + 1);
		if (res[j].host == NULL) {
			return -1;
		}
		res[j].priority = ntohs(*(uint16_t *)rr.rdata);
		res[j].weight = ntohs(*(uint16_t *)(rr.rdata + 2));
		res[j].port = ntohs(*(uint16_t *)(rr.rdata + 4));
		memcpy(res[j].host, rr.rdata + 6, rr.rdlength - 6);
		if (ns_name_ntop(rr.rdata + 6, res[j].host, answer_len) == -1) {
			continue;
		}
		res[j].host[answer_len] = '\0';
		j++;
	}
	n = j;
	qsort(res, n, sizeof(res[0]), cm_srvloc_priority_sort);
	i = 0;
	while (i < n) {
		weights = res[i].weight;
		for (hi = i + 1;
		     (hi < n) && (res[hi].priority == res[i].priority);
		     hi++) {
			weights += res[hi].weight;
		}
		cm_srvloc_weigh(res + i, hi - i);
		i = hi;
		if (weights == 0) {
			continue;
		}
	}
	talloc_free(answer);
	for (i = 0; i < n - 1; i++) {
		res[i].next = &res[i + 1];
	}
	*results = res;
	return 0;
}
#endif
