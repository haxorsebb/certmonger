/*
 * Copyright (C) 2011 Red Hat, Inc.
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
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <keyhi.h>
#include <keythi.h>
#include <pk11pub.h>
#include <prerror.h>

#include "log.h"

int
main(int argc, char **argv)
{
	NSSInitContext *ctx;
	PLArenaPool *arena;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	CK_MECHANISM_TYPE mech = 0;
	CK_TOKEN_INFO info;
	const char *dbdir = "/etc/pki/nssdb", *token;
	int c;

	while ((c = getopt(argc, argv, "d:m:")) != -1) {
		switch (c) {
		case 'd':
			dbdir = optarg;
			break;
		case 'm':
			mech = atol(optarg);
			break;
		default:
			printf("Usage: toklist [-d dbdir] [-m mechnum]\n");
			return 1;
			break;
		}
	}
	printf("Mechanism %ld:\n", (long) mech);

	/* Open the database. */
	ctx = NSS_InitContext(dbdir, NULL, NULL, NULL, NULL,
			      NSS_INIT_NOROOTINIT | NSS_INIT_NOMODDB);
	if (ctx == NULL) {
		printf("Unable to open NSS database '%s'.\n", dbdir);
		_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
	}

	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		printf("Out of memory opening database '%s'.\n", dbdir);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			printf("Error shutting down NSS.\n");
		}
		_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
	}

	/* Find the tokens that we might use for key storage. */
	slotlist = PK11_GetAllTokens(mech, PR_FALSE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			printf("Error shutting down NSS.\n");
		}
		_exit(CM_SUB_STATUS_ERROR_NO_TOKEN);
	}

	for (sle = slotlist->head;
	     ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		/* Read the token's name. */
		token = PK11_GetTokenName(sle->slot);
		if (token != NULL) {
			printf("Found token '%s'.\n", token);
		} else {
			printf("Found unnamed token.\n");
		}
		if (sle->slot == PK11_GetInternalSlot()) {
			printf("\tIs internal slot.\n");
		}
		if (sle->slot == PK11_GetInternalKeySlot()) {
			printf("\tIs internal key slot.\n");
		}
		memset(&info, 0, sizeof(info));
		if (PK11_GetTokenInfo(sle->slot, &info) == SECSuccess) {
			printf("\tFlags = %08lx\n", info.flags);
			printf("\tPIN Length = %lu..%lu\n", info.ulMinPinLen,
			       info.ulMaxPinLen);
		}
		/* Now log in, if we have to. */
		if (PK11_NeedLogin(sle->slot)) {
			printf("\tToken requires login.\n");
		} else {
			printf("\tToken does not require login.\n");
		}

		/* If this was the last token, stop walking. */
		if (sle == slotlist->tail) {
			break;
		}
	}

	PK11_FreeSlotList(slotlist);

	PORT_FreeArena(arena, PR_TRUE);

	return 0;
}
