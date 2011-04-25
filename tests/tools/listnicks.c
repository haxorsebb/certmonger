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

#include "../../src/config.h"

#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include <nss.h>
#include <certt.h>
#include <certdb.h>
#include <cert.h>
#include <pk11pub.h>

#include "../../src/log.h"
#include "../../src/store.h"
#include "../../src/store-int.h"

int
main(int argc, char **argv)
{
	struct cm_store_entry *entry;
	int i;
	void *parent;
	CERTCertList *certlist;
	CERTCertListNode *node;
	SECStatus error;

	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	parent = talloc_new(NULL);
	if (argc > 1) {
		entry = cm_store_files_entry_read(parent, argv[1]);
		if (entry == NULL) {
			printf("Error reading %s: %s.\n", argv[1],
			       strerror(errno));
			return 1;
		}
	} else {
		printf("Specify an entry file as the single argument.\n");
		return 1;
	}
	if (entry->cm_cert_storage_type != cm_cert_storage_nssdb) {
		cm_log(1, "Storage type is not NSSDB.\n");
		return 1;
	}
	/* Open the database. */
	error = NSS_Init(entry->cm_cert_storage_location);
	if (error != SECSuccess) {
		cm_log(1, "Unable to open NSS database.\n");
		_exit(1);
	}
	/* Walk the list of names, if we got one. */
	certlist = PK11_ListCerts(PK11CertListAll, NULL);
	if (certlist != NULL) {
		/* Delete the existing cert. */
		i = 0;
		for (node = CERT_LIST_HEAD(certlist);
		     !CERT_LIST_EMPTY(certlist) &&
		     !CERT_LIST_END(node, certlist);
		     node = CERT_LIST_NEXT(node)) {
			printf("%d: \"%s\"\n", ++i, node->cert->nickname);
		}
		CERT_DestroyCertList(certlist);
	}
	talloc_free(parent);
	if (NSS_Shutdown() != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	return 0;
}
