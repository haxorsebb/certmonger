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

#include "../../src/config.h"

#include <sys/types.h>
#include <stdio.h>
#include <time.h>

#include "../../src/prefs.h"
#include "../../src/store-int.h"

int
main(int argc, char **argv)
{
	const char *dest;
	const time_t *ttls;
	unsigned int i, n_ttls;

	switch (cm_prefs_preferred_cipher()) {
	case cm_prefs_aes128:
		printf("cipher: AES128\n");
		break;
	case cm_prefs_aes256:
		printf("cipher: AES256\n");
		break;
	}
	switch (cm_prefs_preferred_digest()) {
	case cm_prefs_sha1:
		printf("digest: SHA1\n");
		break;
	case cm_prefs_sha256:
		printf("digest: SHA256\n");
		break;
	case cm_prefs_sha384:
		printf("digest: SHA384\n");
		break;
	case cm_prefs_sha512:
		printf("digest: SHA512\n");
		break;
	}

	if (cm_prefs_notify_ttls(&ttls, &n_ttls) == 0) {
		printf("notify_ttls: ");
		for (i = 0; i < n_ttls; i++) {
			printf("%s%llu", ((i > 0) ? ", " : ""),
			       (unsigned long long) ttls[i]);
		}
		printf("\n");
	}
	if (cm_prefs_enroll_ttls(&ttls, &n_ttls) == 0) {
		printf("enroll_ttls: ");
		for (i = 0; i < n_ttls; i++) {
			printf("%s%llu", ((i > 0) ? ", " : ""),
			       (unsigned long long) ttls[i]);
		}
		printf("\n");
	}

	dest = cm_prefs_notification_destination();
	switch (cm_prefs_notification_method()) {
	case cm_notification_unspecified:
		printf("notification: UNSPECIFIED:%s\n", dest);
		break;
	case cm_notification_none:
		printf("notification: NONE\n");
		break;
	case cm_notification_syslog:
		printf("notification: SYSLOG:%s\n", dest);
		break;
	case cm_notification_email:
		printf("notification: MAILTO:%s\n", dest);
		break;
	case cm_notification_stdout:
		printf("notification: STDOUT\n");
		break;
	case cm_notification_command:
		printf("notification: COMMAND:%s\n", dest);
		break;
	}

	return 0;
}
