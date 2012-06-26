/*
 * Copyright (C) 2012 Red Hat, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <krb5.h>

#include "../../src/submit.h"
#include "../../src/submit-d.h"
#include "../../src/submit-e.h"
#include "../../src/submit-u.h"

int
main(int argc, char **argv)
{
	const char *mode, *filename;
	char *xml, *out = NULL, *err = NULL;
	int i;

	if (argc < 3) {
		printf("usage: dparse "
		       "[submit|check|review|reject|approve|fetch] "
		       "reply.xml\n");
		return 0;
	}
	mode = argv[1];
	filename = argv[2];

	xml = cm_submit_u_from_file(filename);
	if (xml == NULL) {
		fprintf(stderr, "error reading %s\n", filename);
		return -1;
	}

	if (strcmp(mode, "submit") == 0) {
		i = cm_submit_d_submit_eval(NULL, xml, &out, &err);
	} else
	if (strcmp(mode, "check") == 0) {
		i = cm_submit_d_check_eval(NULL, xml, &out, &err);
	} else
	if (strcmp(mode, "reject") == 0) {
		i = cm_submit_d_reject_eval(NULL, xml, &out, &err);
	} else
	if (strcmp(mode, "review") == 0) {
		i = cm_submit_d_review_eval(NULL, xml, &out, &err);
	} else
	if (strcmp(mode, "approve") == 0) {
		i = cm_submit_d_approve_eval(NULL, xml, &out, &err);
	} else
	if (strcmp(mode, "fetch") == 0) {
		i = cm_submit_d_fetch_eval(NULL, xml, &out, &err);
	} else {
		fprintf(stderr, "unknown mode \"%s\"\n", mode);
		return -1;
	}

	printf("[%s(%s) = %s]\n", mode, filename,
	       cm_submit_e_status_text(i));
	while ((out != NULL) && (*out != '\0')) {
		if (strchr("\r", *out) == NULL) {
			putchar((unsigned char) *out);
		}
		out++;
	}
	while ((err != NULL) && (*err != '\0')) {
		if (strchr("\r", *err) == NULL) {
			putchar((unsigned char) *err);
		}
		err++;
	}
	printf("\n");

	return 0;
}
