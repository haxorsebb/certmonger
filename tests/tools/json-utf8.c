/*
 * Copyright (C) 2015 Red Hat, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>

#include "../../src/json.h"

int
main(int argc, char **argv)
{
	uint32_t point, point2;
	char buf[7];
	int n, o;

	for (point = 0; point < 0x5000000; point++) {
		if ((point >= 0xd800) && (point <= 0xdfff)) {
			continue;
		}
		n = cm_json_point_to_utf8_length(point);
		switch (n) {
		case 1:
			if (point > 0x7f) {
				fprintf(stderr, "error at point %lu: %d\n",
					(unsigned long) point, n);
				return n;
			}
			break;
		case 2:
			if ((point < 0x80) || (point > 0x7ff)) {
				fprintf(stderr, "error at point %lu: %d\n",
					(unsigned long) point, n);
				return n;
			}
			break;
		case 3:
			if ((point < 0x800) || (point > 0xffff)) {
				fprintf(stderr, "error at point %lu: %d\n",
					(unsigned long) point, n);
				return n;
			}
			break;
		case 4:
			if ((point < 0x10000) || (point > 0x1fffff)) {
				fprintf(stderr, "error at point %lu: %d\n",
					(unsigned long) point, n);
				return n;
			}
			break;
		case 5:
			if ((point < 0x200000) || (point > 0x3ffffff)) {
				fprintf(stderr, "error at point %lu: %d\n",
					(unsigned long) point, n);
				return n;
			}
			break;
		case 6:
			if ((point < 0x4000000) || (point > 0x7fffffff)) {
				fprintf(stderr, "error at point %lu: %d\n",
					(unsigned long) point, n);
				return n;
			}
			break;
		default:
			fprintf(stderr, "error at point %lu: %d\n",
				(unsigned long) point, n);
			return 7;
			break;
		}
		memset(buf, '\0', sizeof(buf));
		o = cm_json_point_to_utf8(point, buf, sizeof(buf));
		if (o != n) {
			fprintf(stderr, "error at encoding of %lu: %d\n",
				(unsigned long) point, o);
			return 8;
		}
		o = cm_json_utf8_to_point(buf, &point2);
		if (o != n) {
			fprintf(stderr, "error at decoding of %s (%lu): %d\n",
				buf, (unsigned long) point, o);
			return 8;
		}
		if (point2 != point) {
			fprintf(stderr, "decode mismatch: expected \"%s\" to be %lu, got %lu\n",
				buf, (unsigned long) point, (unsigned long) point2);
			return 9;
		}
	}
	return 0;
}
