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

#include <stdlib.h>
#include <time.h>

#include "../../src/tm.h"

time_t
cm_time(time_t *dest)
{
	long t;
	if (getenv("CM_FORCE_TIME") != NULL) {
		t = atol(getenv("CM_FORCE_TIME"));
		if (dest != NULL) {
			*dest = t;
		}
		return t;
	} else {
		return time(dest);
	}
}
