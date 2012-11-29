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
#include <stdlib.h>

#include "../../src/util-n.h"
#include "tools.h"

void
cm_set_fips_from_env(void)
{
	enum force_fips_mode force;
	if ((getenv("CERTMONGER_FORCE_FIPS") != NULL) &&
	    (atoi(getenv("CERTMONGER_FORCE_FIPS")) != 0)) {
		force = do_force_fips;
	} else {
		force = do_not_force_fips;
	}
	util_n_set_fips(force);
}
