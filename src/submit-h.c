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

#include "config.h"

#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include "log.h"
#include "submit-e.h"
#include "submit-h.h"

struct cm_submit_h_context {
	int ret;
	char *method, *uri, *args, *result;
};

struct cm_submit_h_context *
cm_submit_h_init(const char *method, const char *uri, const char *args)
{
	return NULL;
}

void
cm_submit_h_run(struct cm_submit_h_context *ctx)
{
}

int
cm_submit_h_result_code(struct cm_submit_h_context *ctx)
{
	return -1;
}

const char *
cm_submit_h_results(struct cm_submit_h_context *ctx)
{
	return NULL;
}
