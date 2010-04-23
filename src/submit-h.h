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

#ifndef cmsubmith_h
#define cmsubmith_h

struct cm_submit_h_context;
struct cm_submit_h_context *cm_submit_h_init(void *parent,
					     const char *method,
					     const char *uri,
					     const char *args);
void cm_submit_h_run(struct cm_submit_h_context *ctx);
int cm_submit_h_result_code(struct cm_submit_h_context *ctx);
const char *cm_submit_h_results(struct cm_submit_h_context *ctx);

#endif
