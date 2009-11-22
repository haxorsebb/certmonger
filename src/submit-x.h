/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#ifndef cmsubmitx_h
#define cmsubmitx_h

int cm_submit_x_make_ccache(const char *ktname, const char *principal);

struct cm_submit_x_context;
struct cm_submit_x_context *cm_submit_x_init(void *parent, const char *uri,
					     const char *method,
					     const char *cainfo,
					     const char *capath,
					     int negotiate);
void cm_submit_x_run(struct cm_submit_x_context *ctx);
int cm_submit_x_has_results(struct cm_submit_x_context *ctx);

void cm_submit_x_add_arg_s(struct cm_submit_x_context *ctx, const char *s);
void cm_submit_x_add_arg_b(struct cm_submit_x_context *ctx, int b);
void cm_submit_x_add_named_arg_s(struct cm_submit_x_context *ctx,
				 const char *name, const char *s);
void cm_submit_x_add_named_arg_b(struct cm_submit_x_context *ctx,
				 const char *name, int b);

int cm_submit_x_get_bss(struct cm_submit_x_context *ctx, int *b,
			char **s1, char **s2);
int cm_submit_x_get_b(struct cm_submit_x_context *ctx, int idx, int *b);
int cm_submit_x_get_s(struct cm_submit_x_context *ctx, int idx, char **s);
int cm_submit_x_get_named_n(struct cm_submit_x_context *ctx,
			    const char *name, int *n);
int cm_submit_x_get_named_b(struct cm_submit_x_context *ctx,
			    const char *name, int *b);
int cm_submit_x_get_named_s(struct cm_submit_x_context *ctx,
			    const char *name, char **s);

#endif
