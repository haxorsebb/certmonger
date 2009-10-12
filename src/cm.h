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

#ifndef cmcm_h
#define cmcm_h

struct cm_context;
struct cm_store_entry;
struct tevent_context;

int cm_init(struct tevent_context *parent, struct cm_context **context);
int cm_start_all(struct cm_context *context);
int cm_keep_going(struct cm_context *context);
void cm_done(struct cm_context *context);

int cm_get_n_entries(struct cm_context *context);
struct cm_store_entry *cm_get_entry_by_index(struct cm_context *c, int i);
struct cm_store_entry *cm_get_entry_by_id(struct cm_context *c, const char *id);
void cm_kick(struct cm_context *c, const char *id);

#endif
