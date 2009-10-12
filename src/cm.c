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

#include "config.h"

#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>
#include <tevent.h>

#include "cm.h"
#include "log.h"
#include "iterate.h"
#include "store.h"
#include "store-int.h"

#define DELAY_SOON	1
#define DELAY_SOONISH	5

struct cm_context {
	int n_entries, should_quit;
	struct cm_store_entry **entries;
	struct cm_event {
		void *iterate_state;
		void *next_event;
	} *events;
};

static void *cm_service_one(struct cm_context *context,
			    struct timeval *now, int i);
static void cm_fd_h(struct tevent_context *ec, struct tevent_fd *fde,
		    uint16_t flags, void *pvt);
static void cm_timer_h(struct tevent_context *ec, struct tevent_timer *te,
		       struct timeval current_time, void *pvt);
static void cm_break_h(struct tevent_context *ec, struct tevent_signal *se,
		       int signum, int count, void *siginfo, void *ctx);

int
cm_init(struct tevent_context *parent, struct cm_context **context)
{
	struct cm_context *ctx;
	int i, j;
	*context = NULL;
	ctx = talloc_ptrtype(parent, ctx);
	if (ctx == NULL) {
		return ENOMEM;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->entries = cm_store_get_all_entries(ctx);
	for (i = 0; (ctx->entries != NULL) && (ctx->entries[i] != NULL); i++) {
		continue;
	}
	ctx->n_entries = i;
	ctx->events = talloc_array_ptrtype(ctx, ctx->events, i);
	if (ctx->events == NULL) {
		talloc_free(ctx);
		return ENOMEM;
	}
	tevent_add_signal(parent, NULL, SIGINT, 0, cm_break_h, ctx);
	tevent_add_signal(parent, NULL, SIGTERM, 0, cm_break_h, ctx);
	for (i = 0; i < ctx->n_entries; i++) {
		memset(&ctx->events[i], 0, sizeof(ctx->events[i]));
		if (cm_iterate_init(ctx->entries[i],
				    &ctx->events[i].iterate_state) != 0) {
			for (j = 0; j < i; j++) {
				talloc_free(ctx->events[i].next_event);
				ctx->events[i].next_event = NULL;
				cm_iterate_done(ctx->entries[j],
						ctx->events[j].iterate_state);
				ctx->events[j].iterate_state = NULL;
			}
			talloc_free(ctx);
			return ENOMEM;
		}
	}
	*context = ctx;
	return 0;
}

static void
cm_timer_h(struct tevent_context *ec, struct tevent_timer *te,
	   struct timeval current_time, void *pvt)
{
	struct cm_context *context = pvt;
	int i;
	talloc_free(te);
	for (i = 0; i < context->n_entries; i++) {
		if (context->events[i].next_event == te) {
			context->events[i].next_event = cm_service_one(context,
								       NULL, i);
		}
		break;
	}
	if (i >= context->n_entries) {
		cm_log(3, "Bug: unowned timer fired.\n");
	}
}

static void
cm_fd_h(struct tevent_context *ec,
	struct tevent_fd *fde, uint16_t flags, void *pvt)
{
	struct cm_context *context = pvt;
	int i;
	talloc_free(fde);
	for (i = 0; i < context->n_entries; i++) {
		if (context->events[i].next_event == fde) {
			context->events[i].next_event = cm_service_one(context,
								       NULL, i);
		}
		break;
	}
	if (i >= context->n_entries) {
		cm_log(3, "Bug: unowned FD watch fired.\n");
	}
}

static void
cm_break_h(struct tevent_context *ec, struct tevent_signal *se,
	   int signum, int count, void *siginfo, void *pvt)
{
	struct cm_context *ctx = pvt;
	cm_log(3, "Got signal %d.\n", signum);
	ctx->should_quit++;
}

static void *
cm_service_one(struct cm_context *context, struct timeval *current_time, int i)
{
	int ret, delay, fd;
	struct timeval now, then;
	enum cm_time when;
	void *t;

	if (current_time != NULL) {
		now = *current_time;
	} else {
		now = tevent_timeval_current();
	}
	ret = cm_iterate(context->entries[i], context->events[i].iterate_state,
			 &when, &delay, &fd);
	t = NULL;
	if (ret == 0) {
		switch (when) {
		case cm_time_now:
			t = tevent_add_timer(talloc_parent(context), NULL,
					     now, cm_timer_h, context);
			cm_log(3, "Will revisit '%s' now.\n",
			       context->entries[i]->cm_id);
			break;
		case cm_time_soon:
			then = tevent_timeval_add(&now, DELAY_SOON, 0);
			t = tevent_add_timer(talloc_parent(context), NULL,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit '%s' soon.\n",
			       context->entries[i]->cm_id);
			break;
		case cm_time_soonish:
			then = tevent_timeval_add(&now, DELAY_SOONISH, 0);
			t = tevent_add_timer(talloc_parent(context), NULL,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit '%s' soonish.\n",
			       context->entries[i]->cm_id);
			break;
		case cm_time_delay:
			then = tevent_timeval_add(&now, delay, 0);
			t = tevent_add_timer(talloc_parent(context), NULL,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit '%s' in %d seconds.\n",
			       context->entries[i]->cm_id, delay);
			break;
		case cm_time_no_time:
			t = tevent_add_fd(talloc_parent(context), NULL,
					  fd, TEVENT_FD_READ,
					  cm_fd_h, context);
			cm_log(3, "Will revisit '%s' on traffic from %d.\n",
			       context->entries[i]->cm_id, fd);
			break;
		}
	}
	return t;
}

int
cm_start_all(struct cm_context *context)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		context->events[i].next_event = cm_service_one(context,
							       NULL, i);
	}
	return 0;
}

int
cm_keep_going(struct cm_context *context)
{
	return context->should_quit;
}

void
cm_done(struct cm_context *context)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		talloc_free(context->events[i].next_event);
		context->events[i].next_event = NULL;
		cm_iterate_done(context->entries[i],
				context->events[i].iterate_state);
		context->events[i].iterate_state = NULL;
		cm_store_entry_save(context->entries[i]);
	}
	talloc_free(context);
}

int
cm_add_entry(struct cm_context *context, struct cm_store_entry *new_entry)
{
	struct cm_store_entry **entries;
	struct cm_event *events;
	int i, j;
	/* Check for duplicates and count the number of entries we're already
	 * managing. */
	for (i = 0; i < context->n_entries; i++) {
		if (strcmp(context->entries[i]->cm_id, new_entry->cm_id) == 0) {
			return -1;
		}
	}
	/* Allocate storage for a new entry array. */
	entries = talloc_array(context, struct cm_store_entry *, i + 2);
	if (entries != NULL) {
		/* Allocate storage for a new entry state array. */
		events = talloc_array(context, struct cm_event, i + 1);
		if (events != NULL) {
			/* Copy the entries to the new arrays. */
			for (j = 0; j < i; j++) {
				talloc_reparent(entries, context->entries,
						context->entries[j]);
				entries[j] = context->entries[j];
			}
			memcpy(events, context->events,
			       sizeof(struct cm_event) * i);
			/* Add the new members. */
			talloc_reparent(talloc_parent(new_entry), entries,
					new_entry);
			entries[i] = new_entry;
			memset(&events[i], 0, sizeof(events[i]));
			/* Reset the pointers. */
			talloc_free(context->entries);
			context->entries = entries;
			talloc_free(context->events);
			context->events = events;
			/* Reset the recorded count of entries. */
			context->n_entries++;
			entries[context->n_entries] = NULL;
		} else {
			talloc_free(entries);
			entries = NULL;
		}
	}
	if ((entries != NULL) && (events != NULL)) {
		/* Prepare to set this entry in motion. */
		if (cm_iterate_init(context->entries[i],
				    &context->events[i].iterate_state) != 0) {
			cm_log(3, "Error starting '%s', please retry.\n",
			       context->entries[i]->cm_id);
		} else {
			/* Set this entry in motion. */
			context->events[i].next_event = cm_service_one(context,
								       NULL, i);
		}
		/* Save this entry to the store, too. */
		cm_store_entry_save(new_entry);
		return 0;
	}
	return -1;
}

void
cm_kick(struct cm_context *context, const char *id)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		if (strcmp(context->entries[i]->cm_id, id) == 0) {
			talloc_free(context->events[i].next_event);
			context->events[i].next_event = NULL;
			cm_iterate_done(context->entries[i],
					context->events[i].iterate_state);
			context->events[i].iterate_state = NULL;
			if (cm_iterate_init(context->entries[i],
					    &context->events[i].iterate_state) == 0) {
				context->events[i].next_event =
					cm_service_one(context, NULL, i);
			} else {
				cm_log(3, "Error restarting '%s', "
				       "please retry.\n",
				       context->entries[i]->cm_id);
			}
			break;
		}
	}
}

struct cm_store_entry *
cm_get_entry_by_id(struct cm_context *context, const char *id)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		if (strcmp(context->entries[i]->cm_id, id) == 0) {
			return context->entries[i];
		}
	}
	return NULL;
}

struct cm_store_entry *
cm_get_entry_by_index(struct cm_context *context, int i)
{
	if (i < context->n_entries) {
		return context->entries[i];
	}
	return NULL;
}

int
cm_get_n_entries(struct cm_context *context)
{
	return context->n_entries;
}
