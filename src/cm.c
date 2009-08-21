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
		struct cm_context *c;
		int i;
		void *iterate_state;
	} *events;
};

static void cm_service_one(struct cm_context *context,
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
		ctx->events[i].c = ctx;
		if (cm_iterate_init(ctx->entries[i],
				    &ctx->events[i].iterate_state) != 0) {
			for (j = 0; j < i; j++) {
				cm_iterate_done(ctx->entries[j],
						ctx->events[j].iterate_state);
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
	struct cm_event *event = pvt;
	talloc_free(te);
	cm_service_one(event->c, NULL, event - event->c->events);
}

static void
cm_fd_h(struct tevent_context *ec,
	struct tevent_fd *fde, uint16_t flags, void *pvt)
{
	struct cm_event *event = pvt;
	talloc_free(fde);
	cm_service_one(event->c, NULL, event - event->c->events);
}

static void
cm_break_h(struct tevent_context *ec, struct tevent_signal *se,
	   int signum, int count, void *siginfo, void *pvt)
{
	struct cm_context *ctx = pvt;
	cm_log(3, "Got signal %d.\n", signum);
	ctx->should_quit++;
}

static void
cm_service_one(struct cm_context *context, struct timeval *current_time, int i)
{
	int ret, delay, fd;
	struct timeval now, then;
	enum cm_time when;
	struct tevent_fd *tfd;

	if (current_time != NULL) {
		now = *current_time;
	} else {
		now = tevent_timeval_current();
	}
	ret = cm_iterate(context->entries[i], context->events[i].iterate_state,
			 &when, &delay, &fd);
	if (ret == 0) {
		switch (when) {
		case cm_time_now:
			tevent_add_timer(talloc_parent(context), NULL,
					 now, cm_timer_h, &context->events[i]);
			cm_log(3, "Will revisit '%s' now.\n",
			       context->entries[i]->cm_id);
			break;
		case cm_time_soon:
			then = tevent_timeval_add(&now, DELAY_SOON, 0);
			tevent_add_timer(talloc_parent(context), NULL,
					 then, cm_timer_h, &context->events[i]);
			cm_log(3, "Will revisit '%s' soon.\n",
			       context->entries[i]->cm_id);
			break;
		case cm_time_soonish:
			then = tevent_timeval_add(&now, DELAY_SOONISH, 0);
			tevent_add_timer(talloc_parent(context), NULL,
					 then, cm_timer_h, &context->events[i]);
			cm_log(3, "Will revisit '%s' soonish.\n",
			       context->entries[i]->cm_id);
			break;
		case cm_time_delay:
			then = tevent_timeval_add(&now, delay, 0);
			tevent_add_timer(talloc_parent(context), NULL,
					 then, cm_timer_h, &context->events[i]);
			cm_log(3, "Will revisit '%s' in %d seconds.\n",
			       context->entries[i]->cm_id, delay);
			break;
		case cm_time_no_time:
			tfd = tevent_add_fd(talloc_parent(context), NULL,
					    fd, TEVENT_FD_READ,
					    cm_fd_h, &context->events[i]);
			cm_log(3, "Will revisit '%s' on traffic from %d.\n",
			       context->entries[i]->cm_id, fd);
			break;
		}
	}
}

int
cm_start_all(struct cm_context *context)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		cm_service_one(context, NULL, i);
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
		cm_iterate_done(context->entries[i],
				context->events[i].iterate_state);
		cm_store_entry_save(context->entries[i]);
	}
	talloc_free(context);
}
