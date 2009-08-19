#include "config.h"

#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <talloc.h>

#include "cm.h"
#include "iterate.h"
#include "store.h"

#define DELAY_SOON	1000
#define DELAY_SOONISH	5000

struct cm_context {
	int n_entries;
	struct cm_store_entry **entries;
	void **iterators;
};

int
cm_init(void *parent, struct cm_context **context)
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
	ctx->iterators = talloc_array_ptrtype(ctx, ctx->iterators, i);
	if (ctx->iterators == NULL) {
		talloc_free(ctx);
		return ENOMEM;
	}
	for (i = 0; i < ctx->n_entries; i++) {
		if (cm_iterate_init(ctx->entries[i],
				    &(ctx->iterators[i])) != 0) {
			for (j = 0; j < i; j++) {
				cm_iterate_done(ctx->entries[j],
						ctx->iterators[j]);
			}
			talloc_free(ctx);
			return ENOMEM;
		}
	}
	*context = ctx;
	return 0;
}

int
cm_next(struct cm_context *context, int **fds, int *nfds, int *timeout)
{
	int i, delay, ret;
	enum cm_time when;
	if (*fds != NULL) {
		talloc_free(*fds);
		*fds = NULL;
	}
	*fds = talloc_array_ptrtype(context, *fds, context->n_entries);
	*nfds = 0;
	*timeout = -1;
	for (i = 0; i < context->n_entries; i++) {
		ret = cm_iterate(context->entries[i], context->iterators[i],
			         &when, &delay, &((*fds)[*nfds]));
		if (ret == 0) {
			switch (when) {
			case cm_time_now:
				*timeout = 0;
				break;
			case cm_time_soon:
				delay = DELAY_SOON;
				if ((*timeout == -1) || (*timeout > delay)) {
					*timeout = delay;
				}
				break;
			case cm_time_soonish:
				delay = DELAY_SOONISH;
				if ((*timeout == -1) || (*timeout > delay)) {
					*timeout = delay;
				}
				break;
			case cm_time_delay:
				if ((*timeout == -1) || (*timeout > delay)) {
					*timeout = delay;
				}
				break;
			case cm_time_no_time:
				(*nfds)++;
				break;
			}
		}
	}
	return 0;
}

void
cm_done(struct cm_context *context, int **fds)
{
	int i;
	if (*fds != NULL) {
		talloc_free(*fds);
		*fds = NULL;
	}
	for (i = 0; i < context->n_entries; i++) {
		cm_iterate_done(context->entries[i], context->iterators[i]);
		context->iterators[i] = NULL;
		cm_store_entry_save(context->entries[i]);
	}
	talloc_free(context);
}
