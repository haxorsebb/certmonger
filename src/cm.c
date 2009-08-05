#include "config.h"

#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cm.h"
#include "iterate.h"
#include "store.h"

#define DELAY_SOON	1
#define DELAY_SOONISH	5

struct cm_context {
	int n_entries;
	struct cm_store_entry **entries;
	void **iterators;
};

int
cm_init(struct cm_context **context)
{
	struct cm_context *ctx;
	int i, j;
	*context = NULL;
	ctx = malloc(sizeof(**context));
	if (ctx == NULL) {
		return ENOMEM;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->entries = cm_store_get_all_entries();
	for (i = 0; (ctx->entries != NULL) && (ctx->entries[i] != NULL); i++) {
		continue;
	}
	ctx->n_entries = i;
	ctx->iterators = malloc(sizeof(ctx->iterators[0]) * i);
	if (ctx->iterators == NULL) {
		cm_store_entry_freev(ctx->entries);
		free(ctx);
		return ENOMEM;
	}
	for (i = 0; i < ctx->n_entries; i++) {
		if (cm_iterate_init(ctx->entries[i],
				    &(ctx->iterators[i])) != 0) {
			for (j = 0; j < i; j++) {
				cm_iterate_done(ctx->entries[j],
						ctx->iterators[j]);
			}
			free(ctx->iterators);
			cm_store_entry_freev(ctx->entries);
			free(ctx);
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
		free(*fds);
		*fds = NULL;
	}
	*fds = malloc(sizeof(**fds) * context->n_entries);
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
cm_done(struct cm_context *context)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		cm_iterate_done(context->entries[i], context->iterators[i]);
		cm_store_entry_save(context->entries[i]);
	}
	free(context->iterators);
	cm_store_entry_freev(context->entries);
	free(context);
}
