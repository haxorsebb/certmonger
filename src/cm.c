/*
 * Copyright (C) 2009,2010,2011 Red Hat, Inc.
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
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>
#include <tevent.h>

#include <dbus/dbus.h>

#include "cm.h"
#include "log.h"
#include "iterate.h"
#include "netlink.h"
#include "store.h"
#include "store-int.h"
#include "tdbush.h"
#include "tm.h"

struct cm_context {
	int n_entries, should_quit;
	struct cm_store_entry **entries;
	struct cm_event {
		void *iterate_state;
		void *next_event;
	} *events;
	int n_cas;
	struct cm_store_ca **cas;
	int netlink;
	void *netlink_tfd, *netlink_delayed_event;
	int idle_timeout;
	void *idle_event, *conn_ptr;
};

static void *cm_service_one(struct cm_context *context,
			    struct timeval *now, int i);
static void cm_fd_h(struct tevent_context *ec, struct tevent_fd *fde,
		    uint16_t flags, void *pvt);
static void cm_timer_h(struct tevent_context *ec, struct tevent_timer *te,
		       struct timeval current_time, void *pvt);
static void cm_break_h(struct tevent_context *ec, struct tevent_signal *se,
		       int signum, int count, void *siginfo, void *ctx);
static void cm_netlink_fd_h(struct tevent_context *ec, struct tevent_fd *fde,
			    uint16_t flags, void *pvt);
static void cm_timeout_h(struct tevent_context *ec, struct tevent_timer *te,
		         struct timeval current_time, void *pvt);

int
cm_init(struct tevent_context *parent, struct cm_context **context,
	int idle_timeout)
{
	struct cm_context *ctx;
	int i, j;
	*context = NULL;
	ctx = talloc_ptrtype(parent, ctx);
	if (ctx == NULL) {
		return ENOMEM;
	}
	memset(ctx, 0, sizeof(*ctx));
	/* Read the entries from the data store. */
	ctx->entries = cm_store_get_all_entries(ctx);
	for (i = 0; (ctx->entries != NULL) && (ctx->entries[i] != NULL); i++) {
		continue;
	}
	ctx->n_entries = i;
	/* Allocate space for the tevents for each entry. */
	ctx->events = talloc_array_ptrtype(ctx, ctx->events, ctx->n_entries);
	if (ctx->events == NULL) {
		talloc_free(ctx);
		return ENOMEM;
	}
	memset(ctx->events, 0, sizeof(ctx->events[0]) * ctx->n_entries);
	/* Read the list of known CAs. */
	ctx->cas = cm_store_get_all_cas(ctx);
	for (i = 0; (ctx->cas != NULL) && (ctx->cas[i] != NULL); i++) {
		continue;
	}
	ctx->n_cas = i;
	/* Handle things which should get us to quit. */
	tevent_add_signal(parent, ctx, SIGINT, 0, cm_break_h, ctx);
	tevent_add_signal(parent, ctx, SIGTERM, 0, cm_break_h, ctx);
	/* Be ready for an idle timeout. */
	ctx->idle_timeout = idle_timeout;
	ctx->idle_event = NULL;
	/* Initialize state tracking, but don't set things in motion yet. */
	for (i = 0; i < ctx->n_entries; i++) {
		memset(&ctx->events[i], 0, sizeof(ctx->events[i]));
		if (cm_iterate_init(ctx->entries[i],
				    &ctx->events[i].iterate_state) != 0) {
			for (j = 0; j < i; j++) {
				cm_iterate_done(ctx->entries[j],
						ctx->events[j].iterate_state);
				ctx->events[j].iterate_state = NULL;
			}
			talloc_free(ctx);
			return ENOMEM;
		}
	}
	/* Start draining the netlink socket so that it doesn't get backed up
	 * waiting for us to read notifications. */
	ctx->netlink = cm_netlink_socket();
	if (ctx->netlink != -1) {
		ctx->netlink_tfd = tevent_add_fd(parent, ctx, ctx->netlink,
						 TEVENT_FD_READ,
						 cm_netlink_fd_h, ctx);
	}
	/* Start out without a DBus connection. */
	ctx->conn_ptr = NULL;
	*context = ctx;
	return 0;
}

static void
cm_timer_h(struct tevent_context *ec, struct tevent_timer *te,
	   struct timeval current_time, void *pvt)
{
	struct cm_context *context = pvt;
	int i;
	for (i = 0; i < context->n_entries; i++) {
		if (context->events[i].next_event == te) {
			talloc_free(te);
			context->events[i].next_event = cm_service_one(context,
								       NULL, i);
			break;
		}
	}
	if (i >= context->n_entries) {
		cm_log(3, "Bug: unowned timer fired.\n");
	}
}

static void
cm_timeout_h(struct tevent_context *ec, struct tevent_timer *te,
	     struct timeval current_time, void *pvt)
{
	struct cm_context *context = pvt;
	if (context->idle_event != NULL) {
		talloc_free(context->idle_event);
		context->idle_event = NULL;
	}
	if (context->n_entries == 0) {
		cm_log(3, "Hit idle timer (%ds).\n", context->idle_timeout);
		context->should_quit++;
	}
}

void
cm_reset_timeout(struct cm_context *context)
{
	struct timeval now, then;
	if (context->idle_event != NULL) {
		cm_log(3, "Clearing previously-set idle timer.\n");
		talloc_free(context->idle_event);
		context->idle_event = NULL;
	}
	if ((context->idle_timeout > 0) &&
	    (context->n_entries == 0)) {
		now = tevent_timeval_current();
		then = tevent_timeval_add(&now, context->idle_timeout, 0);
		cm_log(3, "Setting idle timer (%ds).\n",
		       context->idle_timeout);
		context->idle_event = tevent_add_timer(talloc_parent(context),
						       context,
						       then,
						       cm_timeout_h,
						       context);
	}
}

static void
cm_fd_h(struct tevent_context *ec,
	struct tevent_fd *fde, uint16_t flags, void *pvt)
{
	struct cm_context *context = pvt;
	int i;
	for (i = 0; i < context->n_entries; i++) {
		if (context->events[i].next_event == fde) {
			talloc_free(fde);
			context->events[i].next_event = cm_service_one(context,
								       NULL, i);
			break;
		}
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

static void
cm_netlink_delayed_h(struct tevent_context *ec, struct tevent_timer *te,
		     struct timeval current_time, void *pvt)
{
	struct cm_context *ctx = pvt;
	int i;
	for (i = 0; i < ctx->n_entries; i++) {
		if (ctx->events[i].next_event != NULL) {
			switch (ctx->entries[i]->cm_state) {
			case CM_CA_UNREACHABLE:
				cm_restart_one(ctx,
					       ctx->entries[i]->cm_nickname);
				break;
			default:
				break;
			}
		}
	}
	if (te == ctx->netlink_delayed_event) {
		talloc_free(ctx->netlink_delayed_event);
		ctx->netlink_delayed_event = NULL;
	}
}

static void
cm_netlink_fd_h(struct tevent_context *ec,
		struct tevent_fd *fde, uint16_t flags, void *pvt)
{
	struct cm_context *ctx = pvt;
	char buf[0x10000];
	int len;
	struct timeval later;
	struct sockaddr_storage nlsrc;
	socklen_t nlsrclen;

	/* Shouldn't happen. */
	if ((ctx == NULL) || (ctx->netlink < 0)) {
		return;
	}

	/* Drain the buffer. */
	cm_log(3, "Got netlink traffic.\n");
	memset(&nlsrc, 0, sizeof(nlsrc));
	nlsrclen = sizeof(nlsrc);
	while ((len = recvfrom(ctx->netlink, buf, sizeof(buf), 0,
			       (struct sockaddr *) &nlsrc, &nlsrclen)) != -1) {
		switch (len) {
		case 0:
			cm_log(3, "Got EOF from netlink socket.\n");
			talloc_free(fde);
			close(ctx->netlink);
			ctx->netlink = -1;
			break;
		default:
			cm_log(3, "Got %d bytes from netlink socket.\n", len);
			break;
		}
		memset(&nlsrc, 0, sizeof(nlsrc));
		nlsrclen = 0;
		if (ctx->netlink == -1) {
			break;
		}
	}
	/* Queue delayed processing. */
	if (cm_netlink_pkt_is_route_change(buf, len,
					   (struct sockaddr *) &nlsrc,
					   nlsrclen) == 0) {
		talloc_free(ctx->netlink_delayed_event);
		later = tevent_timeval_current_ofs(CM_DELAY_NETLINK, 0);
		ctx->netlink_delayed_event = tevent_add_timer(talloc_parent(ctx), ctx,
							      later,
							      cm_netlink_delayed_h,
							      ctx);
	}
	/* Sign off. */
	if (len != 0) {
		cm_log(3, "No more netlink traffic (for now).\n");
	}
}

struct cm_store_ca *
cm_find_ca_by_entry(struct cm_context *c, struct cm_store_entry *entry)
{
	return entry->cm_ca_nickname ? cm_get_ca_by_nickname(c, entry->cm_ca_nickname) : NULL;
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
	fd = -1;
	ret = cm_iterate(context->entries[i],
			 cm_find_ca_by_entry(context, context->entries[i]),
			 context,
			 &cm_get_ca_by_index,
			 &cm_get_n_cas,
			 &cm_tdbush_property_emit_entry_saved_cert,
			 &cm_tdbush_property_emit_entry_changes,
			 context->events[i].iterate_state,
			 &when, &delay, &fd);
	t = NULL;
	if (ret == 0) {
		switch (when) {
		case cm_time_now:
			t = tevent_add_timer(talloc_parent(context), context,
					     now, cm_timer_h, context);
			cm_log(3, "Will revisit %s('%s') now.\n",
			       context->entries[i]->cm_busname,
			       context->entries[i]->cm_nickname);
			break;
		case cm_time_soon:
			then = tevent_timeval_add(&now, CM_DELAY_SOON, 0);
			t = tevent_add_timer(talloc_parent(context), context,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit %s('%s') soon.\n",
			       context->entries[i]->cm_busname,
			       context->entries[i]->cm_nickname);
			break;
		case cm_time_soonish:
			then = tevent_timeval_add(&now, CM_DELAY_SOONISH, 0);
			t = tevent_add_timer(talloc_parent(context), context,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit %s('%s') soonish.\n",
			       context->entries[i]->cm_busname,
			       context->entries[i]->cm_nickname);
			break;
		case cm_time_delay:
			then = tevent_timeval_add(&now, delay, 0);
			t = tevent_add_timer(talloc_parent(context), context,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit %s('%s') in %d seconds.\n",
			       context->entries[i]->cm_busname,
			       context->entries[i]->cm_nickname, delay);
			break;
		case cm_time_no_time:
			if (fd != -1) {
				t = tevent_add_fd(talloc_parent(context),
						  context,
						  fd, TEVENT_FD_READ,
						  cm_fd_h, context);
				cm_log(3, "Will revisit %s('%s') on "
				       "traffic from %d.\n",
				       context->entries[i]->cm_busname,
				       context->entries[i]->cm_nickname, fd);
			} else {
				cm_log(3, "Waiting for instructions for "
				       "%s('%s').\n",
				       context->entries[i]->cm_busname,
				       context->entries[i]->cm_nickname);
				t = NULL;
			}
			break;
		}
	}
	return t;
}

int
cm_keep_going(struct cm_context *context)
{
	return context->should_quit;
}

int
cm_add_entry(struct cm_context *context, struct cm_store_entry *new_entry)
{
	struct cm_store_entry **entries;
	struct cm_event *events;
	int i;
	time_t now;
	char timestamp[15];
	/* Check for duplicates and count the number of entries we're already
	 * managing. */
	if (new_entry->cm_nickname != NULL) {
		for (i = 0; i < context->n_entries; i++) {
			if (strcmp(context->entries[i]->cm_nickname,
				   new_entry->cm_nickname) == 0) {
				return -1;
			}
		}
	} else {
		do {
			/* Try to assign a new ID. */
			now = cm_time(NULL);
			new_entry->cm_nickname = cm_store_timestamp_from_time(now,
									      timestamp);
			/* Check for duplicates. */
			for (i = 0; i < context->n_entries; i++) {
				if (strcmp(context->entries[i]->cm_nickname,
					   new_entry->cm_nickname) == 0) {
					/* Busy wait 0.1s. Ugh. */
					usleep(100000);
					break;
				}
			}
		} while (i < context->n_entries);
		new_entry->cm_nickname = talloc_strdup(new_entry,
						       new_entry->cm_nickname);
	}
	/* Allocate storage for a new entry array. */
	events = NULL;
	entries = talloc_array(context, struct cm_store_entry *,
			       context->n_entries + 1);
	if (entries != NULL) {
		/* Allocate storage for a new entry state array. */
		events = talloc_array(context, struct cm_event,
				      context->n_entries + 1);
		if (events != NULL) {
			/* Copy the entries to the new arrays. */
			for (i = 0; i < context->n_entries; i++) {
				talloc_steal(entries, context->entries[i]);
				entries[i] = context->entries[i];
			}
			/* The pointers in this structure belong to the tevent
			 * context, so we don't need to worry about reparenting
			 * them. */
			memcpy(events, context->events,
			       sizeof(context->events[0]) * context->n_entries);
			/* Add the new members. */
			talloc_steal(entries, new_entry);
			entries[context->n_entries] = new_entry;
			memset(&events[context->n_entries], 0,
			       sizeof(events[context->n_entries]));
			/* Reset the pointers. */
			talloc_free(context->entries);
			context->entries = entries;
			talloc_free(context->events);
			context->events = events;
			/* Reset the recorded count of entries. */
			context->n_entries++;
		} else {
			talloc_free(entries);
			entries = NULL;
		}
	}
	cm_reset_timeout(context);
	if ((entries != NULL) && (events != NULL)) {
		/* Prepare to set this entry in motion. */
		i = context->n_entries - 1;
		if (cm_start_one(context,
				 context->entries[i]->cm_nickname) == FALSE) {
			cm_log(3, "Error starting %s('%s'), please retry.\n",
			       context->entries[i]->cm_busname,
			       context->entries[i]->cm_nickname);
		}
		/* Save this entry to the store, too. */
		cm_store_entry_save(new_entry);
		return 0;
	}
	return -1;
}

static int
cm_find_entry_by_nickname(struct cm_context *context, const char *nickname)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		if (strcmp(context->entries[i]->cm_nickname, nickname) == 0) {
			return i;
		}
	}
	return -1;
}

static int
cm_find_ca_by_nickname(struct cm_context *context, const char *nickname)
{
	int i;
	for (i = 0; i < context->n_cas; i++) {
		if (strcmp(context->cas[i]->cm_nickname, nickname) == 0) {
			return i;
		}
	}
	return -1;
}

int
cm_start_all(struct cm_context *context)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		if ((context->events[i].iterate_state == NULL) &&
		    (cm_iterate_init(context->entries[i],
				     &context->events[i].iterate_state)) != 0) {
			cm_log(1, "Error starting %s('%s'), "
			       "please try again.\n",
			       context->entries[i]->cm_busname,
			       context->entries[i]->cm_nickname);
		} else {
			context->events[i].next_event = cm_service_one(context,
								       NULL, i);
		}
	}
	cm_reset_timeout(context);
	return 0;
}

void
cm_stop_all(struct cm_context *context)
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
	for (i = 0; i < context->n_cas; i++) {
		cm_store_ca_save(context->cas[i]);
	}
}

dbus_bool_t
cm_start_one(struct cm_context *context, const char *nickname)
{
	int i;
	i = cm_find_entry_by_nickname(context, nickname);
	if (i != -1) {
		if (cm_iterate_init(context->entries[i],
				    &context->events[i].iterate_state) == 0) {
			context->events[i].next_event = cm_service_one(context,
								       NULL, i);
			cm_log(3, "Started %s('%s').\n",
			       context->entries[i]->cm_busname, nickname);
			return TRUE;
		} else {
			cm_log(3, "Error starting %s('%s'), please retry.\n",
			       context->entries[i]->cm_busname, nickname);
			return FALSE;
		}
	} else {
		cm_log(3, "No entry matching nickname '%s'.\n", nickname);
		return FALSE;
	}
}

dbus_bool_t
cm_stop_one(struct cm_context *context, const char *nickname)
{
	int i;
	i = cm_find_entry_by_nickname(context, nickname);
	if (i != -1) {
		talloc_free(context->events[i].next_event);
		context->events[i].next_event = NULL;
		cm_iterate_done(context->entries[i],
				context->events[i].iterate_state);
		context->events[i].iterate_state = NULL;
		cm_store_entry_save(context->entries[i]);
		cm_log(3, "Stopped %s('%s').\n",
		       context->entries[i]->cm_busname, nickname);
		return TRUE;
	} else {
		cm_log(3, "No entry matching nickname '%s'.\n", nickname);
		return FALSE;
	}
}

int
cm_remove_entry(struct cm_context *context, const char *nickname)
{
	int i, rv = -1;
	if (cm_stop_one(context, nickname)) {
		i = cm_find_entry_by_nickname(context, nickname);
		if (i != -1) {
			if (cm_store_entry_delete(context->entries[i]) == 0) {
				/* Free the entry. */
				talloc_free(context->entries[i]);
				/* Shorten up the arrays of entries and event
				 * information. */
				memmove(context->entries + i,
					context->entries + i + 1,
					(context->n_entries - i - 1) *
					sizeof(context->entries[i]));
				memmove(context->events + i,
					context->events + i + 1,
					(context->n_entries - i - 1) *
					sizeof(context->events[i]));
				context->n_entries--;
				rv = 0;
			} else {
				rv = -1;
			}
		}
	}
	cm_reset_timeout(context);
	return rv;
}

dbus_bool_t
cm_restart_one(struct cm_context *context, const char *nickname)
{
	return cm_stop_one(context, nickname) &&
	       cm_start_one(context, nickname);
}

struct cm_store_entry *
cm_get_entry_by_busname(struct cm_context *context, const char *name)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		if (strcmp(context->entries[i]->cm_busname, name) == 0) {
			return context->entries[i];
		}
	}
	return NULL;
}

struct cm_store_entry *
cm_get_entry_by_nickname(struct cm_context *context, const char *nickname)
{
	int i;
	for (i = 0; i < context->n_entries; i++) {
		if (strcmp(context->entries[i]->cm_nickname, nickname) == 0) {
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

int
cm_add_ca(struct cm_context *context, struct cm_store_ca *new_ca)
{
	struct cm_store_ca **cas;
	int i;
	time_t now;
	char timestamp[15];
	/* Check for duplicates and count the number of CAs we're already
	 * managing. */
	if (new_ca->cm_nickname != NULL) {
		for (i = 0; i < context->n_cas; i++) {
			if (strcmp(context->cas[i]->cm_nickname,
				   new_ca->cm_nickname) == 0) {
				return -1;
			}
		}
	} else {
		do {
			/* Try to assign a new nickname. */
			now = cm_time(NULL);
			new_ca->cm_nickname = cm_store_timestamp_from_time(now,
									   timestamp);
			/* Check for duplicates. */
			for (i = 0; i < context->n_cas; i++) {
				if (strcmp(context->cas[i]->cm_nickname,
					   new_ca->cm_nickname) == 0) {
					/* Busy wait 0.1s. Ugh. */
					usleep(100000);
					break;
				}
			}
		} while (i < context->n_cas);
		new_ca->cm_nickname = talloc_strdup(new_ca,
						    new_ca->cm_nickname);
	}
	/* Allocate storage for a new CA array. */
	cas = talloc_array(context, struct cm_store_ca *, context->n_cas + 2);
	if (cas != NULL) {
		/* Copy the entries to the new arrays. */
		for (i = 0; i < context->n_cas; i++) {
			talloc_steal(cas, context->cas[i]);
			cas[i] = context->cas[i];
		}
		/* Save this entry to the store. */
		cm_store_ca_save(new_ca);
		talloc_steal(cas, new_ca);
		cas[i++] = new_ca;
		cas[i++] = NULL;
		context->cas = cas;
		/* Reset the recorded count of CAs. */
		context->n_cas++;
		return 0;
	}
	return -1;
}

struct cm_store_ca *
cm_get_ca_by_busname(struct cm_context *context, const char *name)
{
	int i;
	for (i = 0; i < context->n_cas; i++) {
		if (strcmp(context->cas[i]->cm_busname, name) == 0) {
			return context->cas[i];
		}
	}
	return NULL;
}

struct cm_store_ca *
cm_get_ca_by_nickname(struct cm_context *context, const char *nickname)
{
	int i;
	for (i = 0; i < context->n_cas; i++) {
		if (strcmp(context->cas[i]->cm_nickname, nickname) == 0) {
			return context->cas[i];
		}
	}
	return NULL;
}

struct cm_store_ca *
cm_get_ca_by_index(struct cm_context *context, int i)
{
	if (i < context->n_cas) {
		return context->cas[i];
	}
	return NULL;
}

int
cm_get_n_cas(struct cm_context *context)
{
	return context->n_cas;
}

int
cm_remove_ca(struct cm_context *context, const char *nickname)
{
	int i;
	i = cm_find_ca_by_nickname(context, nickname);
	if (i != -1) {
		if (cm_store_ca_delete(context->cas[i]) == 0) {
			/* Free the entry. */
			talloc_free(context->cas[i]);
			/* Shorten up the arrays of entries and event
			 * information. */
			memmove(context->cas + i,
				context->cas + i + 1,
				(context->n_cas - i - 1) *
				sizeof(context->cas[i]));
			context->n_cas--;
			return 0;
		} else {
			return -1;
		}
	}
	return -1;
}

void *
cm_get_conn_ptr(struct cm_context *context)
{
	return context->conn_ptr;
}

void
cm_set_conn_ptr(struct cm_context *context, void *ptr)
{
	context->conn_ptr = ptr;
}
