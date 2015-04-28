/*
 * Copyright (C) 2009,2010,2011,2014 Red Hat, Inc.
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
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <talloc.h>
#include <tevent.h>

#include "cm.h"
#include "log.h"
#include "iterate.h"
#include "netlink.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "tdbus.h"
#include "tdbush.h"
#include "tm.h"

struct cm_context {
	int should_quit;
	int n_entries;
	struct cm_store_entry **entries;
	int n_cas;
	struct cm_store_ca **cas;
	struct cm_event {
		void *iterate_state;
		void *next_event;
	} *entry_events;
	struct cm_ca_event {
		void *iterate_state[cm_ca_phase_invalid];
		void *next_event[cm_ca_phase_invalid];
	} *ca_events;
	int netlink;
	void *netlink_tfd, *netlink_delayed_event;
	int idle_timeout;
	void *idle_event, *conn_ptr;
	char *server_address;
	struct {
		void *tfd;
		char *command;
		int fd;
		struct cm_subproc_state *state;
	} gate;
};

static void *cm_service_entry(struct cm_context *context,
			      struct timeval *now, int i);
static void *cm_service_ca(struct cm_context *context,
			   struct timeval *now, int i,
			   enum cm_ca_phase phase);
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
	int idle_timeout, const char *gate_command)
{
	struct cm_context *ctx;
	int i, j;
	enum cm_ca_phase phase;

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
	ctx->entry_events = talloc_array_ptrtype(ctx, ctx->entry_events,
						 ctx->n_entries);
	if (ctx->entry_events == NULL) {
		talloc_free(ctx);
		return ENOMEM;
	}
	memset(ctx->entry_events, 0,
	       sizeof(ctx->entry_events[0]) * ctx->n_entries);
	/* Read the list of known CAs. */
	ctx->cas = cm_store_get_all_cas(ctx);
	for (i = 0; (ctx->cas != NULL) && (ctx->cas[i] != NULL); i++) {
		continue;
	}
	ctx->n_cas = i;
	/* Allocate space for the tevents for each CA. */
	ctx->ca_events = talloc_array_ptrtype(ctx, ctx->ca_events, ctx->n_cas);
	if (ctx->ca_events == NULL) {
		talloc_free(ctx);
		return ENOMEM;
	}
	memset(ctx->ca_events, 0, sizeof(ctx->ca_events[0]) * ctx->n_cas);
	/* Handle things which should get us to quit. */
	tevent_add_signal(parent, ctx, SIGHUP, 0, cm_break_h, ctx);
	tevent_add_signal(parent, ctx, SIGINT, 0, cm_break_h, ctx);
	tevent_add_signal(parent, ctx, SIGTERM, 0, cm_break_h, ctx);
	/* Be ready for an idle timeout. */
	ctx->idle_timeout = idle_timeout;
	ctx->idle_event = NULL;
	/* Be ready to launch a gating command. */
	if (gate_command != NULL) {
		ctx->gate.command = talloc_strdup(ctx, gate_command);
	}
	/* Initialize state tracking, but don't set things in motion yet. */
	for (i = 0; i < ctx->n_entries; i++) {
		memset(&ctx->entry_events[i], 0, sizeof(ctx->entry_events[i]));
		if (cm_iterate_entry_init(ctx->entries[i],
					  &ctx->entry_events[i].iterate_state) != 0) {
			for (j = 0; j < i; j++) {
				cm_iterate_entry_done(ctx->entries[j],
						      ctx->entry_events[j].iterate_state);
				ctx->entry_events[j].iterate_state = NULL;
			}
			talloc_free(ctx);
			return ENOMEM;
		}
	}
	for (i = 0; i < ctx->n_cas; i++) {
		memset(&ctx->ca_events[i], 0, sizeof(ctx->ca_events[i]));
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			if (cm_iterate_ca_init(ctx->cas[i], phase,
					       &ctx->ca_events[i].iterate_state[phase]) != 0) {
				do {
					phase--;
					cm_iterate_ca_done(ctx->cas[i],
							   ctx->ca_events[i].iterate_state[phase]);
					ctx->ca_events[i].iterate_state[phase] = NULL;
				} while (phase > 0);
				for (j = 0; j < i; j++) {
					phase = cm_ca_phase_invalid;
					do {
						phase--;
						cm_iterate_ca_done(ctx->cas[j],
								   ctx->ca_events[j].iterate_state[phase]);
						ctx->ca_events[j].iterate_state[phase] = NULL;
					} while (phase > 0);
				}
				talloc_free(ctx);
				return ENOMEM;
			}
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
	int i, j;
	enum cm_ca_phase phase;

	for (i = 0; i < context->n_entries; i++) {
		if (context->entry_events[i].next_event == te) {
			talloc_free(te);
			context->entry_events[i].next_event =
				cm_service_entry(context, NULL, i);
			break;
		}
	}
	for (j = 0; j < context->n_cas; j++) {
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			if (context->ca_events[j].next_event[phase] == te) {
				talloc_free(te);
				context->ca_events[j].next_event[phase] =
					cm_service_ca(context, NULL, j, phase);
				break;
			}
		}
		if (phase < cm_ca_phase_invalid) {
			break;
		}
	}
	if ((i >= context->n_entries) && (j >= context->n_cas)) {
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
	} else if (context->idle_timeout > 0) {
		cm_log(1, "There are active certificates and requests, "
		       "ignoring idle timeout.\n");
		context->idle_timeout = 0;
	}
}

static void
cm_fd_h(struct tevent_context *ec,
	struct tevent_fd *fde, uint16_t flags, void *pvt)
{
	struct cm_context *context = pvt;
	int i, j;
	enum cm_ca_phase phase;

	for (i = 0; i < context->n_entries; i++) {
		if (context->entry_events[i].next_event == fde) {
			talloc_free(fde);
			context->entry_events[i].next_event =
				cm_service_entry(context, NULL, i);
			break;
		}
	}
	for (j = 0; j < context->n_cas; j++) {
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			if (context->ca_events[j].next_event[phase] == fde) {
				talloc_free(fde);
				context->ca_events[j].next_event[phase] =
					cm_service_ca(context, NULL, j, phase);
				break;
			}
		}
		if (phase < cm_ca_phase_invalid) {
			break;
		}
	}
	if ((i >= context->n_entries) && (j >= context->n_cas)) {
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
	enum cm_ca_phase phase;

	for (i = 0; i < ctx->n_entries; i++) {
		if (ctx->entry_events[i].next_event != NULL) {
			switch (ctx->entries[i]->cm_state) {
			case CM_CA_UNREACHABLE:
				cm_restart_entry(ctx,
						 ctx->entries[i]->cm_nickname);
				break;
			default:
				break;
			}
		}
	}
	for (i = 0; i < ctx->n_cas; i++) {
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			if (ctx->ca_events[i].iterate_state[phase] != NULL) {
				switch (ctx->cas[i]->cm_ca_state[phase]) {
				case CM_CA_DATA_UNREACHABLE:
					cm_restart_ca(ctx,
						      ctx->cas[i]->cm_nickname,
						      phase);
					break;
				default:
					break;
				}
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
cm_service_entry(struct cm_context *context, struct timeval *current_time, int i)
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
	ret = cm_iterate_entry(context->entries[i],
			       cm_find_ca_by_entry(context, context->entries[i]),
			       context,
			       &cm_get_ca_by_index,
			       &cm_get_n_cas,
			       &cm_get_entry_by_index,
			       &cm_get_n_entries,
			       &cm_tdbush_property_emit_entry_saved_cert,
			       &cm_tdbush_property_emit_entry_changes,
			       context->entry_events[i].iterate_state,
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

static void *
cm_service_ca(struct cm_context *context, struct timeval *current_time, int i,
	      enum cm_ca_phase phase)
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
	ret = cm_iterate_ca(context->cas[i],
			    context,
			    &cm_get_ca_by_index,
			    &cm_get_n_cas,
			    &cm_get_entry_by_index,
			    &cm_get_n_entries,
			    &cm_tdbush_property_emit_ca_changes,
			    context->ca_events[i].iterate_state[phase],
			    &when, &delay, &fd);
	t = NULL;
	if (ret == 0) {
		switch (when) {
		case cm_time_now:
			t = tevent_add_timer(talloc_parent(context), context,
					     now, cm_timer_h, context);
			cm_log(3, "Will revisit %s('%s').%s now.\n",
			       context->cas[i]->cm_busname,
			       context->cas[i]->cm_nickname,
			       cm_store_ca_phase_as_string(phase));
			break;
		case cm_time_soon:
			then = tevent_timeval_add(&now, CM_DELAY_SOON, 0);
			t = tevent_add_timer(talloc_parent(context), context,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit %s('%s').%s soon.\n",
			       context->cas[i]->cm_busname,
			       context->cas[i]->cm_nickname,
			       cm_store_ca_phase_as_string(phase));
			break;
		case cm_time_soonish:
			then = tevent_timeval_add(&now, CM_DELAY_SOONISH, 0);
			t = tevent_add_timer(talloc_parent(context), context,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit %s('%s').%s soonish.\n",
			       context->cas[i]->cm_busname,
			       context->cas[i]->cm_nickname,
			       cm_store_ca_phase_as_string(phase));
			break;
		case cm_time_delay:
			then = tevent_timeval_add(&now, delay, 0);
			t = tevent_add_timer(talloc_parent(context), context,
					     then, cm_timer_h, context);
			cm_log(3, "Will revisit %s('%s').%s in %d seconds.\n",
			       context->cas[i]->cm_busname,
			       context->cas[i]->cm_nickname,
			       cm_store_ca_phase_as_string(phase),
			       delay);
			break;
		case cm_time_no_time:
			if (fd != -1) {
				t = tevent_add_fd(talloc_parent(context),
						  context,
						  fd, TEVENT_FD_READ,
						  cm_fd_h, context);
				cm_log(3, "Will revisit %s('%s').%s on "
				       "traffic from %d.\n",
				       context->cas[i]->cm_busname,
				       context->cas[i]->cm_nickname,
				       cm_store_ca_phase_as_string(phase),
				       fd);
			} else {
				cm_log(3, "Waiting for instructions for "
				       "%s('%s').%s.\n",
				       context->cas[i]->cm_busname,
				       context->cas[i]->cm_nickname,
				       cm_store_ca_phase_as_string(phase));
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
	/* Resize the entry array. */
	events = NULL;
	entries = talloc_realloc(context, context->entries,
				 struct cm_store_entry *,
				 context->n_entries + 1);
	if (entries != NULL) {
		/* Resize the entry state array. */
		events = talloc_realloc(context, context->entry_events,
					struct cm_event,
					context->n_entries + 1);
		if (events != NULL) {
			/* Add the new entry to the array. */
			talloc_steal(entries, new_entry);
			entries[context->n_entries] = new_entry;
			/* Clear the new entry event. */
			memset(&events[context->n_entries], 0,
			       sizeof(events[context->n_entries]));
			/* Update the pointers. */
			context->entries = entries;
			context->entry_events = events;
			/* Update the recorded count of entries. */
			context->n_entries++;
		} else {
			/* At least don't sabotage things. */
			context->entries = entries;
			entries = NULL;
		}
	}
	cm_reset_timeout(context);
	if ((entries != NULL) && (events != NULL)) {
		/* Prepare to set this entry in motion. */
		i = context->n_entries - 1;
		if (cm_start_entry(context,
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

static void
cm_gate_fd_h(struct tevent_context *ec, struct tevent_fd *fde,
	     uint16_t flags, void *pvt)
{
	struct cm_context *ctx = pvt;
	int length, status;
	const char *msg;

	talloc_free(ctx->gate.tfd);
	if (cm_subproc_ready(ctx->gate.state) == 0) {
		msg = cm_subproc_get_msg(ctx->gate.state, &length);
		if (length > 0) {
			cm_log(0, "Failed to start command '%s': %s.\n",
			       ctx->gate.command,
			       strerror((unsigned int) msg[0]));
		} else {
			status = cm_subproc_get_exitstatus(ctx->gate.state);
			if (WIFEXITED(status)) {
				cm_log(1, "Command '%s' exited, status %d.\n",
				       ctx->gate.command, WEXITSTATUS(status));
			} else {
				cm_log(0, "Command '%s' exited abnormally.\n",
				       ctx->gate.command);
			}
		}
		ctx->should_quit++;
		ctx->gate.tfd = NULL;
	} else {
		cm_log(1, "Command '%s' output error data, but is still "
		       "running.\n", ctx->gate.command);
		ctx->gate.tfd = tevent_add_fd(ec, ctx, ctx->gate.fd,
					      TEVENT_FD_READ, cm_gate_fd_h,
					      ctx);
	}
}

static int
cm_gate_run(int fd, struct cm_store_ca *ca, struct cm_store_entry *e,
	    void *data)
{
	struct cm_context *ctx = data;
	char **argv;
	const char *error = NULL;
	unsigned char u;

	cm_subproc_mark_most_cloexec(fd, STDOUT_FILENO, STDERR_FILENO);
	argv = cm_subproc_parse_args(NULL, ctx->gate.command, &error);
	if (argv == NULL) {
		cm_log(1, "Error parsing '%s'.\n", ctx->gate.command);
		return -1;
	}
	cm_log(1, "Running gate command \"%s\" (\"%s\").\n", argv[0],
	       ctx->gate.command);
	if (ctx->server_address != NULL) {
		setenv(CERTMONGER_PVT_ADDRESS_ENV, ctx->server_address, 1);
	}
	signal(SIGHUP, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	execvp(argv[0], argv);
	u = errno;
	if (write(fd, &u, 1) != 1) {
		cm_log(1, "Error sending exec() error to parent.\n");
	}
	return u;
}

int
cm_start_all(struct cm_context *context)
{
	int i;
	enum cm_ca_phase phase;

	if (context->gate.command != NULL) {
		context->gate.state = cm_subproc_start(cm_gate_run, context,
						       NULL, NULL, context);
		if (context->gate.state == NULL) {
			cm_log(1, "Error starting '%s', please try again.\n",
			       context->gate.command);
			return -1;
		}
		i = cm_subproc_get_fd(context->gate.state);
		if (i == -1) {
			cm_log(1, "Error starting '%s', please try again.\n",
			       context->gate.command);
			return -1;
		}
		context->gate.fd = i;
		context->gate.tfd = tevent_add_fd(talloc_parent(context),
						  context, i, TEVENT_FD_READ,
						  cm_gate_fd_h, context);
		cm_log(3, "Command '%s' on FD %d.\n", context->gate.command, i);
	}
	for (i = 0; i < context->n_entries; i++) {
		if ((context->entry_events[i].iterate_state == NULL) &&
		    (cm_iterate_entry_init(context->entries[i],
					   &context->entry_events[i].iterate_state)) != 0) {
			cm_log(1, "Error starting %s('%s'), "
			       "please try again.\n",
			       context->entries[i]->cm_busname,
			       context->entries[i]->cm_nickname);
		} else {
			context->entry_events[i].next_event =
				cm_service_entry(context, NULL, i);
		}
	}
	for (i = 0; i < context->n_cas; i++) {
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			if ((context->ca_events[i].iterate_state[phase] == NULL) &&
			    (cm_iterate_ca_init(context->cas[i], phase,
						&context->ca_events[i].iterate_state[phase])) != 0) {
				cm_log(1, "Error starting %s('%s')-%s, "
				       "please try again.\n",
				       context->cas[i]->cm_busname,
				       context->cas[i]->cm_nickname,
				       cm_store_ca_phase_as_string(phase));
			} else {
				context->ca_events[i].next_event[phase] =
					cm_service_ca(context, NULL, i, phase);
			}
		}
	}
	cm_reset_timeout(context);
	return 0;
}

void
cm_stop_all(struct cm_context *context)
{
	int i;
	enum cm_ca_phase phase;

	for (i = 0; i < context->n_entries; i++) {
		talloc_free(context->entry_events[i].next_event);
		context->entry_events[i].next_event = NULL;
		cm_iterate_entry_done(context->entries[i],
				      context->entry_events[i].iterate_state);
		context->entry_events[i].iterate_state = NULL;
		cm_store_entry_save(context->entries[i]);
	}
	for (i = 0; i < context->n_cas; i++) {
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			talloc_free(context->ca_events[i].next_event[phase]);
			context->ca_events[i].next_event[phase] = NULL;
			cm_iterate_ca_done(context->cas[i],
					   context->ca_events[i].iterate_state[phase]);
			context->ca_events[i].iterate_state[phase] = NULL;
		}
		cm_store_ca_save(context->cas[i]);
	}
	if (context->gate.state != NULL) {
		cm_subproc_done(context->gate.state);
	}
}

dbus_bool_t
cm_start_entry(struct cm_context *context, const char *nickname)
{
	int i;

	i = cm_find_entry_by_nickname(context, nickname);
	if (i != -1) {
		if (cm_iterate_entry_init(context->entries[i],
					  &context->entry_events[i].iterate_state) == 0) {
			context->entry_events[i].next_event =
				cm_service_entry(context, NULL, i);
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
cm_stop_entry(struct cm_context *context, const char *nickname)
{
	int i;

	i = cm_find_entry_by_nickname(context, nickname);
	if (i != -1) {
		talloc_free(context->entry_events[i].next_event);
		context->entry_events[i].next_event = NULL;
		cm_iterate_entry_done(context->entries[i],
				      context->entry_events[i].iterate_state);
		context->entry_events[i].iterate_state = NULL;
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
	if (cm_stop_entry(context, nickname)) {
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
				memmove(context->entry_events + i,
					context->entry_events + i + 1,
					(context->n_entries - i - 1) *
					sizeof(context->entry_events[i]));
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
cm_restart_entry(struct cm_context *context, const char *nickname)
{
	return cm_stop_entry(context, nickname) &&
	       cm_start_entry(context, nickname);
}

dbus_bool_t
cm_restart_entries_by_ca(struct cm_context *context, const char *nickname)
{
	struct cm_store_entry *entry;
	dbus_bool_t status = FALSE, this;
	int i, n = 0;

	for (i = 0; i < context->n_entries; i++) {
		entry = context->entries[i];
		if ((entry->cm_ca_nickname != NULL) &&
		    (strcmp(entry->cm_ca_nickname, nickname) == 0)) {
			this = cm_restart_entry(context, entry->cm_nickname);
			status = n++ ? this && status : this;
		}
	}
	return status;
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
	struct cm_ca_event *events;
	int i;
	time_t now;
	char timestamp[15];
	enum cm_ca_phase phase;

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
	cas = talloc_realloc(context, context->cas, struct cm_store_ca *,
			     context->n_cas + 1);
	events = talloc_realloc(context, context->ca_events,
				struct cm_ca_event, context->n_cas + 1);
	if ((cas != NULL) && (events != NULL)) {
		/* Save this entry to the store. */
		cm_store_ca_save(new_ca);
		cas[context->n_cas] = new_ca;
		talloc_steal(cas, new_ca);
		context->cas = cas;
		memset(&events[context->n_cas], 0,
		       sizeof(events[context->n_cas]));
		context->ca_events = events;
		/* Update the recorded count of CAs. */
		context->n_cas++;
		/* Start the CA's data fetchers. */
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			cm_start_ca(context, new_ca->cm_nickname, phase);
		}
		return 0;
	}
	if (cas != NULL) {
		context->cas = cas;
	}
	if (events != NULL) {
		context->ca_events = events;
	}
	return -1;
}

dbus_bool_t
cm_start_ca(struct cm_context *context, const char *nickname,
	    enum cm_ca_phase phase)
{
	int i;

	i = cm_find_ca_by_nickname(context, nickname);
	if (i != -1) {
		if (cm_iterate_ca_init(context->cas[i], phase,
				       &context->ca_events[i].iterate_state[phase]) == 0) {
			context->ca_events[i].next_event[phase] =
				cm_service_ca(context, NULL, i, phase);
			cm_log(3, "Started CA %s('%s')-%s.\n",
			       context->cas[i]->cm_busname, nickname,
			       cm_store_ca_phase_as_string(phase));
			return TRUE;
		} else {
			cm_log(3, "Error starting CA %s('%s')-%s, please retry.\n",
			       context->cas[i]->cm_busname, nickname,
			       cm_store_ca_phase_as_string(phase));
			return FALSE;
		}
	} else {
		cm_log(3, "No CA matching nickname '%s'.\n", nickname);
		return FALSE;
	}
}

dbus_bool_t
cm_stop_ca(struct cm_context *context, const char *nickname,
	   enum cm_ca_phase phase)
{
	int i;

	i = cm_find_ca_by_nickname(context, nickname);
	if (i != -1) {
		talloc_free(context->ca_events[i].next_event[phase]);
		context->ca_events[i].next_event[phase] = NULL;
		cm_iterate_ca_done(context->cas[i],
				   context->ca_events[i].iterate_state[phase]);
		context->ca_events[i].iterate_state[phase] = NULL;
		cm_store_ca_save(context->cas[i]);
		cm_log(3, "Stopped CA %s('%s')-%s.\n",
		       context->cas[i]->cm_busname, nickname,
		       cm_store_ca_phase_as_string(phase));
		return TRUE;
	} else {
		cm_log(3, "No CA matching nickname '%s'.\n", nickname);
		return FALSE;
	}
}

dbus_bool_t
cm_restart_ca(struct cm_context *context, const char *nickname,
	      enum cm_ca_phase phase)
{
	return cm_stop_ca(context, nickname, phase) &&
	       cm_start_ca(context, nickname, phase);
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
	enum cm_ca_phase phase;
	i = cm_find_ca_by_nickname(context, nickname);
	if (i != -1) {
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			if (!cm_stop_ca(context, nickname, phase)) {
				break;
			}
		}
		if (phase != cm_ca_phase_invalid) {
			cm_log(3, "Error stopping CA '%s'-%s, please retry.\n",
			       nickname, cm_store_ca_phase_as_string(phase));
			return -1;
		}
		if (cm_store_ca_delete(context->cas[i]) == 0) {
			/* Free the entry. */
			talloc_free(context->cas[i]);
			/* Shorten up the arrays of CAs and event
			 * information. */
			memmove(context->cas + i,
				context->cas + i + 1,
				(context->n_cas - i - 1) *
				sizeof(context->cas[i]));
			memmove(context->ca_events + i,
				context->ca_events + i + 1,
				(context->n_cas - i - 1) *
				sizeof(context->ca_events[i]));
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

const char *
cm_get_server_address(struct cm_context *context)
{
	return context->server_address;
}

void
cm_set_server_address(struct cm_context *context, const char *address)
{
	context->server_address = talloc_strdup(context, address);
}
