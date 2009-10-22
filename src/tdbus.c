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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>
#include <tevent.h>

#include <dbus/dbus.h>

#include "log.h"
#include "tdbus.h"
#include "tdbush.h"
#include "tdbusm.h"

struct tdbus_connection {
	DBusConnection *conn;
	struct tdbus_watch {
		struct tdbus_connection *conn;
		struct tdbus_watch *next;
		DBusWatch *watch;
		struct tevent_fd *tfd;
		int tfdflags;
		dbus_bool_t active;
	} *watches;
	struct tdbus_timer {
		struct tdbus_connection *conn;
		struct tdbus_timer *next;
		DBusTimeout *timeout;
		struct tevent_timer *tt;
		int d_interval;
		dbus_bool_t active;
	} *timers;
	void *data;
};

static void
cm_tdbus_dispatch_status(DBusConnection *conn, DBusDispatchStatus new_status,
			 void *data)
{
	while (new_status == DBUS_DISPATCH_DATA_REMAINS) {
		new_status = dbus_connection_dispatch(conn);
	}
}

static int
cm_tdbus_tfd_flags_for_watch_flags(unsigned int watch_flags)
{
	int tfd_flags;
	tfd_flags = 0;
	if (watch_flags & DBUS_WATCH_READABLE) {
		tfd_flags |= TEVENT_FD_READ;
	}
	if (watch_flags & DBUS_WATCH_WRITABLE) {
		tfd_flags |= TEVENT_FD_WRITE;
	}
	if (watch_flags & DBUS_WATCH_ERROR) {
		tfd_flags |= TEVENT_FD_READ;
		tfd_flags |= TEVENT_FD_WRITE;
	}
	if (watch_flags & DBUS_WATCH_HANGUP) {
		tfd_flags |= TEVENT_FD_READ;
	}
	return tfd_flags;
}

static int
cm_tdbus_watch_flags_for_tfd_flags(unsigned int tfd_flags)
{
	int watch_flags;
	watch_flags = 0;
	if (tfd_flags & TEVENT_FD_READ) {
		watch_flags |= DBUS_WATCH_READABLE;
	}
	if (tfd_flags & TEVENT_FD_WRITE) {
		watch_flags |= DBUS_WATCH_WRITABLE;
	}
	return watch_flags;
}

static void
cm_tdbus_handle_fd(struct tevent_context *ec, struct tevent_fd *tfd,
		   uint16_t tflags, void *pvt)
{
	struct tdbus_watch *watch;
	int fd, flags;
	watch = pvt;
	talloc_free(watch->tfd);
	watch->tfd = NULL;
	if (watch->active) {
		cm_log(3, "Handling D-Bus traffic on %d.\n",
		       dbus_watch_get_unix_fd(watch->watch));
		flags = cm_tdbus_watch_flags_for_tfd_flags(tflags);
		if (dbus_watch_handle(watch->watch, flags)) {
			fd = dbus_watch_get_unix_fd(watch->watch);
			watch->tfd = tevent_add_fd(ec, watch, fd,
						   watch->tfdflags,
						   cm_tdbus_handle_fd, watch);
		}
	}
}

static void
cm_tdbus_handle_timer(struct tevent_context *ec, struct tevent_timer *timer,
		      struct timeval current_time, void *pvt)
{
	struct tdbus_timer *tdb_timer;
	struct timeval next_time;
	tdb_timer = pvt;
	talloc_free(tdb_timer->tt);
	tdb_timer->tt = NULL;
	if (tdb_timer->active) {
		cm_log(3, "Handling D-Bus timeout.\n");
		if (dbus_timeout_handle(tdb_timer->timeout)) {
			next_time = tevent_timeval_current_ofs(tdb_timer->d_interval, 0);
			tdb_timer->tt = tevent_add_timer(ec, tdb_timer,
							 next_time,
							 cm_tdbus_handle_timer,
							 tdb_timer);
		}
	}
}

static dbus_bool_t
cm_tdbus_watch_add(DBusWatch *watch, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_watch *tdb_watch;
	unsigned int flags;
	int fd;
	conn = data;
	tdb_watch = talloc_ptrtype(conn, tdb_watch);
	if (tdb_watch != NULL) {
		memset(tdb_watch, 0, sizeof(*tdb_watch));
		tdb_watch->watch = watch;
		flags = dbus_watch_get_flags(watch);
		tdb_watch->conn = conn;
		tdb_watch->tfdflags = cm_tdbus_tfd_flags_for_watch_flags(flags);
		tdb_watch->active = dbus_watch_get_enabled(watch);
		if (tdb_watch->active) {
			fd = dbus_watch_get_unix_fd(watch);
			tdb_watch->tfd = tevent_add_fd(talloc_parent(conn),
						       tdb_watch,
						       fd,
						       tdb_watch->tfdflags,
						       cm_tdbus_handle_fd,
						       tdb_watch);
			if (tdb_watch->tfd != NULL) {
				tdb_watch->next = conn->watches;
				conn->watches = tdb_watch;
				return TRUE;
			}
		} else {
			tdb_watch->next = conn->watches;
			conn->watches = tdb_watch;
			return TRUE;
		}
	}
	return FALSE;
}

static void
cm_tdbus_watch_remove(DBusWatch *watch, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_watch *tdb_watch, *prev;
	conn = data;
	for (prev = NULL, tdb_watch = conn->watches;
	     tdb_watch != NULL;
	     tdb_watch = tdb_watch->next) {
		if (tdb_watch->watch == watch) {
			if (prev != NULL) {
				prev->next = tdb_watch->next;
				tdb_watch->next = NULL;
				talloc_free(tdb_watch);
			} else {
				conn->watches = tdb_watch->next;
				tdb_watch->next = NULL;
				talloc_free(tdb_watch);
			}
			break;
		}
		prev = tdb_watch;
	}
}

static void
cm_tdbus_watch_toggle(DBusWatch *watch, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_watch *tdb_watch, *prev;
	unsigned int flags;
	int fd, tfd_flags;
	void *parent;
	conn = data;
	for (prev = NULL, tdb_watch = conn->watches;
	     tdb_watch != NULL;
	     tdb_watch = tdb_watch->next) {
		if (tdb_watch->watch == watch) {
			flags = dbus_watch_get_flags(watch);
			tfd_flags = cm_tdbus_tfd_flags_for_watch_flags(flags);
			tdb_watch->active = dbus_watch_get_enabled(watch);
			talloc_free(tdb_watch->tfd);
			if (tdb_watch->active) {
				fd = dbus_watch_get_unix_fd(watch),
				parent = talloc_parent(conn);
				tdb_watch->tfd = tevent_add_fd(parent,
							       tdb_watch,
							       fd,
							       tfd_flags,
							       cm_tdbus_handle_fd,
							       tdb_watch);
			} else {
				tdb_watch->tfd = NULL;
			}
			break;
		}
		prev = tdb_watch;
	}
}

static void
cm_tdbus_watch_cleanup(void *data)
{
	struct tdbus_connection *conn;
	conn = data;
	while (conn->watches != NULL) {
		cm_tdbus_watch_remove(conn->watches->watch, data);
	}
}

static dbus_bool_t
cm_tdbus_timeout_add(DBusTimeout *timeout, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_timer *tdb_timer;
	struct timeval next_time;
	conn = data;
	tdb_timer = talloc_ptrtype(conn, tdb_timer);
	if (tdb_timer != NULL) {
		memset(tdb_timer, 0, sizeof(*tdb_timer));
		tdb_timer->conn = conn;
		tdb_timer->timeout = timeout;
		tdb_timer->d_interval = dbus_timeout_get_interval(timeout);
		tdb_timer->active = dbus_timeout_get_enabled(timeout);
		if (tdb_timer->active) {
			next_time = tevent_timeval_current_ofs(tdb_timer->d_interval, 0);
			tdb_timer->tt = tevent_add_timer(talloc_parent(conn),
						         tdb_timer,
							 next_time,
						         cm_tdbus_handle_timer,
						         tdb_timer);
			if (tdb_timer->tt != NULL) {
				tdb_timer->next = conn->timers;
				conn->timers = tdb_timer;
				return TRUE;
			}
		} else {
			tdb_timer->next = conn->timers;
			conn->timers = tdb_timer;
			return TRUE;
		}
	}
	return FALSE;
}

static void
cm_tdbus_timeout_remove(DBusTimeout *timeout, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_timer *tdb_timer, *prev;
	conn = data;
	for (prev = NULL, tdb_timer = conn->timers;
	     tdb_timer != NULL;
	     tdb_timer = tdb_timer->next) {
		if (tdb_timer->timeout == timeout) {
			if (prev != NULL) {
				prev->next = tdb_timer->next;
				tdb_timer->next = NULL;
				talloc_free(tdb_timer);
			} else {
				conn->timers = tdb_timer->next;
				tdb_timer->next = NULL;
				talloc_free(tdb_timer);
			}
			break;
		}
		prev = tdb_timer;
	}
}

static void
cm_tdbus_timeout_toggle(DBusTimeout *timeout, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_timer *tdb_timer, *prev;
	struct timeval next_time;
	void *parent;
	conn = data;
	for (prev = NULL, tdb_timer = conn->timers;
	     tdb_timer != NULL;
	     tdb_timer = tdb_timer->next) {
		if (tdb_timer->timeout == timeout) {
			tdb_timer->d_interval = dbus_timeout_get_interval(timeout);
			tdb_timer->active = dbus_timeout_get_enabled(timeout);
			talloc_free(tdb_timer->tt);
			if (tdb_timer->active) {
				next_time = tevent_timeval_current_ofs(tdb_timer->d_interval, 0);
				parent = talloc_parent(conn);
				tdb_timer->tt = tevent_add_timer(parent,
								 tdb_timer,
								 next_time,
								 cm_tdbus_handle_timer,
								 tdb_timer);
			} else {
				tdb_timer->tt = NULL;
			}
			break;
		}
		prev = tdb_timer;
	}
}

static void
cm_tdbus_timeout_cleanup(void *data)
{
	struct tdbus_connection *conn;
	conn = data;
	while (conn->timers != NULL) {
		cm_tdbus_timeout_remove(conn->timers->timeout, data);
	}
}

static DBusHandlerResult
cm_tdbus_filter(DBusConnection *conn, DBusMessage *dmessage, void *data)
{
	struct tdbus_connection *tdb = data;
	const char *destination, *path, *interface, *member;
	/* Catch weird-looking messages. */
	destination = dbus_message_get_destination(dmessage);
	path = dbus_message_get_path(dmessage);
	interface = dbus_message_get_interface(dmessage);
	member = dbus_message_get_member(dmessage);
	if ((destination == NULL) || (path == NULL) || (member == NULL)) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	/* Make sure it's a message we care about. */
	cm_log(3, "message %p(%s)->%s:%s:%s.%s\n", tdb,
	       dbus_message_type_to_string(dbus_message_get_type(dmessage)),
	       destination, path, interface ? interface : "", member);
	switch (dbus_message_get_type(dmessage)) {
	case DBUS_MESSAGE_TYPE_METHOD_CALL:
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
		/* Check that the call or return is directed to us. */
		if (strcmp(destination, CM_DBUS_NAME) != 0) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		break;
	default:
		break;
	}
	/* Okay, the message is one we need to worry about. */
	return cm_tdbush_handle(conn, dmessage, tdb->data);
}

int
cm_tdbus_setup(struct tevent_context *ec, enum cm_tdbus_type bus_type,
	       void *data)
{
	DBusConnection *conn;
	DBusError err;
	const char *bus_desc;
	struct tdbus_connection *tdb;
	/* Build our own context. */
	tdb = talloc_ptrtype(ec, tdb);
	if (tdb == NULL) {
		return ENOMEM;
	}
	memset(tdb, 0, sizeof(*tdb));
	/* Connect to the right bus. */
	bus_desc = NULL;
	switch (bus_type) {
	case cm_tdbus_system:
		conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		bus_desc = "system";
		break;
	case cm_tdbus_session:
		conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
		bus_desc = "session";
		break;
	}
	if (conn == NULL) {
		talloc_free(tdb);
		return -1;
	}
	tdb->conn = conn;
	tdb->data = data;
	/* Set the callback to be called when I/O processing has yielded a
	 * request that we need to act on. */
	dbus_connection_set_dispatch_status_function(conn,
						     cm_tdbus_dispatch_status,
						     tdb, NULL);
	/* Hook up the I/O callbacks so that D-Bus can actually do its thing. */
	if (!dbus_connection_set_watch_functions(conn,
						 &cm_tdbus_watch_add,
						 &cm_tdbus_watch_remove,
						 &cm_tdbus_watch_toggle,
						 tdb,
						 &cm_tdbus_watch_cleanup)) {
		cm_log(1, "Unable to add timer callbacks.\n");
		return -1;
	}
	/* Hook up the (unused?) timer callbacks to be polite. */
	if (!dbus_connection_set_timeout_functions(conn,
						   cm_tdbus_timeout_add,
						   cm_tdbus_timeout_remove,
						   cm_tdbus_timeout_toggle,
						   tdb,
						   cm_tdbus_timeout_cleanup)) {
		cm_log(1, "Unable to add timer callbacks.\n");
		return -1;
	}
	/* Set the filter on messages. */
	if (!dbus_connection_add_filter(conn, cm_tdbus_filter, tdb, NULL)) {
		cm_log(1, "Unable to add filter.\n");
		return -1;
	}
	/* Bind to the well-known name we intend to use. */
	memset(&err, 0, sizeof(err));
	if (!dbus_bus_request_name(conn, CM_DBUS_NAME, 0, &err) ||
	    dbus_error_is_set(&err)) {
		cm_log(1, "Unable to set well-known bus name \"%s\": %s.\n",
		       CM_DBUS_NAME, err.message ? err.message : err.name);
		return -1;
	}
	/* Handle any messages that are already pending. */
	cm_tdbus_dispatch_status(conn,
				 dbus_connection_get_dispatch_status(conn), 
				 tdb);
	cm_log(3, "Connected to %s message bus with name \"%s\", "
	       "unique name \"%s\".\n",
	       bus_desc, dbus_bus_get_unique_name(conn) ?: "(unknown)",
	       CM_DBUS_NAME);
	return 0;
}
