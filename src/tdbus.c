/*
 * Copyright (C) 2009,2011 Red Hat, Inc.
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

#include "cm.h"
#include "log.h"
#include "tdbus.h"
#include "tdbush.h"
#include "tdbusm.h"

struct tdbus_connection {
	DBusConnection *conn;
	enum cm_tdbus_type conn_type;
	struct tdbus_watch {
		struct tdbus_watch *next;
		struct tdbus_connection *conn;
		int fd;
		struct tevent_fd *tfd;
		struct tdbus_dwatch {
			struct tdbus_dwatch *next;
			DBusWatch *watch;
			int dflags;
			dbus_bool_t active;
		} *dwatches;
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

static int cm_tdbus_setup_connection(struct tdbus_connection *tdb, DBusError *);

static void
cm_tdbus_dispatch_status(DBusConnection *conn, DBusDispatchStatus new_status,
			 void *data)
{
	while (new_status == DBUS_DISPATCH_DATA_REMAINS) {
		new_status = dbus_connection_dispatch(conn);
	}
}

static int
cm_tdbus_watch_get_fd(DBusWatch *watch)
{
#if defined(HAVE_DBUS_WATCH_GET_UNIX_FD)
	return dbus_watch_get_unix_fd(watch);
#elif defined(HAVE_DBUS_WATCH_GET_FD)
	return dbus_watch_get_fd(watch);
#else
#error "Don't know how to retrieve a watchable descriptor from a DBus watch!"
	return -1;
#endif
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
		watch_flags |= DBUS_WATCH_HANGUP;
	}
	if (tfd_flags & TEVENT_FD_WRITE) {
		watch_flags |= DBUS_WATCH_WRITABLE;
	}
	return watch_flags;
}

static void
cm_tdbus_queue_fd(struct tevent_context *ec, struct tdbus_watch *watch,
		  tevent_fd_handler_t handler)
{
	struct tdbus_dwatch *dwatch;
	int newtflags, dflags;
	newtflags = 0;
	dwatch = watch->dwatches;
	while (dwatch != NULL) {
		if (dwatch->active) {
			dwatch->dflags = dbus_watch_get_flags(dwatch->watch);
			dflags = dwatch->dflags;
			newtflags |= cm_tdbus_tfd_flags_for_watch_flags(dflags);
		}
		dwatch = dwatch->next;
	}
	if (newtflags != 0) {
		cm_log(5, "Queuing FD %d for 0x%02x.\n", watch->fd, newtflags);
		watch->tfd = tevent_add_fd(ec, watch, watch->fd, newtflags,
					   handler, watch);
	} else {
		watch->tfd = NULL;
	}
}

static void
cm_tdbus_handle_fd(struct tevent_context *ec, struct tevent_fd *tfd,
		   uint16_t tflags, void *pvt)
{
	struct tdbus_watch *watch;
	struct tdbus_dwatch *dwatch;
	int dflags;
	watch = pvt;
	talloc_free(watch->tfd);
	watch->tfd = NULL;
	dwatch = watch->dwatches;
	dflags = cm_tdbus_watch_flags_for_tfd_flags(tflags);
	while (dwatch != NULL) {
		if (dwatch->active) {
			cm_log(5, "Handling D-Bus traffic on %d.\n", watch->fd);
			if ((dflags & dwatch->dflags) != 0) {
				dbus_watch_handle(dwatch->watch,
						  dflags & dwatch->dflags);
			}
		}
		dwatch = dwatch->next;
	}
	cm_tdbus_queue_fd(ec, watch, cm_tdbus_handle_fd);
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
		cm_log(5, "Handling D-Bus timeout.\n");
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
	struct tdbus_dwatch *tdb_dwatch;
	int fd;
	conn = data;
	fd = cm_tdbus_watch_get_fd(watch);
	cm_log(5, "Adding DBus watch on %d.\n", fd);
	/* Find the tevent watch for this fd. */
	tdb_watch = conn->watches;
	while (tdb_watch != NULL) {
		if (tdb_watch->fd == fd) {
			break;
		}
		tdb_watch = tdb_watch->next;
	}
	/* If we couldn't find one, add it. */
	if (tdb_watch == NULL) {
		cm_log(5, "Adding a new tevent FD for %d.\n", fd);
		tdb_watch = talloc_ptrtype(conn, tdb_watch);
		if (tdb_watch == NULL) {
			return FALSE;
		}
		memset(tdb_watch, 0, sizeof(*tdb_watch));
		tdb_watch->conn = conn;
		tdb_watch->fd = fd;
		tdb_watch->tfd = NULL;
		tdb_watch->dwatches = NULL;
		tdb_watch->next = conn->watches;
		conn->watches = tdb_watch;
	}
	/* Add a new dwatch to the watch. */
	tdb_dwatch = talloc_ptrtype(tdb_watch, tdb_dwatch);
	if (tdb_dwatch == NULL) {
		return FALSE;
	}
	memset(tdb_dwatch, 0, sizeof(*tdb_dwatch));
	tdb_dwatch->watch = watch;
	tdb_dwatch->dflags = dbus_watch_get_flags(watch);
	tdb_dwatch->active = dbus_watch_get_enabled(watch);
	tdb_dwatch->next = tdb_watch->dwatches;
	tdb_watch->dwatches = tdb_dwatch;
	/* (Re-)queue the tfd. */
	talloc_free(tdb_watch->tfd);
	cm_tdbus_queue_fd(talloc_parent(conn), tdb_watch, cm_tdbus_handle_fd);
	return TRUE;
}

static void
cm_tdbus_watch_remove(DBusWatch *watch, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_watch *tdb_watch;
	struct tdbus_dwatch *tdb_dwatch, *prev;
	int fd;
	conn = data;
	fd = cm_tdbus_watch_get_fd(watch);
	cm_log(5, "Removing a DBus watch for %d.\n", fd);
	/* Find the tevent watch for this fd. */
	tdb_watch = conn->watches;
	while (tdb_watch != NULL) {
		if (tdb_watch->fd == fd) {
			break;
		}
		tdb_watch = tdb_watch->next;
	}
	if (tdb_watch == NULL) {
		return;
	}
	/* Find the watch in the list of dwatches. */
	for (prev = NULL, tdb_dwatch = tdb_watch->dwatches;
	     tdb_dwatch != NULL;
	     tdb_dwatch = tdb_dwatch->next) {
		if (tdb_dwatch->watch == watch) {
			if (prev != NULL) {
				prev->next = tdb_dwatch->next;
				tdb_dwatch->next = NULL;
				talloc_free(tdb_dwatch);
			} else {
				tdb_watch->dwatches = tdb_dwatch->next;
				tdb_dwatch->next = NULL;
				talloc_free(tdb_dwatch);
			}
			break;
		}
		prev = tdb_dwatch;
	}
	/* (Re-)queue the tfd. */
	talloc_free(tdb_watch->tfd);
	cm_tdbus_queue_fd(talloc_parent(conn), tdb_watch, cm_tdbus_handle_fd);
}

static void
cm_tdbus_watch_toggle(DBusWatch *watch, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_watch *tdb_watch;
	struct tdbus_dwatch *tdb_dwatch;
	int fd;
	conn = data;
	fd = cm_tdbus_watch_get_fd(watch);
	/* Find the tevent watch for this fd. */
	tdb_watch = conn->watches;
	while (tdb_watch != NULL) {
		if (tdb_watch->fd == fd) {
			break;
		}
		tdb_watch = tdb_watch->next;
	}
	if (tdb_watch == NULL) {
		return;
	}
	/* Find the watch in the list of dwatches. */
	tdb_dwatch = tdb_watch->dwatches;
	while (tdb_dwatch != NULL) {
		if (tdb_dwatch->watch == watch) {
			tdb_dwatch->active = dbus_watch_get_enabled(watch);
			break;
		}
		tdb_dwatch = tdb_dwatch->next;
	}
	/* (Re-)queue the tfd. */
	talloc_free(tdb_watch->tfd);
	cm_tdbus_queue_fd(talloc_parent(conn), tdb_watch, cm_tdbus_handle_fd);
}

static void
cm_tdbus_watch_cleanup(void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_watch *watch;
	conn = data;
	watch = conn->watches;
	while (watch != NULL) {
		while (watch->dwatches != NULL) {
			cm_tdbus_watch_remove(watch->dwatches->watch, data);
		}
		watch = watch->next;
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
	struct tdbus_timer *tdb_timer;
	struct timeval next_time;
	void *parent;
	conn = data;
	for (tdb_timer = conn->timers;
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

static void
cm_tdbus_reconnect(struct tevent_context *ec, struct tevent_timer *timer,
		   struct timeval current_time, void *pvt)
{
	const char *bus_desc;
	struct tdbus_connection *tdb;
	struct timeval later;
	tdb = pvt;
	talloc_free(timer);
	if (!dbus_connection_get_is_connected(tdb->conn)) {
		/* Close the current connection and open a new one. */
		dbus_connection_unref(tdb->conn);
		bus_desc = NULL;
		switch (tdb->conn_type) {
		case cm_tdbus_system:
			cm_log(1, "Attempting to reconnect to system bus.\n");
			tdb->conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
			cm_set_conn_ptr(tdb->data, tdb->conn);
			bus_desc = "system";
			break;
		case cm_tdbus_session:
			cm_log(1, "Attempting to reconnect to session bus.\n");
			tdb->conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
			cm_set_conn_ptr(tdb->data, tdb->conn);
			bus_desc = "session";
			break;
		}
		if (dbus_connection_get_is_connected(tdb->conn)) {
			/* We're reconnected; reset our handlers. */
			cm_log(1, "Reconnected to %s bus.\n", bus_desc);
			cm_tdbus_setup_connection(tdb, NULL);
		} else {
			/* Try reconnecting again later. */
			later = tevent_timeval_current_ofs(CM_DBUS_RECONNECT_TIMEOUT, 0),
			tevent_add_timer(ec, tdb, later,
					 cm_tdbus_reconnect,
					 tdb);
		}
	}
}

static DBusHandlerResult
cm_tdbus_filter(DBusConnection *conn, DBusMessage *dmessage, void *data)
{
	struct tdbus_connection *tdb = data;
	const char *destination, *unique_name, *path, *interface, *member;
	/* If we're disconnected, queue a reconnect. */
	if (!dbus_connection_get_is_connected(conn)) {
		tevent_add_timer(talloc_parent(tdb), tdb,
				 tevent_timeval_current(),
				 cm_tdbus_reconnect,
				 tdb);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	switch (dbus_message_get_type(dmessage)) {
	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		/* Make sure it's a message we care about. */
		destination = dbus_message_get_destination(dmessage);
		path = dbus_message_get_path(dmessage);
		interface = dbus_message_get_interface(dmessage);
		member = dbus_message_get_member(dmessage);
		/* Catch weird-looking messages. */
		if ((destination == NULL) || (path == NULL) || (member == NULL)) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		cm_log(4, "message %p(%s)->%s:%s:%s.%s\n", tdb,
		       dbus_message_type_to_string(dbus_message_get_type(dmessage)),
		       destination, path, interface ? interface : "", member);
		return cm_tdbush_handle_method_call(conn, dmessage, tdb->data);
		break;
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
		/* Check that the call or return is directed to us. */
		destination = dbus_message_get_destination(dmessage);
		if ((strcmp(destination, CM_DBUS_NAME) != 0) &&
		    (((unique_name = dbus_bus_get_unique_name(conn)) == NULL) ||
		      (strcmp(destination, unique_name) != 0))) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		cm_log(4, "message %p(%s)->%lu->%lu\n", tdb,
		       dbus_message_type_to_string(dbus_message_get_type(dmessage)),
		       (unsigned long) dbus_message_get_reply_serial(dmessage),
		       (unsigned long) dbus_message_get_serial(dmessage));
		return cm_tdbush_handle_method_return(conn, dmessage, tdb->data);
		break;
	default:
		break;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int
cm_tdbus_setup_connection(struct tdbus_connection *tdb, DBusError *error)
{
	DBusError err;
	const char *bus_desc;
	int i;
	/* Set the callback to be called when I/O processing has yielded a
	 * request that we need to act on. */
	dbus_connection_set_dispatch_status_function(tdb->conn,
						     cm_tdbus_dispatch_status,
						     tdb, NULL);
	/* Hook up the I/O callbacks so that D-Bus can actually do its thing. */
	if (!dbus_connection_set_watch_functions(tdb->conn,
						 &cm_tdbus_watch_add,
						 &cm_tdbus_watch_remove,
						 &cm_tdbus_watch_toggle,
						 tdb,
						 &cm_tdbus_watch_cleanup)) {
		cm_log(1, "Unable to add timer callbacks.\n");
		return -1;
	}
	/* Hook up the (unused?) timer callbacks to be polite. */
	if (!dbus_connection_set_timeout_functions(tdb->conn,
						   cm_tdbus_timeout_add,
						   cm_tdbus_timeout_remove,
						   cm_tdbus_timeout_toggle,
						   tdb,
						   cm_tdbus_timeout_cleanup)) {
		cm_log(1, "Unable to add timer callbacks.\n");
		return -1;
	}
	/* Set the filter on messages. */
	if (!dbus_connection_add_filter(tdb->conn, cm_tdbus_filter,
					tdb, NULL)) {
		cm_log(1, "Unable to add filter.\n");
		return -1;
	}
	/* Bind to the well-known name we intend to use. */
	memset(&err, 0, sizeof(err));
	i = dbus_bus_request_name(tdb->conn, CM_DBUS_NAME, 0, &err);
	if ((i == 0) ||
	    ((i != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) &&
	     (i != DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER)) ||
	    dbus_error_is_set(&err)) {
		cm_log(-2,
		       "Unable to set well-known bus name \"%s\": %s(%d).\n",
		       CM_DBUS_NAME,
		       err.message ? err.message : (err.name ? err.name : ""),
		       i);
		if (error != NULL) {
			dbus_move_error(&err, error);
		}
		return -1;
	}
	/* Handle any messages that are already pending. */
	cm_tdbus_dispatch_status(tdb->conn,
				 dbus_connection_get_dispatch_status(tdb->conn),
				 tdb);
	bus_desc = NULL;
	switch (tdb->conn_type) {
	case cm_tdbus_system:
		bus_desc = "system";
		break;
	case cm_tdbus_session:
		bus_desc = "session";
		break;
	}
	cm_log(3, "Connected to %s message bus with name \"%s\", "
	       "unique name \"%s\".\n",
	       bus_desc, dbus_bus_get_unique_name(tdb->conn) ?: "(unknown)",
	       CM_DBUS_NAME);
	return 0;
}

int
cm_tdbus_setup(struct tevent_context *ec, enum cm_tdbus_type bus_type,
	       void *data, DBusError *error)
{
	DBusConnection *conn;
	const char *bus_desc;
	struct tdbus_connection *tdb;
	dbus_bool_t exit_on_disconnect;
	/* Build our own context. */
	tdb = talloc_ptrtype(ec, tdb);
	if (tdb == NULL) {
		return ENOMEM;
	}
	memset(tdb, 0, sizeof(*tdb));
	/* Connect to the right bus. */
	bus_desc = NULL;
	conn = NULL;
	exit_on_disconnect = TRUE;
	if (error != NULL) {
		dbus_error_init(error);
	}
	switch (bus_type) {
	case cm_tdbus_system:
		conn = dbus_bus_get(DBUS_BUS_SYSTEM, error);
		cm_set_conn_ptr(data, conn);
		/* Don't exit if we get disconnected. */
		exit_on_disconnect = FALSE;
		bus_desc = "system";
		break;
	case cm_tdbus_session:
		conn = dbus_bus_get(DBUS_BUS_SESSION, error);
		cm_set_conn_ptr(data, conn);
		/* Exit if we get disconnected. */
		exit_on_disconnect = TRUE;
		bus_desc = "session";
		break;
	}
	if (conn == NULL) {
		cm_log(-2, "Error connecting to %s bus.\n", bus_desc);
		talloc_free(tdb);
		return -1;
	}
	dbus_connection_set_exit_on_disconnect(conn, exit_on_disconnect);
	tdb->conn = conn;
	tdb->conn_type = bus_type;
	tdb->data = data;
	return cm_tdbus_setup_connection(tdb, error);
}
