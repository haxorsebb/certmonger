#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>
#include <tevent.h>

#include <dbus/dbus.h>

struct tdbus_connection {
	DBusConnection *d_conn;
	struct tdbus_watch {
		struct tdbus_watch *next;
		DBusWatch *watch;
		struct tevent_fd *tfd;
		dbus_bool_t active;
	} *watches;
	struct tdbus_timer {
		struct tdbus_timer *next;
		DBusTimeout *timeout;
		struct tevent_timer *tt;
		int d_interval;
		dbus_bool_t active;
	} *timers;
};

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
		tfd_flags |= TEVENT_FD_WRITE;
	}
	return tfd_flags;
}

static void
cm_tdbus_handle_fd(struct tevent_context *ec, struct tevent_fd *tfd,
		   uint16_t flags, void *pvt)
{
	struct tdbus_watch *watch;
	int fd;
	watch = pvt;
	if (watch->active) {
		talloc_free(watch->tfd);
		if (dbus_watch_handle(watch->watch, flags)) {
			fd = dbus_watch_get_unix_fd(watch->watch);
			watch->tfd = tevent_add_fd(ec, watch, fd, flags,
						   cm_tdbus_handle_fd, watch);
		} else {
			watch->tfd = NULL;
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
	if (tdb_timer->active) {
		talloc_free(tdb_timer->tt);
		if (dbus_timeout_handle(tdb_timer->timeout)) {
			next_time = tevent_timeval_current_ofs(tdb_timer->d_interval, 0);
			tdb_timer->tt = tevent_add_timer(ec, tdb_timer,
							 next_time,
							 cm_tdbus_handle_timer,
							 tdb_timer);
		} else {
			tdb_timer->tt = NULL;
		}
	}
}

static dbus_bool_t
cm_tdbus_watch_add(DBusWatch *watch, void *data)
{
	struct tdbus_connection *conn;
	struct tdbus_watch *tdb_watch;
	unsigned int flags;
	int fd, tfd_flags;
	conn = data;
	tdb_watch = talloc_ptrtype(conn, tdb_watch);
	if (tdb_watch != NULL) {
		memset(tdb_watch, 0, sizeof(*tdb_watch));
		tdb_watch->watch = watch;
		flags = dbus_watch_get_flags(watch);
		tfd_flags = cm_tdbus_tfd_flags_for_watch_flags(flags);
		tdb_watch->active = dbus_watch_get_enabled(watch);
		if (tdb_watch->active) {
			fd = dbus_watch_get_unix_fd(watch),
			tdb_watch->tfd = tevent_add_fd(talloc_parent(conn),
						       tdb_watch,
						       fd,
						       tfd_flags,
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
	talloc_free(tdb_watch);
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
	talloc_free(tdb_timer);
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

int
cm_tdbus_setup(struct tevent_context *ec, DBusConnection *conn)
{
	struct tdbus_connection *tdb;
	tdb = talloc_ptrtype(ec, tdb);
	if (tdb == NULL) {
		return ENOMEM;
	}
	memset(tdb, 0, sizeof(*tdb));
	tdb->d_conn = conn;
	if (dbus_connection_set_watch_functions(conn,
						&cm_tdbus_watch_add,
						&cm_tdbus_watch_remove,
						&cm_tdbus_watch_toggle,
						tdb,
						&cm_tdbus_watch_cleanup) == FALSE) {
		return -1;
	}
	if (dbus_connection_set_timeout_functions(conn,
						  cm_tdbus_timeout_add,
						  cm_tdbus_timeout_remove,
						  cm_tdbus_timeout_toggle,
						  tdb,
						  cm_tdbus_timeout_cleanup) == FALSE) {
		return -1;
	}
	return 0;
}
