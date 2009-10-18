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

#ifndef cmtdbus_h
#define cmtdbus_h

#define CM_DBUS_BASE_INTERFACE CM_DBUS_NAME
#define CM_DBUS_DEFAULT_BUS cm_tdbus_system
#define CM_DBUS_CA_PATH CM_DBUS_BASE_PATH "/cas"
#define CM_DBUS_CA_INTERFACE CM_DBUS_BASE_INTERFACE ".ca"
#define CM_DBUS_REQUEST_PATH CM_DBUS_BASE_PATH "/requests"
#define CM_DBUS_REQUEST_INTERFACE CM_DBUS_BASE_INTERFACE ".request"

enum cm_tdbus_type { cm_tdbus_system, cm_tdbus_session };
int cm_tdbus_setup(struct tevent_context *ec, enum cm_tdbus_type bus_type,
		   void *data);

#endif
