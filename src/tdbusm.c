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

#include <stdlib.h>

#include <talloc.h>

#include <dbus/dbus.h>

#include "log.h"
#include "tdbusm.h"

int
cm_tdbusm_get_s(DBusMessage *msg, void *parent, char **s)
{
	return -1;
}

int
cm_tdbusm_get_ss(DBusMessage *msg, void *parent, char **s1, char **s2)
{
	return -1;
}

int
cm_tdbusm_get_sssas(DBusMessage *msg, void *parent,
		    char **s1, char **s2, char *s3, char ***s4)
{
	return -1;
}

int
cm_tdbusm_get_as(DBusMessage *msg, void *parent, char ***s)
{
	return -1;
}

int
cm_tdbusm_get_b(DBusMessage *msg, void *parent, dbus_bool_t *b)
{
	return -1;
}

int
cm_tdbusm_get_d(DBusMessage *msg, void *parent, struct cm_tdbusm_dict ***d)
{
	return -1;
}

int
cm_tdbusm_set_s(DBusMessage *msg, const char *s)
{
	return -1;
}

int
cm_tdbusm_set_b(DBusMessage *msg, dbus_bool_t b)
{
	return -1;
}

int
cm_tdbusm_set_bs(DBusMessage *msg, dbus_bool_t b, const char *s)
{
	return -1;
}

int
cm_tdbusm_set_sb(DBusMessage *msg, const char *s, dbus_bool_t b)
{
	return -1;
}

int
cm_tdbusm_set_sn(DBusMessage *msg, const char *s, long n)
{
	return -1;
}

int
cm_tdbusm_set_n(DBusMessage *msg, long n)
{
	return -1;
}

int
cm_tdbusm_set_as(DBusMessage *msg, const char **s)
{
	return -1;
}

int
cm_tdbusm_set_ssss(DBusMessage *msg, const char *s1, const char *s2,
		   const char *s3, const char *s4)
{
	return -1;
}

int
cm_tdbusm_set_sssnasasasas(DBusMessage *msg, const char *s1, const char *s2,
			   const char *s3, long n,
			   const char **as1, const char **as2,
			   const char **as3, const char **as4)
{
	return -1;
}

int
cm_tdbusm_set_sasasasnas(DBusMessage *msg, const char *s,
			 const char **as1, const char **as2,
			 const char **as3, long n, const char **as4)
{
	return -1;
}
