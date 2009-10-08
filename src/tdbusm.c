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

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>

#include <dbus/dbus.h>

#include "log.h"
#include "tdbusm.h"

int
cm_tdbusm_get_b(DBusMessage *msg, void *parent, dbus_bool_t *b)
{
	DBusError err;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_n(DBusMessage *msg, void *parent, long *n)
{
	DBusError err;
	int64_t i64;
	int32_t i32;
	int16_t i16;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_INT64, &i64,
				  DBUS_TYPE_INVALID)) {
		*n = i64;
		return 0;
	} else {
		memset(&err, 0, sizeof(err));
		if (dbus_message_get_args(msg, &err,
					  DBUS_TYPE_INT32, &i32,
					  DBUS_TYPE_INVALID)) {
			*n = i32;
			return 0;
		} else {
			memset(&err, 0, sizeof(err));
			if (dbus_message_get_args(msg, &err,
						  DBUS_TYPE_INT16, &i16,
						  DBUS_TYPE_INVALID)) {
				*n = i16;
				return 0;
			} else {
				return -1;
			}
		}
	}
}

int
cm_tdbusm_get_p(DBusMessage *msg, void *parent, char **p)
{
	DBusError err;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_OBJECT_PATH, p,
				  DBUS_TYPE_INVALID)) {
		*p = *p ? talloc_strdup(parent, *p) : NULL;
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_s(DBusMessage *msg, void *parent, char **s)
{
	DBusError err;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s,
				  DBUS_TYPE_INVALID)) {
		*s = *s ? talloc_strdup(parent, *s) : NULL;
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_bp(DBusMessage *msg, void *parent, dbus_bool_t *b, char **p)
{
	DBusError err;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_OBJECT_PATH, p,
				  DBUS_TYPE_INVALID)) {
		*p = *p ? talloc_strdup(parent, *p) : NULL;
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_bs(DBusMessage *msg, void *parent, dbus_bool_t *b, char **s)
{
	DBusError err;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_STRING, s,
				  DBUS_TYPE_INVALID)) {
		*s = *s ? talloc_strdup(parent, *s) : NULL;
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_sb(DBusMessage *msg, void *parent, char **s, dbus_bool_t *b)
{
	DBusError err;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_INVALID)) {
		*s = *s ? talloc_strdup(parent, *s) : NULL;
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_sn(DBusMessage *msg, void *parent, char **s, long *n)
{
	DBusError err;
	int64_t i64;
	int64_t i32;
	int64_t i16;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s,
				  DBUS_TYPE_INT64, &i64,
				  DBUS_TYPE_INVALID)) {
		*s = *s ? talloc_strdup(parent, *s) : NULL;
		*n = i64;
		return 0;
	} else {
		memset(&err, 0, sizeof(err));
		if (dbus_message_get_args(msg, &err,
					  DBUS_TYPE_STRING, s,
					  DBUS_TYPE_INT32, &i32,
					  DBUS_TYPE_INVALID)) {
			*s = *s ? talloc_strdup(parent, *s) : NULL;
			*n = i32;
			return 0;
		} else {
			memset(&err, 0, sizeof(err));
			if (dbus_message_get_args(msg, &err,
						  DBUS_TYPE_STRING, s,
						  DBUS_TYPE_INT16, &i16,
						  DBUS_TYPE_INVALID)) {
				*s = *s ? talloc_strdup(parent, *s) : NULL;
				*n = i16;
				return 0;
			} else {
				return -1;
			}
		}
	}
}

int
cm_tdbusm_get_ss(DBusMessage *msg, void *parent, char **s1, char **s2)
{
	DBusError err;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_ap(DBusMessage *msg, void *parent, char ***ap)
{
	return -1;
}

int
cm_tdbusm_get_as(DBusMessage *msg, void *parent, char ***as)
{
	return -1;
}

int
cm_tdbusm_get_ssss(DBusMessage *msg, void *parent, char **s1, char **s2,
		   char **s3, char **s4)
{
	DBusError err;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_STRING, s3,
				  DBUS_TYPE_STRING, s4,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
		*s3 = *s3 ? talloc_strdup(parent, *s3) : NULL;
		*s4 = *s4 ? talloc_strdup(parent, *s4) : NULL;
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_sssas(DBusMessage *msg, void *parent,
		    char **s1, char **s2, char **s3, char ***as)
{
	return -1;
}

int
cm_tdbusm_get_sssnasasasas(DBusMessage *msg, void *parent,
			   char **s1, char **s2, char **s3, long *n,
			   char ***as1, char ***as2, char ***as3, char ***as4)
{
	return -1;
}

int
cm_tdbusm_get_sasasasnas(DBusMessage *msg, void *parent, char **s,
			 char ***as1, char ***as2, char ***as3,
			 long *n, char ***as4)
{
	return -1;
}

int
cm_tdbusm_get_d(DBusMessage *msg, void *parent, struct cm_tdbusm_dict ***d)
{
	return -1;
}

int
cm_tdbusm_set_b(DBusMessage *msg, dbus_bool_t b)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_n(DBusMessage *msg, long n)
{
	int64_t i = n;
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_INT64, &i,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_p(DBusMessage *msg, const char *p)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_OBJECT_PATH, &p,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_s(DBusMessage *msg, const char *s)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_bs(DBusMessage *msg, dbus_bool_t b, const char *s)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_bp(DBusMessage *msg, dbus_bool_t b, const char *p)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_OBJECT_PATH, &p,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sb(DBusMessage *msg, const char *s, dbus_bool_t b)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sn(DBusMessage *msg, const char *s, long n)
{
	int64_t i = n;
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_INT64, &i,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ss(DBusMessage *msg, const char *s1, const char *s2)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ap(DBusMessage *msg, const char **ap)
{
	return -1;
}

int
cm_tdbusm_set_as(DBusMessage *msg, const char **as)
{
	return -1;
}

int
cm_tdbusm_set_ssss(DBusMessage *msg, const char *s1, const char *s2,
		   const char *s3, const char *s4)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_STRING, &s3,
				     DBUS_TYPE_STRING, &s4,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sssas(DBusMessage *msg,
		    const char *s1, const char *s2,
		    const char *s3, const char **as)
{
	return -1;
}

int
cm_tdbusm_set_sssnasasasas(DBusMessage *msg,
			   const char *s1, const char *s2, const char *s3,
			   long n,
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

int
cm_tdbusm_set_d(DBusMessage *msg, const struct cm_tdbusm_dict **d)
{
	return -1;
}
