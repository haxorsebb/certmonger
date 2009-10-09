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

#include "tdbusm.h"

static int
cm_tdbusm_array_length(const char **array)
{
	int i;
	for (i = 0; (array != NULL) && (array[i] != NULL); i++) {
		continue;
	}
	return i;
}

static char **
cm_tdbusm_take_dbus_string_array(void *parent, char **array, int len)
{
	int i;
	char **ret;
	if (len == -1) {
		len = cm_tdbusm_array_length((const char **) array);
	}
	if (len > 0) {
		ret = talloc_zero_array(parent, char *, len + 1);
		if (ret != NULL) {
			for (i = 0;
			     (array != NULL) && (i < len) && (array[i] != NULL);
			     i++) {
				ret[i] = talloc_strdup(ret, array[i]);
			}
			ret[i] = NULL;
		}
	} else {
		ret = NULL;
	}
	if (array != NULL) {
		dbus_free_string_array(array);
	}
	return ret;
}

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
	DBusError err;
	char **tmp;
	int i;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
				  &tmp, &i,
				  DBUS_TYPE_INVALID)) {
		*ap = cm_tdbusm_take_dbus_string_array(parent, tmp, i);
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_as(DBusMessage *msg, void *parent, char ***as)
{
	DBusError err;
	char **tmp;
	int i;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp, &i,
				  DBUS_TYPE_INVALID)) {
		*as = cm_tdbusm_take_dbus_string_array(parent, tmp, i);
		return 0;
	} else {
		return -1;
	}
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
	DBusError err;
	char **tmp;
	int i;
	memset(&err, 0, sizeof(err));
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_STRING, s3,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp, &i,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
		*s3 = *s3 ? talloc_strdup(parent, *s3) : NULL;
		*as = cm_tdbusm_take_dbus_string_array(parent, tmp, i);
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_get_sssnasasasas(DBusMessage *msg, void *parent,
			   char **s1, char **s2, char **s3, long *n,
			   char ***as1, char ***as2, char ***as3, char ***as4)
{
	DBusError err;
	char **tmp1, **tmp2, **tmp3, **tmp4;
	int64_t i64;
	int32_t i32;
	int16_t i16;
	int i, j, k, l;
	memset(&err, 0, sizeof(err));
	if (!dbus_message_get_args(msg, &err,
				   DBUS_TYPE_STRING, s1,
				   DBUS_TYPE_STRING, s2,
				   DBUS_TYPE_STRING, s3,
				   DBUS_TYPE_INT64, &i64,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp1, &i,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp2, &j,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp3, &k,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp4, &l,
				   DBUS_TYPE_INVALID)) {
		if (!dbus_message_get_args(msg, &err,
					   DBUS_TYPE_STRING, s1,
					   DBUS_TYPE_STRING, s2,
					   DBUS_TYPE_STRING, s3,
					   DBUS_TYPE_INT32, &i32,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp1, &i,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp2, &j,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp3, &k,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp4, &l,
					   DBUS_TYPE_INVALID)) {
			if (!dbus_message_get_args(msg, &err,
						   DBUS_TYPE_STRING, s1,
						   DBUS_TYPE_STRING, s2,
						   DBUS_TYPE_STRING, s3,
						   DBUS_TYPE_INT16, &i16,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp1, &i,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp2, &j,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp3, &k,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp4, &l,
						   DBUS_TYPE_INVALID)) {
				return -1;
			}
			i32 = i16;
		}
		i64 = i32;
	}
	*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
	*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
	*s3 = *s3 ? talloc_strdup(parent, *s3) : NULL;
	*n = i64;
	*as1 = cm_tdbusm_take_dbus_string_array(parent, tmp1, i);
	*as2 = cm_tdbusm_take_dbus_string_array(parent, tmp2, j);
	*as3 = cm_tdbusm_take_dbus_string_array(parent, tmp3, k);
	*as4 = cm_tdbusm_take_dbus_string_array(parent, tmp4, l);
	return 0;
}

int
cm_tdbusm_get_sasasasnas(DBusMessage *msg, void *parent, char **s,
			 char ***as1, char ***as2, char ***as3,
			 long *n, char ***as4)
{
	DBusError err;
	char **tmp1, **tmp2, **tmp3, **tmp4;
	int64_t i64;
	int32_t i32;
	int16_t i16;
	int i, j, k, l;
	memset(&err, 0, sizeof(err));
	if (!dbus_message_get_args(msg, &err,
				   DBUS_TYPE_STRING, s,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp1, &i,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp2, &j,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp3, &k,
				   DBUS_TYPE_INT64, &i64,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp4, &l,
				   DBUS_TYPE_INVALID)) {
		if (!dbus_message_get_args(msg, &err,
					   DBUS_TYPE_STRING, s,
					   DBUS_TYPE_ARRAY,
					   DBUS_TYPE_STRING, &tmp1, &i,
					   DBUS_TYPE_ARRAY,
					   DBUS_TYPE_STRING, &tmp2, &j,
					   DBUS_TYPE_ARRAY,
					   DBUS_TYPE_STRING, &tmp3, &k,
					   DBUS_TYPE_INT32, &i32,
					   DBUS_TYPE_ARRAY,
					   DBUS_TYPE_STRING, &tmp4, &l,
					   DBUS_TYPE_INVALID)) {
			if (!dbus_message_get_args(msg, &err,
						   DBUS_TYPE_STRING, s,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp1, &i,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp2, &j,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp3, &k,
						   DBUS_TYPE_INT16, &i16,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp4, &l,
						   DBUS_TYPE_INVALID)) {
				return -1;
			}
			i32 = i16;
		}
		i64 = i32;
	}
	*s = *s ? talloc_strdup(parent, *s) : NULL;
	*as1 = cm_tdbusm_take_dbus_string_array(parent, tmp1, i);
	*as2 = cm_tdbusm_take_dbus_string_array(parent, tmp2, j);
	*as3 = cm_tdbusm_take_dbus_string_array(parent, tmp3, k);
	*n = i64;
	*as4 = cm_tdbusm_take_dbus_string_array(parent, tmp4, l);
	return 0;
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
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
				     &ap, cm_tdbusm_array_length(ap),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_as(DBusMessage *msg, const char **as)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as, cm_tdbusm_array_length(as),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
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
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_STRING, &s3,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as, cm_tdbusm_array_length(as),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sssnasasasas(DBusMessage *msg,
			   const char *s1, const char *s2, const char *s3,
			   long n,
			   const char **as1, const char **as2,
			   const char **as3, const char **as4)
{
	int64_t i = n;
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_STRING, &s3,
				     DBUS_TYPE_INT64, &i,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as1, cm_tdbusm_array_length(as1),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as2, cm_tdbusm_array_length(as2),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as3, cm_tdbusm_array_length(as3),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as4, cm_tdbusm_array_length(as4),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sasasasnas(DBusMessage *msg, const char *s,
			 const char **as1, const char **as2,
			 const char **as3, long n, const char **as4)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as1, cm_tdbusm_array_length(as1),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as2, cm_tdbusm_array_length(as2),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as3, cm_tdbusm_array_length(as3),
				     DBUS_TYPE_INT64, &n,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as4, cm_tdbusm_array_length(as4),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_d(DBusMessage *msg, const struct cm_tdbusm_dict **d)
{
	return -1;
}
