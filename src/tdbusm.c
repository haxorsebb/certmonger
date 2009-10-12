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
	*p = NULL;
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
	*s = NULL;
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
	*p = NULL;
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
	*s = NULL;
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
	*s = NULL;
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
	*s = NULL;
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
	*s1 = NULL;
	*s2 = NULL;
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
	*ap = NULL;
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
	*as = NULL;
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
	*s1 = NULL;
	*s2 = NULL;
	*s3 = NULL;
	*s4 = NULL;
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
	*s1 = NULL;
	*s2 = NULL;
	*s3 = NULL;
	*as = NULL;
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
	*s1 = NULL;
	*s2 = NULL;
	*s3 = NULL;
	*as1 = NULL;
	*as2 = NULL;
	*as3 = NULL;
	*as4 = NULL;
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
	*s = NULL;
	*as1 = NULL;
	*as2 = NULL;
	*as3 = NULL;
	*as4 = NULL;
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

static struct cm_tdbusm_dict *
cm_tdbusm_get_d_item(DBusMessageIter *item, void *parent)
{
	struct cm_tdbusm_dict *dict;
	char *s, **as;
	int64_t i64;
	int32_t i32;
	int16_t i16;
	int n_values;
	DBusMessageIter value, sval;
	dict = talloc_ptrtype(parent, dict);
	/* Pull out a string. */
	switch (dbus_message_iter_get_arg_type(item)) {
	case DBUS_TYPE_STRING:
		dbus_message_iter_get_basic(item, &s);
		dict->key = talloc_strdup(dict, s);
		break;
	default:
		talloc_free(dict);
		return NULL;
		break;
	}
	if (!dbus_message_iter_has_next(item) ||
	    !dbus_message_iter_next(item)) {
		talloc_free(dict);
		return NULL;
	}
	/* Pull out a variant. */
	switch (dbus_message_iter_get_arg_type(item)) {
	case DBUS_TYPE_VARIANT:
		memset(&value, 0, sizeof(value));
		dbus_message_iter_recurse(item, &value);
		switch (dbus_message_iter_get_arg_type(&value)) {
		/* The variant value can be a boolean. */
		case DBUS_TYPE_BOOLEAN:
			dict->value_type = cm_tdbusm_dict_b;
			dbus_message_iter_get_basic(&value, &dict->value.b);
			break;
		/* It can be a string. */
		case DBUS_TYPE_STRING:
			dict->value_type = cm_tdbusm_dict_s;
			dbus_message_iter_get_basic(&value, &s);
			dict->value.s = talloc_strdup(dict, s);
			break;
		/* It can be an integer type. */
		case DBUS_TYPE_INT16:
			dict->value_type = cm_tdbusm_dict_n;
			dbus_message_iter_get_basic(&value, &i16);
			dict->value.n = i16;
			break;
		case DBUS_TYPE_INT32:
			dict->value_type = cm_tdbusm_dict_n;
			dbus_message_iter_get_basic(&value, &i32);
			dict->value.n = i32;
			break;
		case DBUS_TYPE_INT64:
			dict->value_type = cm_tdbusm_dict_n;
			dbus_message_iter_get_basic(&value, &i64);
			dict->value.n = i64;
			break;
		/* It can be an array of strings. */
		case DBUS_TYPE_ARRAY:
			dict->value_type = cm_tdbusm_dict_as;
			memset(&sval, 0, sizeof(sval));
			dbus_message_iter_recurse(&value, &sval);
			as = NULL;
			n_values = 0;
			for (;;) {
				/* This had better be a string. */
				switch (dbus_message_iter_get_arg_type(&sval)) {
				case DBUS_TYPE_STRING:
					dbus_message_iter_get_basic(&sval, &s);
					as = talloc_realloc(dict, as, char *,
							    n_values + 2);
					if (as != NULL) {
						as[n_values] = talloc_strdup(as,
									     s);
						n_values++;
						as[n_values] = NULL;
					}
					break;
				default:
					talloc_free(dict);
					return NULL;
					break;
				}
				/* Move on to the next element. */
				if (dbus_message_iter_has_next(&sval)) {
					if (!dbus_message_iter_next(&sval)) {
						talloc_free(dict);
						return NULL;
					}
				} else {
					/* Out of elements. */
					break;
				}
			}
			dict->value.as = as;
			break;
		default:
			/* It had better not be something else. */
			talloc_free(dict);
			return NULL;
			break;
		}
		break;
	default:
		talloc_free(dict);
		return NULL;
		break;
	}
	return dict;
}
static struct cm_tdbusm_dict **
cm_tdbusm_get_d_array(DBusMessageIter *array, void *parent)
{
	struct cm_tdbusm_dict *ditem, **dict, **tmp;
	int n_items;
	DBusMessageIter item;
	dict = NULL;
	n_items = 0;
	for (;;) {
		/* We'd better be walking a list of dictionary entries. */
		switch (dbus_message_iter_get_arg_type(array)) {
		case DBUS_TYPE_DICT_ENTRY:
			/* Found a dictionary entry. */
			memset(&item, 0, sizeof(item));
			dbus_message_iter_recurse(array, &item);
			ditem = cm_tdbusm_get_d_item(&item, parent);
			if (ditem != NULL) {
				tmp = talloc_realloc(parent, dict,
						     struct cm_tdbusm_dict *,
						     n_items + 2);
				if (tmp != NULL) {
					tmp[n_items] = ditem;
					n_items++;
					tmp[n_items] = NULL;
					dict = tmp;
				}
			}
			break;
		default:
			/* Found... something else. */
			talloc_free(dict);
			return NULL;
			break;
		}
		if (dbus_message_iter_has_next(array)) {
			if (!dbus_message_iter_next(array)) {
				talloc_free(dict);
				return NULL;
			}
		} else {
			break;
		}
	}
	return dict;
}

int
cm_tdbusm_get_d(DBusMessage *msg, void *parent, struct cm_tdbusm_dict ***d)
{
	struct cm_tdbusm_dict **tdicts, **dicts, **tmp;
	DBusMessageIter args, array;
	int i, n_dicts;
	*d = NULL;
	dicts = NULL;
	n_dicts = 0;
	memset(&args, 0, sizeof(args));
	if (dbus_message_iter_init(msg, &args)) {
		for (;;) {
			switch (dbus_message_iter_get_arg_type(&args)) {
			case DBUS_TYPE_ARRAY:
				memset(&array, 0, sizeof(array));
				dbus_message_iter_recurse(&args, &array);
				tdicts = cm_tdbusm_get_d_array(&array, parent);
				if (tdicts != NULL) {
					for (i = 0; tdicts[i] != NULL; i++) {
						continue;
					}
					tmp = talloc_realloc(parent, dicts,
							     struct cm_tdbusm_dict *,
							     n_dicts + i + 1);
					if (tmp != NULL) {
						memcpy(tmp + n_dicts,
						       tdicts,
						       i * sizeof(tdicts[0]));
						n_dicts += i;
						tmp[n_dicts] = NULL;
						dicts = tmp;
					} else {
						talloc_free(tdicts);
						talloc_free(dicts);
						return -1;
					}
				}
				break;
			default:
				talloc_free(dicts);
				return -1;
				break;
			}
			if (dbus_message_iter_has_next(&args)) {
				if (!dbus_message_iter_next(&args)) {
					talloc_free(dicts);
					return -1;
				}
			} else {
				break;
			}
		}
		*d = dicts;
		return 0;
	}
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
	DBusMessageIter args, array, entry, val, elt;
	int i;
	long l;
	memset(&args, 0, sizeof(args));
	dbus_message_iter_init_append(msg, &args);
	memset(&array, 0, sizeof(array));
	dbus_message_iter_open_container(&args,
					 DBUS_TYPE_ARRAY,
					 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_VARIANT_AS_STRING
					 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					 &array);
	for (i = 0; (d != NULL) && (d[i] != NULL); i++) {
		memset(&entry, 0, sizeof(entry));
		dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY,
						 NULL,
						 &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
					       &d[i]->key);
		memset(&val, 0, sizeof(val));
		switch (d[i]->value_type) {
		case cm_tdbusm_dict_b:
			dbus_message_iter_open_container(&entry,
							 DBUS_TYPE_VARIANT,
							 DBUS_TYPE_BOOLEAN_AS_STRING,
							 &val);
			dbus_message_iter_append_basic(&val,
						       DBUS_TYPE_BOOLEAN,
						       &d[i]->value.b);
			dbus_message_iter_close_container(&entry, &val);
			break;
		case cm_tdbusm_dict_n:
			dbus_message_iter_open_container(&entry,
							 DBUS_TYPE_VARIANT,
							 DBUS_TYPE_INT64_AS_STRING,
							 &val);
			l = d[i]->value.n;
			dbus_message_iter_append_basic(&val,
						       DBUS_TYPE_INT64,
						       &l);
			dbus_message_iter_close_container(&entry, &val);
			break;
		case cm_tdbusm_dict_s:
			dbus_message_iter_open_container(&entry,
							 DBUS_TYPE_VARIANT,
							 DBUS_TYPE_STRING_AS_STRING,
							 &val);
			dbus_message_iter_append_basic(&val,
						       DBUS_TYPE_STRING,
						       &d[i]->value.s);
			dbus_message_iter_close_container(&entry, &val);
			break;
		case cm_tdbusm_dict_as:
			dbus_message_iter_open_container(&entry,
							 DBUS_TYPE_VARIANT,
							 DBUS_TYPE_ARRAY_AS_STRING
							 DBUS_TYPE_STRING_AS_STRING,
							 &val);
			memset(&elt, 0, sizeof(elt));
			dbus_message_iter_open_container(&val,
							 DBUS_TYPE_ARRAY,
							 DBUS_TYPE_STRING_AS_STRING,
							 &elt);
			for (l = 0;
			     (d[i]->value.as != NULL) &&
			     (d[i]->value.as[l] != NULL);
			     l++) {
				dbus_message_iter_append_basic(&elt,
							       DBUS_TYPE_STRING,
							       &d[i]->value.as[l]);
			}
			dbus_message_iter_close_container(&val, &elt);
			dbus_message_iter_close_container(&entry, &val);
			break;
		}
		dbus_message_iter_close_container(&array, &entry);
	}
	dbus_message_iter_close_container(&args, &array);
	return (i > 0) ? 0 : -1;
}
