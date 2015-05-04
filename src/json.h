/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#ifndef cmjson_h
#define cmjson_h

struct cm_json;

enum cm_json_type {
	cm_json_type_undefined = 0,
	cm_json_type_null,
	cm_json_type_string,
	cm_json_type_numberl,
	cm_json_type_numberd,
	cm_json_type_boolean,
	cm_json_type_object,
	cm_json_type_array,
};

#define CM_JSON_EXPECTED_KEY_OR_CLOSE		-2
#define CM_JSON_EXPECTED_KEY			-3
#define CM_JSON_EXPECTED_COLON			-4
#define CM_JSON_EXPECTED_COMMA_OR_CLOSE		-5
#define CM_JSON_EXPECTED_EXPRESSION_OR_CLOSE	-6
#define CM_JSON_EXPECTED_EXPRESSION		-7

int cm_json_decode(void *parent, const char *encoded, ssize_t length,
		   struct cm_json **json, const char **next);
const char *cm_json_decode_strerror(int error);
struct cm_json *cm_json_find(struct cm_json *json, const char *path);
char *cm_json_encode(void *parent, struct cm_json *json);

enum cm_json_type cm_json_type(struct cm_json *json);

ssize_t cm_json_n_keys(struct cm_json *json);
const char *cm_json_nth_key(struct cm_json *json, size_t n);
struct cm_json *cm_json_get(struct cm_json *json, const char *key);
struct cm_json *cm_json_nth_val(struct cm_json *json, size_t n);
int cm_json_set(struct cm_json *json, const char *key, struct cm_json *value);

ssize_t cm_json_array_size(struct cm_json *json);
struct cm_json *cm_json_n(struct cm_json *json, size_t n);
int cm_json_append(struct cm_json *json, struct cm_json *value);
int cm_json_set_n(struct cm_json *json, size_t n, struct cm_json *value);

const char *cm_json_string(struct cm_json *json, ssize_t *length);
long double cm_json_numberd(struct cm_json *json);
long long cm_json_numberl(struct cm_json *json);
unsigned char cm_json_boolean(struct cm_json *json);

struct cm_json *cm_json_new_null(void *parent);
struct cm_json *cm_json_new_string(void *parent, const char *string,
				   ssize_t length);
struct cm_json *cm_json_new_numberl(void *parent, long long number);
struct cm_json *cm_json_new_numberd(void *parent, long double number);
struct cm_json *cm_json_new_boolean(void *parent, unsigned char value);
struct cm_json *cm_json_new_object(void *parent);
struct cm_json *cm_json_new_array(void *parent);

int cm_json_utf8_to_point(const char *p, uint32_t *point);
int cm_json_point_to_utf8_length(uint32_t point);
int cm_json_point_to_utf8(uint32_t point, char *out, ssize_t max);

#endif
