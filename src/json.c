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

#include "config.h"

#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>

#include "json.h"

struct cm_json {
	enum cm_json_type type;
	union {
		struct {
			char *s;
			ssize_t l;
		} s;
		long long l;
		long double d;
		unsigned char b;
		struct {
			size_t n;
			struct cm_json_object_rec {
				char *key;
				struct cm_json *val;
			} *o;
		} o;
		struct {
			size_t n;
			struct cm_json **a;
		} a;
	};
};

enum cm_json_type
cm_json_type(struct cm_json *json)
{
	if (json == NULL) {
		return cm_json_type_undefined;
	}
	return json->type;
}

struct cm_json *
cm_json_new_null(void *parent)
{
	struct cm_json *json;

	json = talloc_zero(parent, struct cm_json);
	if (json != NULL) {
		json->type = cm_json_type_null;
	}
	return json;
}

struct cm_json *
cm_json_new_string(void *parent, const char *string, ssize_t length)
{
	struct cm_json *json;

	json = talloc_zero(parent, struct cm_json);
	if (json != NULL) {
		json->type = cm_json_type_string;
		if (length < 0) {
			json->s.s = talloc_strdup(json, string);
			json->s.l = strlen(json->s.s);
		} else {
			json->s.s = talloc_size(json, length + 1);
			if (json->s.s != NULL) {
				memcpy(json->s.s, string, length);
				json->s.s[length] = '\0';
			}
			json->s.l = length;
		}
		if (json->s.s == NULL) {
			talloc_free(json);
			json = NULL;
		}
	}
	return json;
}

struct cm_json *
cm_json_new_numberl(void *parent, long long number)
{
	struct cm_json *json;

	json = talloc_zero(parent, struct cm_json);
	if (json != NULL) {
		json->type = cm_json_type_numberl;
		json->l = number;
	}
	return json;
}

struct cm_json *
cm_json_new_numberd(void *parent, long double number)
{
	struct cm_json *json;

	json = talloc_zero(parent, struct cm_json);
	if (json != NULL) {
		json->type = cm_json_type_numberd;
		json->d = number;
	}
	return json;
}

struct cm_json *
cm_json_new_boolean(void *parent, unsigned char value)
{
	struct cm_json *json;

	json = talloc_zero(parent, struct cm_json);
	if (json != NULL) {
		json->type = cm_json_type_boolean;
		json->b = value;
	}
	return json;
}

struct cm_json *
cm_json_new_object(void *parent)
{
	struct cm_json *json;

	json = talloc_zero(parent, struct cm_json);
	if (json != NULL) {
		json->type = cm_json_type_object;
		json->o.n = 0;
		json->o.o = NULL;
	}
	return json;
}

struct cm_json *
cm_json_new_array(void *parent)
{
	struct cm_json *json;

	json = talloc_zero(parent, struct cm_json);
	if (json != NULL) {
		json->type = cm_json_type_array;
		json->a.n = 0;
		json->a.a = NULL;
	}
	return json;
}

const char *
cm_json_string(struct cm_json *json, ssize_t *length)
{
	if (cm_json_type(json) != cm_json_type_string) {
		return NULL;
	}
	if (length != NULL) {
		*length = json->s.l;
	}
	return json->s.s;
}

long double
cm_json_numberd(struct cm_json *json)
{
	if (cm_json_type(json) != cm_json_type_numberd) {
		return -1;
	}
	return json->d;
}

long long
cm_json_numberl(struct cm_json *json)
{
	if (cm_json_type(json) != cm_json_type_numberl) {
		return -1;
	}
	return json->l;
}

unsigned char
cm_json_boolean(struct cm_json *json)
{
	if (cm_json_type(json) != cm_json_type_boolean) {
		return -1;
	}
	return json->b;
}

ssize_t
cm_json_n_keys(struct cm_json *json)
{
	if (cm_json_type(json) != cm_json_type_object) {
		return -1;
	}
	return json->o.n;
}

const char *
cm_json_nth_key(struct cm_json *json, size_t n)
{
	if ((cm_json_type(json) != cm_json_type_object) || (n >= json->o.n)) {
		return NULL;
	}
	return json->o.o[n].key;
}

struct cm_json *
cm_json_nth_val(struct cm_json *json, size_t n)
{
	if ((cm_json_type(json) != cm_json_type_object) || (n >= json->o.n)) {
		return NULL;
	}
	return json->o.o[n].val;
}

ssize_t
cm_json_array_size(struct cm_json *json)
{
	if (cm_json_type(json) != cm_json_type_array) {
		return -1;
	}
	return json->a.n;
}

struct cm_json *
cm_json_n(struct cm_json *json, size_t n)
{
	if ((cm_json_type(json) != cm_json_type_array) || (n >= json->a.n)) {
		return NULL;
	}
	return json->a.a[n];
}

struct cm_json *
cm_json_get(struct cm_json *json, const char *key)
{
	ssize_t n;

	if ((cm_json_type(json) != cm_json_type_object) || (key == NULL)) {
		return NULL;
	}
	for (n = json->o.n - 1; n >= 0; n--) {
		if (strcmp(key, json->o.o[n].key) == 0) {
			return json->o.o[n].val;
		}
	}
	return NULL;
}

int
cm_json_set(struct cm_json *json, const char *key, struct cm_json *value)
{
	struct cm_json_object_rec *recs;
	ssize_t n;

	for (n = json->o.n - 1; n >= 0; n--) {
		if (strcmp(key, json->o.o[n].key) == 0) {
			if (value != NULL) {
				talloc_steal(json, value);
			}
			json->o.o[n].val = value;
			break;
		}
	}
	if (n < 0) {
		n = json->o.n;
		recs = talloc_realloc(json, json->o.o, struct cm_json_object_rec, n + 1);
		if (recs == NULL) {
			return ENOMEM;
		}
		json->o.o = recs;
		recs[n].key = talloc_strdup(json, key);
		if (recs[n].key == NULL) {
			return ENOMEM;
		}
		if (value != NULL) {
			talloc_steal(json, value);
		}
		recs[n].val = value;
		json->o.n = n + 1;
	}
	return 0;
}

int
cm_json_append(struct cm_json *json, struct cm_json *value)
{
	struct cm_json **recs;
	ssize_t n;

	n = json->a.n;
	recs = talloc_realloc(json, json->a.a, struct cm_json *, n + 1);
	if (recs == NULL) {
		return ENOMEM;
	}
	json->a.a = recs;
	talloc_steal(json, value);
	recs[n] = value;
	json->a.n = n + 1;
	return 0;
}

int
cm_json_set_n(struct cm_json *json, size_t n, struct cm_json *value)
{
	struct cm_json **recs;
	size_t size, i;

	if (json->a.n < n + 1) {
		size = n + 1;
		recs = talloc_realloc(json, json->a.a, struct cm_json *, size);
		if (recs == NULL) {
			return ENOMEM;
		}
		json->a.a = recs;
		for (i = json->a.n; i < n; i++) {
			json->a.a[i] = NULL;
		}
		json->a.n = size;
	}
	talloc_steal(json, value);
	json->a.a[n] = value;
	return 0;
}

int
cm_json_utf8_to_point(const char *p, uint32_t *point)
{
	const unsigned char *u;
	uint32_t ret;
	int count, i;
	unsigned char uc;

	u = (const unsigned char *)p;
	uc = *u;
	if ((uc & 0x80) == 0) {
		*point = uc;
		return 1;
	}
	if ((uc & 0x40) == 0) {
		/* sync error: not the first of a utf-8 multibyte character */
		*point = 0;
		return -1;
	}
	count = 0; /* the number of bytes */
	while ((uc & 0x80) != 0) {
		count++;
		uc <<= 1;
	}
	if (count > 6) {
		/* shouldn't happen - code point way too high */
		*point = 0;
		return -5;
	}
	ret = *u & (0xff >> (count + 1));
	for (i = 1; i < count; i++) {
		uc = u[i];
		if (uc == '\0') {
			/* not enough input bytes */
			*point = 0;
			return -3;
		}
		if ((uc & 0xc0) != 0x80) {
			/* sync error: not a subsequent byte */
			*point = 0;
			return -2;
		}
		ret = (ret << 6) | (uc & 0x3f);
	}
	*point = ret;
	return count;
}

static char *
cm_json_escape(void *parent, const char *s, ssize_t l)
{
	char *ret, *q;
	const unsigned char *p;
	unsigned char uc;
	uint32_t uni;
	int esc = 0, n;

	if (l < 0) {
		l = strlen(s);
	}
	for (p = (const unsigned char *) s; (const char *) p < s + l; p++) {
		uc = *p;
		if ((uc < 0x20) || (uc == 0x22) || (uc == 0x5c) || (uc > 0x7f)) {
			esc++;
		}
	}
	ret = talloc_size(parent, l + esc * 12 + 2 + 1);
	if (ret != NULL) {
		q = ret;
		*q++ = '"';
		for (p = (const unsigned char *) s; (const char *) p < s + l; p++) {
			uc = *p;
			switch (uc) {
			case '"':
			case '\\':
				*q++ = '\\';
				*q++ = *p;
				break;
			case '\b':
				*q++ = '\\';
				*q++ = 'b';
				break;
			case '\f':
				*q++ = '\\';
				*q++ = 'f';
				break;
			case '\n':
				*q++ = '\\';
				*q++ = 'n';
				break;
			case '\r':
				*q++ = '\\';
				*q++ = 'r';
				break;
			case '\t':
				*q++ = '\\';
				*q++ = 't';
				break;
			default:
				if ((uc >= 0x20) && (uc < 0x80)) {
					*q++ = *p;
				} else {
					n = cm_json_utf8_to_point((const char *) p, &uni);
					if ((n < 0) || (n > 6)) {
						/* invalid */
						talloc_free(ret);
						return NULL;
					}
					if (uni > 0x10ffff) {
						/* invalid */
						talloc_free(ret);
						return NULL;
					}
					p += n;
					if ((uni < 0xd800) || ((uni >= 0xe000) && (uni <= 0xffff))) {
						sprintf(q, "\\u%04X", uni);
						q += 6;
					} else {
						uni -= 0x10000;
						sprintf(q, "\\u%04X\\u%04X", (uni >> 10) | 0xd800, (uni & 0x3ff) | 0xdc00);
						q += 12;
					}
					p--;
				}
				break;
			}
		}
		*q++ = '"';
		*q = '\0';
	}
	return ret;
}

char *
cm_json_encode(void *parent, struct cm_json *json)
{
	char *ret = NULL, *key, *val;
	size_t i;

	if (json == NULL) {
		return talloc_strdup(parent, "");
	}
	switch (json->type) {
	case cm_json_type_undefined:
		break;
	case cm_json_type_null:
		ret = talloc_strdup(parent, "null");
		break;
	case cm_json_type_string:
		ret = cm_json_escape(ret, json->s.s, json->s.l);
		break;
	case cm_json_type_numberl:
		ret = talloc_asprintf(parent, "%lld", json->l);
		break;
	case cm_json_type_numberd:
		ret = talloc_asprintf(parent, "%Lf", json->d);
		break;
	case cm_json_type_boolean:
		ret = talloc_strdup(parent, json->b ? "true" : "false");
		break;
	case cm_json_type_object:
		ret = talloc_strdup(parent, "{");
		for (i = 0; i < json->o.n; i++) {
			if ((json->o.o[i].key == NULL) ||
			    (json->o.o[i].val == NULL)) {
				continue;
			}
			key = cm_json_escape(ret, json->o.o[i].key, -1);
			val = cm_json_encode(ret, json->o.o[i].val);
			if ((key == NULL) || (val == NULL)) {
				talloc_free(ret);
				ret = NULL;
				break;
			} else {
				ret = talloc_asprintf_append(ret, "%s%s:%s",
							     i > 0 ? "," : "",
							     key, val);
				talloc_free(key);
				talloc_free(val);
			}
		}
		ret = talloc_strdup_append(ret, "}");
		break;
	case cm_json_type_array:
		ret = talloc_strdup(parent, "[");
		for (i = 0; i < json->a.n; i++) {
			val = cm_json_encode(ret, json->a.a[i]);
			if (val == NULL) {
				talloc_free(ret);
				ret = NULL;
				break;
			} else {
				ret = talloc_asprintf_append(ret, "%s%s",
							     i > 0 ? "," : "",
							     val);
				talloc_free(val);
			}
		}
		ret = talloc_strdup_append(ret, "]");
		break;
	}
	return ret;
}

int
cm_json_point_to_utf8_length(uint32_t point)
{
	int ret;

	if (point < 0x80) {
		return 1;
	}
	if ((point >= 0xd800) && (point <= 0xdfff)){
		return -1;
	}
	ret = 2;
	point >>= 11;
	while (point != 0) {
		ret++;
		point >>= 5;
	}
	return ret;
}

int
cm_json_point_to_utf8(uint32_t point, char *out, ssize_t max)
{
	int count, i;
	unsigned char final;

	count = cm_json_point_to_utf8_length(point);
	if ((count < 0) || (count > max)) {
		return -1;
	}
	if (point < 0x80) {
		*out = (point & 0x7f);
		return 1;
	}
	final = 0x80;
	for (i = 0; i < count - 1; i++) {
		out[count - i - 1] = 0x80 | (point & 0x3f);
		point >>= 6;
		final = (final >> 1) | 0x80;
	}
	*out = final | (point & 0x3f);
	return count;
}

static char *
cm_json_decode_string(void *parent, const char *s, ssize_t length,
		      const char **next, ssize_t *out_length)
{
	char *ret = NULL, *q, *end;
	const char *p, *hex, *hexchars = "00112233445566778899AaBbCcDdEeFf", *psave;
	int unesc = 0, i, closed = 0;
	uint32_t point, point2;

	if (out_length != NULL) {
		*out_length = 0;
	}
	*next = s;
	if (*s != '"') {
		return NULL;
	}
	s++;
	length--;
	for (p = s; p < s + length; p++) {
		switch (*p) {
		case '"':
			length = p - s;
			*next = s + length + 1;
			closed++;
			break;
		case '\\':
			psave = p;
			p++;
			switch (*p) {
			case 'u':
				p++;
				point = 0;
				for (i = 0; i < 4; i++) {
					hex = strchr(hexchars, *p);
					if (hex == NULL) {
						break;
					}
					point = (point << 4) | ((hex - hexchars) / 2);
					p++;
				}
				if ((point >= 0xd800) && (point < 0xdc000) &&
				    (p + 2 < s + length) &&
				    (p[0] == '\\') && (p[1] == 'u')) {
					psave = p;
					p += 2;
					point2 = 0;
					for (i = 0; (i < 4) && (p + 2 + i < s + length); i++) {
						hex = strchr(hexchars, *p);
						if (hex == NULL) {
							break;
						}
						point2 = (point2 << 4) | ((hex - hexchars) / 2);
						p++;
					}
					if ((point >= 0xd800) && (point < 0xdc00) &&
					    (point2 >= 0xdc00) && (point2 <= 0xdcff)) {
						point = ((point & 0x3ff) << 10) | (point2 & 0x3ff);
						point += 0x10000;
					} else {
						p = psave;
					}
				}
				i = cm_json_point_to_utf8_length(point);
				if (i < 0) {
					*next = psave;
					return NULL;
				}
				unesc += i;
				p--;
				break;
			default:
				unesc++;
				break;
			}
			break;
		default:
			unesc++;
			break;
		}
	}
	if (!closed) {
		*next = p;
		return NULL;
	}
	ret = talloc_size(parent, unesc + 1);
	end = ret + unesc + 1;
	for (p = s, q = ret; p < s + length; p++) {
		switch (*p) {
		case '\\':
			psave = p;
			p++;
			switch (*p) {
			case 'u':
				p++;
				point = 0;
				for (i = 0; i < 4; i++) {
					hex = strchr(hexchars, *p);
					if (hex == NULL) {
						break;
					}
					point = (point << 4) | ((hex - hexchars) / 2);
					p++;
				}
				if ((point >= 0xd800) && (point < 0xdc00) &&
				    (p + 2 < s + length) &&
				    (p[0] == '\\') && (p[1] == 'u')) {
					psave = p;
					p += 2;
					point2 = 0;
					for (i = 0; (i < 4) && (p + 2 + i < s + length); i++) {
						hex = strchr(hexchars, *p);
						if (hex == NULL) {
							break;
						}
						point2 = (point2 << 4) | ((hex - hexchars) / 2);
						p++;
					}
					if ((point >= 0xd800) && (point < 0xdc00) &&
					    (point2 >= 0xdc00) && (point2 <= 0xdcff)) {
						point = ((point & 0x3ff) << 10) | (point2 & 0x3ff);
						point += 0x10000;
					} else {
						p = psave;
					}
				}
				i = cm_json_point_to_utf8(point, q, end - q);
				if (i < 0) {
					*next = psave;
					return NULL;
				}
				q += i;
				p--;
				break;
			case 'b':
				*q++ = '\b';
				break;
			case 'f':
				*q++ = '\f';
				break;
			case 'n':
				*q++ = '\n';
				break;
			case 'r':
				*q++ = '\r';
				break;
			case 't':
				*q++ = '\t';
				break;
			default:
				*q++ = *p;
				break;
			}
			break;
		default:
			*q++ = *p;
			break;
		}
	}
	*q = '\0';
	if (out_length != NULL) {
		*out_length = q - ret;
	}
	return ret;
}

static long double
my_strtold(const char *nptr, char **endptr)
{
#if HAVE_DECL_STRTOLD
	return strtold(nptr, endptr);
#else
	return strtod(nptr, endptr);
#endif
}

int
cm_json_decode(void *parent, const char *encoded, ssize_t length,
	       struct cm_json **json, const char **next)
{
	int ret = 0;
	const char *p, *q, *nextp;
	char *s = NULL, *tmp;
	struct cm_json *agg = NULL, *sub = NULL;
	enum cm_json_type aggtype;
	ssize_t slength;
	enum {key, keyorclose, colon, commaorclose, expr, exprorclose} expect = expr;

	p = encoded;
	if (next == NULL) {
		next = &nextp;
	}
	*next = p;
	if (length == -1) {
		length = strlen(encoded);
	}
	aggtype = cm_json_type_undefined;
	*json = NULL;
	while ((p < encoded + length) && (*json == NULL)) {
		switch (*p) {
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			p++;
			continue;
			break;
		case '[':
			switch (expect) {
			case key:
			case keyorclose:
			case colon:
			case commaorclose:
				goto done;
				break;
			case expr:
			case exprorclose:
				break;
			}
			if (aggtype != cm_json_type_undefined) {
				/* This is an array item in an aggregate. */
				ret = cm_json_decode(parent, p, length - (p - encoded), &sub, &p);
				if (ret != 0) {
					goto done;
				}
				expect = commaorclose;
			} else {
				/* This level is an array. */
				aggtype = cm_json_type_array;
				agg = cm_json_new_array(parent);
				p++;
				expect = exprorclose;
			}
			break;
		case ']':
			switch (expect) {
			case key:
			case colon:
			case expr:
				goto done;
				break;
			case keyorclose:
			case exprorclose:
			case commaorclose:
				break;
			}
			if (aggtype != cm_json_type_array) {
				/* Not expecting an array close. */
				goto done;
			}
			if (sub != NULL) {
				ret = cm_json_append(agg, sub);
				sub = NULL;
			}
			*json = agg;
			p++;
			break;
		case '{':
			switch (expect) {
			case keyorclose:
			case key:
			case colon:
			case commaorclose:
				goto done;
				break;
			case exprorclose:
			case expr:
				break;
			}
			if (aggtype != cm_json_type_undefined) {
				/* This is an object item in an aggregate. */
				ret = cm_json_decode(parent, p, length - (p - encoded), &sub, &p);
				if (ret != 0) {
					goto done;
				}
				expect = commaorclose;
			} else {
				/* This level is an object. */
				aggtype = cm_json_type_object;
				agg = cm_json_new_object(parent);
				expect = keyorclose;
				p++;
			}
			break;
		case '}':
			switch (expect) {
			case key:
			case colon:
			case expr:
				goto done;
				break;
			case keyorclose:
			case exprorclose:
			case commaorclose:
				break;
			}
			if (aggtype != cm_json_type_object) {
				goto done;
			}
			if ((s != NULL) && (sub != NULL)) {
				ret = cm_json_set(agg, s, sub);
			}
			talloc_free(s);
			s = NULL;
			sub = NULL;
			*json = agg;
			p++;
			break;
		case ',':
			switch (expect) {
			case key:
			case colon:
			case expr:
			case keyorclose:
			case exprorclose:
				goto done;
				break;
			case commaorclose:
				break;
			}
			if (aggtype == cm_json_type_object) {
				if ((s == NULL) || (sub == NULL)) {
					goto done;
				}
				ret = cm_json_set(agg, s, sub);
				talloc_free(s);
				s = NULL;
				sub = NULL;
				expect = key;
			} else
			if (aggtype == cm_json_type_array) {
				if (sub == NULL) {
					goto done;
				}
				ret = cm_json_append(agg, sub);
				sub = NULL;
				expect = expr;
			} else {
				goto done;
			}
			p++;
			break;
		case ':':
			switch (expect) {
			case colon:
				break;
			case keyorclose:
			case key:
			case exprorclose:
			case expr:
			case commaorclose:
				goto done;
				break;
			}
			if (aggtype != cm_json_type_object) {
				goto done;
			}
			expect = expr;
			p++;
			break;
		case '"':
			switch (expect) {
			case colon:
			case commaorclose:
				goto done;
				break;
			case keyorclose:
			case key:
			case exprorclose:
			case expr:
				break;
			}
			if (aggtype == cm_json_type_undefined) {
				/* This level is a string. */
				if (s != NULL) {
					goto done;
				}
				s = cm_json_decode_string(parent, p, length - (p - encoded), &p, &slength);
				if (s == NULL) {
					goto done;
				}
				*json = cm_json_new_string(parent, s, slength);
				talloc_free(s);
				s = NULL;
			} else {
				tmp = cm_json_decode_string(parent, p, length - (p - encoded), &p, &slength);
				if (tmp == NULL) {
					goto done;
				}
				if ((expect == key) || (expect == keyorclose)) {
					/* It's a key in an object. */
					s = tmp;
					expect = colon;
				} else {
					/* It's a value in an object or array. */
					sub = cm_json_new_string(parent, tmp, slength);
					talloc_free(tmp);
					tmp = NULL;
					expect = commaorclose;
				}
			}
			break;
		default:
			switch (expect) {
			case keyorclose:
			case key:
			case colon:
			case commaorclose:
				goto done;
				break;
			case exprorclose:
			case expr:
				break;
			}
			if (sub != NULL) {
				goto done;
			}
			if ((length - (p - encoded) >= 4) &&
			    (memcmp(p, "null", 4) == 0)) {
				sub = cm_json_new_null(parent);
				p += 4;
			} else
			if ((length - (p - encoded) >= 4) &&
			    (memcmp(p, "true", 4) == 0)) {
				sub = cm_json_new_boolean(parent, 1);
				p += 4;
			} else
			if ((length - (p - encoded) >= 5) &&
			    (memcmp(p, "false", 4) == 0)) {
				sub = cm_json_new_boolean(parent, 0);
				p += 5;
			} else
			if (strchr("0123456789+-", *p) != NULL) {
				q = p + 1;
				while ((q < encoded + length) &&
				       (strchr("0123456789+-Ee.", *q) != NULL)) {
					q++;
				}
				tmp = talloc_strndup(parent, p, q - p);
				if (tmp == NULL) {
					ret = ENOMEM;
					goto done;
				}
				if (strcspn(tmp, "Ee.") == strlen(tmp)) {
					sub = cm_json_new_numberl(parent, strtoll(tmp, NULL, 10));
				} else {
					sub = cm_json_new_numberd(parent, my_strtold(tmp, NULL));
				}
				talloc_free(tmp);
				if (sub == NULL) {
					ret = ENOMEM;
					goto done;
				}
				p = q;
			} else {
				/* Doesn't look like a valid token. */
				goto done;
			}
			if (aggtype == cm_json_type_undefined) {
				/* This level is a simple item. */
				*json = sub;
			} else {
				expect = commaorclose;
			}
			break;
		}
	}
done:
	while ((p < encoded + length) &&
	       (strchr(" \t\r\n", *p) != NULL)) {
		p++;
	}
	*next = p;
	if ((*json == NULL) && (ret == 0)) {
		switch (expect) {
		case keyorclose:
			ret = CM_JSON_EXPECTED_KEY_OR_CLOSE;
			break;
		case key:
			ret = CM_JSON_EXPECTED_KEY;
			break;
		case colon:
			ret = CM_JSON_EXPECTED_COLON;
			break;
		case commaorclose:
			ret = CM_JSON_EXPECTED_COMMA_OR_CLOSE;
			break;
		case exprorclose:
			ret = CM_JSON_EXPECTED_EXPRESSION_OR_CLOSE;
			break;
		case expr:
			ret = CM_JSON_EXPECTED_EXPRESSION;
			break;
		}
	}
	return ret;
}

const char *
cm_json_decode_strerror(int error)
{
	switch (error) {
	case CM_JSON_EXPECTED_KEY_OR_CLOSE:
		return "expected an object key or close ('}')";
		break;
	case CM_JSON_EXPECTED_KEY:
		return "expected an object key";
		break;
	case CM_JSON_EXPECTED_COLON:
		return "expected a colon (':')";
		break;
	case CM_JSON_EXPECTED_COMMA_OR_CLOSE:
		return "expected a comma or close ('}' or ']')";
		break;
	case CM_JSON_EXPECTED_EXPRESSION_OR_CLOSE:
		return "expected an expression or close ('}' or ']')";
		break;
	case CM_JSON_EXPECTED_EXPRESSION:
		return "expected an expression";
		break;
	}
	return "unknown error";
}

struct cm_json *
cm_json_find(struct cm_json *json, const char *path)
{
	const char *p, *q;
	char *component, *end;
	long l;
	struct cm_json *this = json;

	while ((*path != '\0') && (this != NULL)) {
		while (*path == '/') {
			path++;
		}
		p = path;
		q = p + strcspn(p, "/");
		if (p == q) {
			break;
		}
		path = q;
		component = talloc_strndup(json, p, q - p);
		if (this->type == cm_json_type_object) {
			this = cm_json_get(this, component);
			talloc_free(component);
			continue;
		}
		if (this->type == cm_json_type_array) {
			end = component;
			l = strtol(component, &end, 10);
			if ((end == NULL) || ((*end != '/') && (*end != '\0')) || (l < 0)) {
				this = NULL;
				talloc_free(component);
				continue;
			}
			this = cm_json_n(this, l);
			talloc_free(component);
			continue;
		}
		this = NULL;
	}
	return this;
}
