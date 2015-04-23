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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>

#include <tevent.h>

#include <popt.h>

#include "tdbus.h"
#include "tdbusm.h"

static const dbus_bool_t b = TRUE;
static const long n = 12345, n1 = 23456, n2 = 34567;
static char s[] = "This is a string.";
static char s1[] = "This is a first string.";
static char s2[] = "This is a second string.";
static char s3[] = "This is a third string.";
static char s4[] = "This is a fourth string.";
static char p[] = "/this/is/a/path/to/an/object";
static const char *as[] = {"This", "is", "a", "string", "array.", NULL};
static const char *ap[] = {"/this", "/is", "/a", "/path", "/array", NULL};
static const char *as1[] = {"This", "is", "a", "first", "string", "array.",
			    NULL};
static const char *as2[] = {"This", "is", "a", "second", "string", "array.",
			    NULL};
static const char *as3[] = {"This", "is", "a", "third", "string", "array.",
			    NULL};
static const char *as4[] = {"This", "is", "a", "fourth", "string", "array.",
			    NULL};
static const char *ass[] = {"This", "is", "a", "string", "array.", NULL};
static struct cm_tdbusm_dict d0 = {
	.key = "key 0",
	.value_type = cm_tdbusm_dict_b,
	.value.b = TRUE,
};
static struct cm_tdbusm_dict d1 = {
	.key = "key 1",
	.value_type = cm_tdbusm_dict_n,
	.value.n = 12345,
};
static struct cm_tdbusm_dict d2 = {
	.key = "key 2",
	.value_type = cm_tdbusm_dict_s,
	.value.s = "this is a string value",
};
static struct cm_tdbusm_dict d3 = {
	.key = "key 3",
	.value_type = cm_tdbusm_dict_as,
	.value.as = (char **) as,
};
static struct cm_tdbusm_dict d4 = {
	.key = "key 4",
	.value_type = cm_tdbusm_dict_ass,
	.value.as = (char **) ass,
};
static const struct cm_tdbusm_dict *dsub[] = {&d0, &d1, NULL};
static struct cm_tdbusm_dict d5 = {
	.key = "key 5",
	.value_type = cm_tdbusm_dict_d,
	.value.d = dsub,
};
static const struct cm_tdbusm_dict *d[] = {&d0, &d1, &d2, &d3, &d4, &d5, NULL};

static int
set_b(DBusMessage *msg)
{
	return cm_tdbusm_set_b(msg, b);
}
static int
set_n(DBusMessage *msg)
{
	return cm_tdbusm_set_n(msg, n);
}
static int
set_p(DBusMessage *msg)
{
	return cm_tdbusm_set_p(msg, p);
}
static int
set_s(DBusMessage *msg)
{
	return cm_tdbusm_set_s(msg, s);
}
static int
set_bp(DBusMessage *msg)
{
	return cm_tdbusm_set_bp(msg, b, p);
}
static int
set_bs(DBusMessage *msg)
{
	return cm_tdbusm_set_bs(msg, b, s);
}
static int
set_sb(DBusMessage *msg)
{
	return cm_tdbusm_set_sb(msg, s, b);
}
static int
set_sn(DBusMessage *msg)
{
	return cm_tdbusm_set_sn(msg, s, n);
}
static int
set_ss(DBusMessage *msg)
{
	return cm_tdbusm_set_ss(msg, s1, s2);
}
static int
set_ssb(DBusMessage *msg)
{
	return cm_tdbusm_set_ssb(msg, s1, s2, b);
}
static int
set_ssn(DBusMessage *msg)
{
	return cm_tdbusm_set_ssn(msg, s1, s2, n);
}
static int
set_ap(DBusMessage *msg)
{
	return cm_tdbusm_set_ap(msg, ap);
}
static int
set_as(DBusMessage *msg)
{
	return cm_tdbusm_set_as(msg, as);
}
static int
set_ass(DBusMessage *msg)
{
	return cm_tdbusm_set_ass(msg, ass);
}
static int
set_sss(DBusMessage *msg)
{
	return cm_tdbusm_set_sss(msg, s1, s2, s3);
}
static int
set_ssvs(DBusMessage *msg)
{
	return cm_tdbusm_set_ssvs(msg, s1, s2, s3);
}
static int
set_ssas(DBusMessage *msg)
{
	return cm_tdbusm_set_ssas(msg, s1, s2, as);
}
static int
set_ssss(DBusMessage *msg)
{
	return cm_tdbusm_set_ssss(msg, s1, s2, s3, s4);
}
static int
set_ssoas(DBusMessage *msg)
{
	return cm_tdbusm_set_ssoas(msg, s1, s2, as);
}
static int
set_sssas(DBusMessage *msg)
{
	return cm_tdbusm_set_sssas(msg, s1, s2, s3, as);
}
static int
set_sssnasasasnas(DBusMessage *msg)
{
	return cm_tdbusm_set_sssnasasasnas(msg, s1, s2, s3, n1,
					   as1, as2, as3, n2, as4);
}
static int
set_sasasasnas(DBusMessage *msg)
{
	return cm_tdbusm_set_sasasasnas(msg, s, as1, as2, as3, n, as4);
}
static int
set_d(DBusMessage *msg)
{
	return cm_tdbusm_set_d(msg, d);
}
static int
set_sd(DBusMessage *msg)
{
	return cm_tdbusm_set_sd(msg, s, d);
}
static int
set_ssass(DBusMessage *msg)
{
	return cm_tdbusm_set_ssass(msg, s1, s2, ass);
}
static int
get_b(DBusMessage *rep, int msgid)
{
	int ret;
	dbus_bool_t b;
	ret = cm_tdbusm_get_b(rep, NULL, &b);
	if (ret == 0) {
		printf("Message %d - b:%s\n", msgid, b ? "TRUE" : "FALSE");
	}
	return ret;
}
static int
get_n(DBusMessage *rep, int msgid)
{
	int ret;
	long n;
	ret = cm_tdbusm_get_n(rep, NULL, &n);
	if (ret == 0) {
		printf("Message %d - n:%ld\n", msgid, n);
	}
	return ret;
}
static int
get_p(DBusMessage *rep, int msgid)
{
	int ret;
	char *p;
	ret = cm_tdbusm_get_p(rep, NULL, &p);
	if (ret == 0) {
		printf("Message %d - p:%s\n", msgid, p);
	}
	return ret;
}
static int
get_s(DBusMessage *rep, int msgid)
{
	int ret;
	char *s;
	ret = cm_tdbusm_get_s(rep, NULL, &s);
	if (ret == 0) {
		printf("Message %d - s:%s\n", msgid, s);
	}
	return ret;
}
static int
get_bp(DBusMessage *rep, int msgid)
{
	dbus_bool_t b;
	int ret;
	char *p;
	ret = cm_tdbusm_get_bp(rep, NULL, &b, &p);
	if (ret == 0) {
		printf("Message %d - b:%s,p:%s\n", msgid,
		       b ? "TRUE" : "FALSE", p);
	}
	return ret;
}
static int
get_bs(DBusMessage *rep, int msgid)
{
	dbus_bool_t b;
	int ret;
	char *s;
	ret = cm_tdbusm_get_bs(rep, NULL, &b, &s);
	if (ret == 0) {
		printf("Message %d - b:%s,s:%s\n", msgid,
		       b ? "TRUE" : "FALSE", s);
	}
	return ret;
}
static int
get_sb(DBusMessage *rep, int msgid)
{
	dbus_bool_t b;
	int ret;
	char *s;
	ret = cm_tdbusm_get_sb(rep, NULL, &s, &b);
	if (ret == 0) {
		printf("Message %d - s:%s,b:%s\n", msgid, s,
		       b ? "TRUE" : "FALSE");
	}
	return ret;
}
static int
get_sn(DBusMessage *rep, int msgid)
{
	int ret;
	long n;
	char *s;
	ret = cm_tdbusm_get_sn(rep, NULL, &s, &n);
	if (ret == 0) {
		printf("Message %d - s:%s,n:%ld\n", msgid, s, n);
	}
	return ret;
}
static int
get_ss(DBusMessage *rep, int msgid)
{
	int ret;
	char *s1, *s2;
	ret = cm_tdbusm_get_ss(rep, NULL, &s1, &s2);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s\n", msgid, s1, s2);
	}
	return ret;
}
static int
get_ap(DBusMessage *rep, int msgid)
{
	int ret, i;
	char **ap;
	ret = cm_tdbusm_get_ap(rep, NULL, &ap);
	if (ret == 0) {
		printf("Message %d - [", msgid);
		for (i = 0; (ap != NULL) && (ap[i] != NULL); i++) {
			printf("%sp:%s", i > 0 ? "," : "", ap[i]);
		}
		printf("]\n");
	}
	return ret;
}
static int
get_as(DBusMessage *rep, int msgid)
{
	int ret, i;
	char **as;

	ret = cm_tdbusm_get_as(rep, NULL, &as);
	if (ret == 0) {
		printf("Message %d - [", msgid);
		for (i = 0; (as != NULL) && (as[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as[i]);
		}
		printf("]\n");
	}
	return ret;
}
static int
get_ass(DBusMessage *rep, int msgid)
{
	int ret, i;
	char **ass = NULL;

	ret = cm_tdbusm_get_ass(rep, NULL, &ass);
	if (ret == 0) {
		printf("Message %d - [", msgid);
		for (i = 0;
		     (ass != NULL) && (ass[i] != NULL) && (ass[i + 1] != NULL);
		     i += 2) {
			printf("%s(%s,%s)", i > 0 ? "," : "", ass[i],
			       ass[i + 1]);
		}
		printf("]\n");
	}
	return ret;
}
static int
get_sss(DBusMessage *rep, int msgid)
{
	int ret;
	char *s1, *s2, *s3;

	ret = cm_tdbusm_get_sss(rep, NULL, &s1, &s2, &s3);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s,s:%s\n", msgid,
		       s1, s2, s3);
	}
	return ret;
}
static int
get_ssvs(DBusMessage *rep, int msgid)
{
	int ret;
	char *s1, *s2;
	enum cm_tdbusm_dict_value_type type;
	union cm_tdbusm_variant value;

	memset(&value, 0, sizeof(value));
	ret = cm_tdbusm_get_ssv(rep, NULL, &s1, &s2, &type, &value);
	if (ret == 0) {
		if (type == cm_tdbusm_dict_s) {
			printf("Message %d - s:%s,s:%s,s:%s\n", msgid,
			       s1, s2, value.s);
		}
	}
	return ret;
}
static int
get_ssb(DBusMessage *rep, int msgid)
{
	int ret;
	char *s1, *s2;
	dbus_bool_t b;
	ret = cm_tdbusm_get_ssb(rep, NULL, &s1, &s2, &b);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s,b:%s\n", msgid,
		       s1, s2, b ? "TRUE" : "FALSE");
	}
	return ret;
}
static int
get_ssn(DBusMessage *rep, int msgid)
{
	int ret;
	char *s1, *s2;
	long n;
	ret = cm_tdbusm_get_ssn(rep, NULL, &s1, &s2, &n);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s,n:%ld\n", msgid,
		       s1, s2, n);
	}
	return ret;
}
static int
get_ssas(DBusMessage *rep, int msgid)
{
	int ret, i;
	char *s1, *s2, **as;
	ret = cm_tdbusm_get_ssas(rep, NULL, &s1, &s2, &as);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s,as:[", msgid, s1, s2);
		for (i = 0; (as != NULL) && (as[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as[i]);
		}
		printf("]\n");
	}
	return ret;
}
static int
get_ssss(DBusMessage *rep, int msgid)
{
	int ret;
	char *s1, *s2, *s3, *s4;

	ret = cm_tdbusm_get_ssss(rep, NULL, &s1, &s2, &s3, &s4);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%ss:%s,s:%s\n", msgid,
		       s1, s2, s3, s4);
	}
	return ret;
}
static int
get_ssosos(DBusMessage *rep, int msgid)
{
	int ret;
	char *s1, *s2, *s3, *s4;
	ret = cm_tdbusm_get_ssosos(rep, NULL, &s1, &s2, &s3, &s4);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%ss:%ss:%s\n", msgid,
		       s1, s2, s3 ? s3 : "(NULL)", s4 ? s4 : "(NULL)");
	}
	return ret;
}
static int
get_sososos(DBusMessage *rep, int msgid)
{
	int ret;
	char *s1, *s2, *s3, *s4;
	ret = cm_tdbusm_get_sososos(rep, NULL, &s1, &s2, &s3, &s4);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%ss:%s,s:%s\n", msgid,
		       s1, s2 ? s2 : "(NULL)",
		       s3 ? s3 : "(NULL)", s4 ? s4 : "(NULL)");
	}
	return ret;
}
static int
get_ssoas(DBusMessage *rep, int msgid)
{
	int ret, i;
	char *s1, *s2, **as;
	ret = cm_tdbusm_get_ssoas(rep, NULL, &s1, &s2, &as);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s,[", msgid, s1, s2);
		for (i = 0; (as != NULL) && (as[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as[i]);
		}
		printf("]\n");
	}
	return ret;
}
static int
get_sssas(DBusMessage *rep, int msgid)
{
	int ret, i;
	char *s1, *s2, *s3, **as;

	ret = cm_tdbusm_get_sssas(rep, NULL, &s1, &s2, &s3, &as);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s,s:%s,[", msgid, s1, s2, s3);
		for (i = 0; (as != NULL) && (as[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as[i]);
		}
		printf("]\n");
	}
	return ret;
}
static int
get_sssnasasasnas(DBusMessage *rep, int msgid)
{
	int ret, i;
	long n1, n2;
	char *s1, *s2, *s3, **as1, **as2, **as3, **as4;

	ret = cm_tdbusm_get_sssnasasasnas(rep, NULL,
					  &s1, &s2, &s3, &n1,
					  &as1, &as2, &as3, &n2, &as4);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s,s:%s," "n:%ld,[",
		       msgid, s1, s2, s3, n1);
		for (i = 0; (as1 != NULL) && (as1[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as1[i]);
		}
		printf("],[");
		for (i = 0; (as2 != NULL) && (as2[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as2[i]);
		}
		printf("],[");
		for (i = 0; (as3 != NULL) && (as3[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as3[i]);
		}
		printf("],n:%ld,[", n2);
		for (i = 0; (as4 != NULL) && (as4[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as4[i]);
		}
		printf("]\n");
	}
	return ret;
}
static int
get_sasasasnas(DBusMessage *rep, int msgid)
{
	int ret, i;
	long n;
	char *s, **as1, **as2, **as3, **as4;
	ret = cm_tdbusm_get_sasasasnas(rep, NULL, &s,
				       &as1, &as2, &as3,
				       &n, &as4);
	if (ret == 0) {
		printf("Message %d - s:%s,[", msgid, s);
		for (i = 0; (as1 != NULL) && (as1[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as1[i]);
		}
		printf("],[");
		for (i = 0; (as2 != NULL) && (as2[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as2[i]);
		}
		printf("],[");
		for (i = 0; (as3 != NULL) && (as3[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as3[i]);
		}
		printf("],n:%ld,[", n);
		for (i = 0; (as4 != NULL) && (as4[i] != NULL); i++) {
			printf("%ss:%s", i > 0 ? "," : "", as4[i]);
		}
		printf("]\n");
	}
	return ret;
}
static int
print_d(DBusMessage *rep, const struct cm_tdbusm_dict **d)
{
	int i, k;

	for (i = 0; (d != NULL) && (d[i] != NULL); i++) {
		printf("%s{%s=", i > 0 ? "," : "", d[i]->key);
		switch (d[i]->value_type) {
		case cm_tdbusm_dict_invalid:
			printf("(invalid)}");
			break;
		case cm_tdbusm_dict_s:
			printf("s:%s}", d[i]->value.s);
			break;
		case cm_tdbusm_dict_p:
			printf("p:%s}", d[i]->value.s);
			break;
		case cm_tdbusm_dict_as:
			printf("as:[");
			for (k = 0;
			     (d[i]->value.as != NULL) &&
			     (d[i]->value.as[k] != NULL);
			     k++) {
				printf("%s%s", k > 0 ? "," : "",
				       d[i]->value.as[k]);
			}
			printf("]");
			break;
		case cm_tdbusm_dict_ass:
			printf("ass:[");
			for (k = 0;
			     (d[i]->value.ass != NULL) &&
			     (d[i]->value.ass[k] != NULL) &&
			     (d[i]->value.ass[k + 1] != NULL);
			     k += 2) {
				printf("%s(%s,%s)", k > 0 ? "," : "",
				       d[i]->value.ass[k],
				       d[i]->value.ass[k + 1]);
			}
			printf("]");
			break;
		case cm_tdbusm_dict_n:
			printf("n:%ld}", d[i]->value.n);
			break;
		case cm_tdbusm_dict_b:
			printf("b:%s}",
			       d[i]->value.b ? "TRUE" : "FALSE");
			break;
		case cm_tdbusm_dict_d:
			printf("d:[");
			print_d(rep, d[i]->value.d);
			printf("]");
			break;
		}
	}
	return i;
}
static int
get_d(DBusMessage *rep, int msgid)
{
	int ret;
	struct cm_tdbusm_dict **d;

	ret = cm_tdbusm_get_d(rep, NULL, &d);
	if (ret == 0) {
		printf("Message %d - [", msgid);
		print_d(rep, (const struct cm_tdbusm_dict **) d);
		printf("]\n");
	}
	return ret;
}
static int
get_sd(DBusMessage *rep, int msgid)
{
	int ret;
	struct cm_tdbusm_dict **d;
	char *s;

	ret = cm_tdbusm_get_sd(rep, NULL, &s, &d);
	if (ret == 0) {
		printf("Message %d - s:%s,[", msgid, s);
		print_d(rep, (const struct cm_tdbusm_dict **) d);
		printf("]\n");
	}
	return ret;
}
static int
get_ssass(DBusMessage *rep, int msgid)
{
	int ret, i;
	char *s1, *s2, **ass;

	ret = cm_tdbusm_get_ssass(rep, NULL, &s1, &s2, &ass);
	if (ret == 0) {
		printf("Message %d - s:%s,s:%s,", msgid, s1, s2);
		printf("ass:[");
		for (i = 0; (ass[i] != NULL) && (ass[i + 1] != NULL); i += 2) {
			printf("%s(%s,%s)", i > 0 ? "," : "",
			       ass[i], ass[i + 1]);
		}
		printf("]\n");
	}
	return ret;
}

int
main(int argc, const char **argv)
{
	DBusConnection *conn;
	DBusMessage *msg;
	DBusError err;
	DBusBusType bus = DBUS_BUS_SESSION;
	int c, ret;
	unsigned int i;
	const struct {
		int (*set)(DBusMessage *);
		int (*get)(DBusMessage *, int);
	} tests[] = {
		{&set_b, &get_b},
		{&set_n, &get_n},
		{&set_p, &get_p},
		{&set_s, &get_s},
		{&set_bp, &get_bp},
		{&set_bs, &get_bs},
		{&set_sb, &get_sb},
		{&set_sn, &get_sn},
		{&set_ss, &get_ss},
		{&set_ap, &get_ap},
		{&set_as, &get_as},
		{&set_sss, &get_sss},
		{&set_ssn, &get_ssn},
		{&set_ssb, &get_ssb},
		{&set_ssas, &get_ssas},
		{&set_ssss, &get_ssss},
		{&set_ss, &get_ssosos},
		{&set_sss, &get_ssosos},
		{&set_ssss, &get_ssosos},
		{&set_s, &get_sososos},
		{&set_ss, &get_sososos},
		{&set_sss, &get_sososos},
		{&set_ssss, &get_sososos},
		{&set_ssoas, &get_ssoas},
		{&set_sssas, &get_sssas},
		{&set_sssnasasasnas, &get_sssnasasasnas},
		{&set_sasasasnas, &get_sasasasnas},
		{&set_ass, &get_ass},
		{&set_d, &get_d},
		{&set_sd, &get_sd},
		{&set_ssass, &get_ssass},
		{&set_ssvs, &get_ssvs},
	};
	poptContext pctx;
	struct poptOption popts[] = {
		{"session", 's', POPT_ARG_NONE, NULL, 's', NULL, NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};
	memset(&err, 0, sizeof(err));
	pctx = poptGetContext("tdbusm-check", argc, argv, popts, 0);
	if (pctx == NULL) {
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 's':
			bus = DBUS_BUS_SESSION;
			break;
		case 'S':
			bus = DBUS_BUS_SYSTEM;
			break;
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return 1;
	}
	conn = dbus_bus_get(bus, NULL);
	if (conn == NULL) {
		printf("Error connecting to bus!\n");
		return 1;
	}
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		msg = dbus_message_new_method_call(CM_DBUS_NAME,
						   CM_DBUS_BASE_PATH,
						   CM_DBUS_BASE_INTERFACE,
						   "echo");
		if (msg == NULL) {
			continue;
		}
		ret = (*(tests[i].set))(msg);
		if (ret != 0) {
			printf("Error encoding parameters for message %u.\n",
			       i);
			continue;
		}
		ret = (*(tests[i].get))(msg, i);
		if (ret != 0) {
			printf("Error parsing parameters in message %u.\n", i);
		}
	}
	return 0;
}
