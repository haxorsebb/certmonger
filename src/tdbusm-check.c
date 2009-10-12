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
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>

#include <tevent.h>

#include "tdbus.h"
#include "tdbusm.h"

static dbus_bool_t b = TRUE;
static long n = 12345;
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
static const struct cm_tdbusm_dict *d[] = {&d0, &d1, &d2, &d3, NULL};

int
main(int argc, char **argv)
{
	DBusConnection *conn;
	DBusMessage *msg, *rep;
	DBusError err;
	DBusBusType bus = DBUS_BUS_SESSION;
	int i, c, ret;
	memset(&err, 0, sizeof(err));
	while ((c = getopt(argc, argv, "sS")) != -1) {
		switch (c) {
		case 's':
			bus = DBUS_BUS_SESSION;
			break;
		case 'S':
			bus = DBUS_BUS_SYSTEM;
			break;
		}
	}
	conn = dbus_bus_get(bus, NULL);
	if (conn == NULL) {
		printf("Error connecting to bus!\n");
		return 1;
	}
	for (i = 0; i < 16; i++) {
		msg = dbus_message_new_method_call(CM_DBUS_NAME,
						   CM_DBUS_BASE_PATH,
						   CM_DBUS_BASE_INTERFACE,
						   "echo");
		if (msg == NULL) {
			continue;
		}
		switch (i) {
		case 0:
			ret = cm_tdbusm_set_b(msg, b);
			break;
		case 1:
			ret = cm_tdbusm_set_n(msg, n);
			break;
		case 2:
			ret = cm_tdbusm_set_p(msg, p);
			break;
		case 3:
			ret = cm_tdbusm_set_s(msg, s);
			break;
		case 4:
			ret = cm_tdbusm_set_bp(msg, b, p);
			break;
		case 5:
			ret = cm_tdbusm_set_bs(msg, b, s);
			break;
		case 6:
			ret = cm_tdbusm_set_sb(msg, s, b);
			break;
		case 7:
			ret = cm_tdbusm_set_sn(msg, s, n);
			break;
		case 8:
			ret = cm_tdbusm_set_ss(msg, s1, s2);
			break;
		case 9:
			ret = cm_tdbusm_set_ap(msg, ap);
			break;
		case 10:
			ret = cm_tdbusm_set_as(msg, as);
			break;
		case 11:
			ret = cm_tdbusm_set_ssss(msg, s1, s2, s3, s4);
			break;
		case 12:
			ret = cm_tdbusm_set_sssas(msg, s1, s2, s3, as);
			break;
		case 13:
			ret = cm_tdbusm_set_sssnasasasas(msg, s1, s2, s3, n,
							 as1, as2, as3, as4);
			break;
		case 14:
			ret = cm_tdbusm_set_sasasasnas(msg, s, as1, as2, as3,
						       n, as4);
			break;
		case 15:
			ret = cm_tdbusm_set_d(msg, d);
			break;
		}
		if (ret != 0) {
			printf("Error encoding parameters for message %d.\n",
			       i);
			continue;
		}
		memset(&err, 0, sizeof(err));
		rep = dbus_connection_send_with_reply_and_block(conn, msg,
							        30000, &err);
		if (rep == NULL) {
			printf("No reply to message %d.\n", i);
			rep = msg;
		}
		{
			dbus_bool_t b;
			int j, k;
			char *s, *p, *s1, *s2, *s3, *s4;
			char **ap, **as, **as1, **as2, **as3, **as4;
			struct cm_tdbusm_dict **d;
			switch (i) {
			case 0:
				ret = cm_tdbusm_get_b(rep, NULL, &b);
				if (ret == 0) {
					printf("Message %d - b:%s\n", i,
					       b ? "TRUE" : "FALSE");
				}
				break;
			case 1:
				ret = cm_tdbusm_get_n(rep, NULL, &n);
				if (ret == 0) {
					printf("Message %d - n:%ld\n", i, n);
				}
				break;
			case 2:
				ret = cm_tdbusm_get_p(rep, NULL, &p);
				if (ret == 0) {
					printf("Message %d - p:%s\n", i, p);
				}
				break;
			case 3:
				ret = cm_tdbusm_get_s(rep, NULL, &s);
				if (ret == 0) {
					printf("Message %d - s:%s\n", i, s);
				}
				break;
			case 4:
				ret = cm_tdbusm_get_bp(rep, NULL, &b, &p);
				if (ret == 0) {
					printf("Message %d - b:%s,p:%s\n", i,
					       b ? "TRUE" : "FALSE", p);
				}
				break;
			case 5:
				ret = cm_tdbusm_get_bs(rep, NULL, &b, &s);
				if (ret == 0) {
					printf("Message %d - b:%s,s:%s\n", i,
					       b ? "TRUE" : "FALSE", s);
				}
				break;
			case 6:
				ret = cm_tdbusm_get_sb(rep, NULL, &s, &b);
				if (ret == 0) {
					printf("Message %d - s:%s,b:%s\n", i,
					       s, b ? "TRUE" : "FALSE");
				}
				break;
			case 7:
				ret = cm_tdbusm_get_sn(rep, NULL, &s, &n);
				if (ret == 0) {
					printf("Message %d - s:%s,n:%ld\n", i,
					       s, n);
				}
				break;
			case 8:
				ret = cm_tdbusm_get_ss(rep, NULL, &s1, &s2);
				if (ret == 0) {
					printf("Message %d - s:%s,s:%s\n", i,
					       s1, s2);
				}
				break;
			case 9:
				ret = cm_tdbusm_get_ap(rep, NULL, &ap);
				if (ret == 0) {
					printf("Message %d - [", i);
					for (j = 0;
					     (ap != NULL) && (ap[j] != NULL);
					     j++) {
						printf("%sp:%s",
						       j > 0 ? "," : "",
						       ap[j]);
					}
					printf("]\n");
				}
				break;
			case 10:
				ret = cm_tdbusm_get_as(rep, NULL, &as);
				if (ret == 0) {
					printf("Message %d - [", i);
					for (j = 0;
					     (as != NULL) && (as[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as[j]);
					}
					printf("]\n");
				}
				break;
			case 11:
				ret = cm_tdbusm_get_ssss(rep, NULL,
							 &s1, &s2, &s3, &s4);
				if (ret == 0) {
					printf("Message %d - "
					       "s:%s,s:%ss:%s,s:%s\n", i,
					       s1, s2, s3, s4);
				}
				break;
			case 12:
				ret = cm_tdbusm_get_sssas(rep, NULL,
							  &s1, &s2, &s3, &as);
				if (ret == 0) {
					printf("Message %d - s:%s,s:%s,s:%s,[",
					       i, s1, s2, s3);
					for (j = 0;
					     (as != NULL) && (as[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as[j]);
					}
					printf("]\n");
				}
				break;
			case 13:
				ret = cm_tdbusm_get_sssnasasasas(rep, NULL,
								 &s1, &s2, &s3,
								 &n,
								 &as1, &as2,
								 &as3, &as4);
				if (ret == 0) {
					printf("Message %d - s:%s,s:%s,s:%s,"
					       "n:%ld,[",
					       i, s1, s2, s3, n);
					for (j = 0;
					     (as1 != NULL) && (as1[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as1[j]);
					}
					printf("],[");
					for (j = 0;
					     (as2 != NULL) && (as2[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as2[j]);
					}
					printf("],[");
					for (j = 0;
					     (as3 != NULL) && (as3[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as3[j]);
					}
					printf("],[");
					for (j = 0;
					     (as4 != NULL) && (as4[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as4[j]);
					}
					printf("]\n");
				}
				break;
			case 14:
				ret = cm_tdbusm_get_sasasasnas(rep, NULL, &s,
							       &as1, &as2, &as3,
							       &n, &as4);
				if (ret == 0) {
					printf("Message %d - s:%s,[", i, s);
					for (j = 0;
					     (as1 != NULL) && (as1[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as1[j]);
					}
					printf("],[");
					for (j = 0;
					     (as2 != NULL) && (as2[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as2[j]);
					}
					printf("],[");
					for (j = 0;
					     (as3 != NULL) && (as3[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as3[j]);
					}
					printf("],n:%ld,[", n);
					for (j = 0;
					     (as4 != NULL) && (as4[j] != NULL);
					     j++) {
						printf("%ss:%s",
						       j > 0 ? "," : "",
						       as4[j]);
					}
					printf("]\n");
				}
				break;
			case 15:
				ret = cm_tdbusm_get_d(rep, NULL, &d);
				if (ret == 0) {
					printf("Message %d - [", i);
					for (j = 0;
					     (d != NULL) && (d[j] != NULL);
					     j++) {
						printf("%s{%s=",
						       j > 0 ? "," : "",
						       d[j]->key);
						switch (d[j]->value_type) {
						case cm_tdbusm_dict_s:
							printf("s:%s}",
							       d[j]->value.s);
							break;
						case cm_tdbusm_dict_as:
							printf("as:[");
							for (k = 0;
							     (d[j]->value.as != NULL) &&
							     (d[j]->value.as[k] != NULL);
							     k++) {
								printf("%s%s",
								       j > 0 ? "," : "",
								       d[j]->value.as[k]);
							}
							printf("]");
							break;
						case cm_tdbusm_dict_n:
							printf("n:%ld}",
							       d[j]->value.n);
							break;
						case cm_tdbusm_dict_b:
							printf("b:%s}",
							       d[j]->value.b ?
							       "TRUE" :
							       "FALSE");
							break;
						}
					}
					printf("]\n");
				}
				break;
			}
		}
	}

	return 0;
}
