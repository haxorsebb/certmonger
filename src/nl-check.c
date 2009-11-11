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
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "netlink.h"

#if !defined(HAVE_LINUX_NETLINK_H) || !defined(HAVE_LINUX_RTNETLINK_H)
int
main(int argc, char **argv)
{
	printf("Netlink support not built.\n");
	return 1;
}
#else

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int
main(int argc, char **argv)
{
	fd_set fds;
	int nl, len, err;
	unsigned char buf[0x10000];
	nl = cm_netlink_socket();
	if (nl == -1) {
		printf("Error creating socket.\n");
		return 1;
	}
	printf("Waiting for data.\n");
	for (;;) {
		FD_ZERO(&fds);
		FD_SET(nl, &fds);
		select(nl + 1, &fds, NULL, NULL, NULL);
		len = recv(nl, buf, sizeof(buf), 0);
		switch (len) {
		case 0:
			printf("EOF\n");
			return 0;
			break;
		case -1:
			err = errno;
			printf("Error %s\n", strerror(errno));
			return err;
			break;
		}
		printf("Received %d bytes.\n", len);
	}
	return 0;
}

#endif
