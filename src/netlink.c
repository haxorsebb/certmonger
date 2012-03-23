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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "netlink.h"

#if defined(HAVE_LINUX_NETLINK_H) && defined(HAVE_LINUX_RTNETLINK_H)

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int
cm_netlink_socket(void)
{
	int fd;
	struct sockaddr_nl sn;
	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd == -1) {
		return -1;
	}
	if (fcntl(fd, F_SETFL, (long) O_NONBLOCK) == -1) {
		close(fd);
		return -1;
	};
	if (fcntl(fd, F_SETFD, (long) FD_CLOEXEC) == -1) {
		close(fd);
		return -1;
	};
	memset(&sn, 0, sizeof(sn));
	sn.nl_family = AF_NETLINK;
	sn.nl_pad = 0;
	sn.nl_pid = getpid();
	sn.nl_groups = RTMGRP_NOTIFY | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
	if (bind(fd, (struct sockaddr *) &sn, sizeof(sn)) == -1) {
		close(fd);
		return -1;
	}
	return fd;
}

int
cm_netlink_pkt_is_route_change(char *buf, int len,
			       struct sockaddr *src_addr, socklen_t addrlen)
{
	struct nlmsghdr *nlmsg;
	struct sockaddr_nl *src;
	if (addrlen != sizeof(*src)) {
		return -1;
	}
	src = (struct sockaddr_nl *) src_addr;
	if (src->nl_pid != 0) {
		return -1;
	}
	for (nlmsg = (struct nlmsghdr *) buf;
	     (len > 0) && NLMSG_OK(nlmsg, (unsigned int) len);
	     nlmsg = NLMSG_NEXT(nlmsg, len)) {
		switch (nlmsg->nlmsg_type) {
		case RTM_NEWLINK:
		case RTM_DELLINK:
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			return 0;
			break;
		}
	}
	return -1;
}

#else
int
cm_netlink_socket(void)
{
	return -1;
}
int
cm_netlink_pkt_is_route_change(char *buf, int len,
			       struct sockaddr *src_addr, socklen_t addrlen)
{
	return -1;
}
#endif
