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

static void
dump_rta(struct rtattr *buf, int len)
{
	struct rtattr *rta;
	for (rta = buf; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {
		default:
			printf(" Got an unknown attribute of length %ld.\n",
			       (long) RTA_PAYLOAD(rta));
			break;
		}
	}
	printf(" %d leftover attribute bytes.\n", len);
}

static void
dump_nlmsg(unsigned char *buf, int len,
	   struct sockaddr_nl *nlmsgsrc)
{
	struct nlmsghdr *nlmsg;
	struct rtmsg *rtm;
	for (nlmsg = (struct nlmsghdr *) buf;
	     (len > 0) && NLMSG_OK(nlmsg, (unsigned int) len);
	     nlmsg = NLMSG_NEXT(nlmsg, len)) {
		printf("Got a full message with payload length %ld from %ld.\n",
		       (long) NLMSG_PAYLOAD(nlmsg, 0),
		       (long) nlmsgsrc->nl_pid);
		rtm = NLMSG_DATA(nlmsg);
		switch (nlmsg->nlmsg_type) {
		case RTM_NEWLINK:
			printf(" Got a new-link message.\n");
			break;
		case RTM_DELLINK:
			printf(" Got a del-link message.\n");
			break;
		case RTM_GETLINK:
			printf(" Got a get-link message.\n");
			break;
		case RTM_SETLINK:
			printf(" Got a set-link message.\n");
			break;
		case RTM_NEWADDR:
			printf(" Got a new-addr message.\n");
			break;
		case RTM_DELADDR:
			printf(" Got a del-addr message.\n");
			break;
		case RTM_GETADDR:
			printf(" Got a get-addr message.\n");
			break;
		case RTM_NEWROUTE:
			printf(" Got a new-route message.\n");
			break;
		case RTM_DELROUTE:
			printf(" Got a del-route message.\n");
			break;
		case RTM_GETROUTE:
			printf(" Got a get-route message.\n");
			break;
		case RTM_NEWNEIGH:
			printf(" Got a new-neighbor message.\n");
			break;
		case RTM_DELNEIGH:
			printf(" Got a del-neighbor message.\n");
			break;
		case RTM_GETNEIGH:
			printf(" Got a get-neighbor message.\n");
			break;
		case RTM_NEWRULE:
			printf(" Got a new-rule message.\n");
			break;
		case RTM_DELRULE:
			printf(" Got a del-rule message.\n");
			break;
		case RTM_GETRULE:
			printf(" Got a get-rule message.\n");
			break;
		default:
			printf(" Got an unknown message %d.\n", rtm->rtm_type);
			rtm = NULL;
			break;
		}
		if (rtm != NULL) {
			switch (rtm->rtm_family) {
			case AF_INET:
				printf("  IPv4.\n");
				break;
			case AF_INET6:
				printf("  IPv6.\n");
				break;
			default:
				printf("  family %d.\n", rtm->rtm_family);
				break;
			}
			dump_rta(RTM_RTA(nlmsg), RTM_PAYLOAD(nlmsg));
		}
	}
	printf("%d leftover message bytes.\n", len);
}

int
main(int argc, char **argv)
{
	fd_set fds;
	int nl, len, err;
	unsigned char buf[0x10000];
	struct sockaddr_nl nlmsgsrc;
	socklen_t nlmsgsrclen;
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
		memset(&nlmsgsrc, 0, sizeof(nlmsgsrc));
		nlmsgsrclen = sizeof(nlmsgsrc);
		len = recvfrom(nl, buf, sizeof(buf), 0,
			       (struct sockaddr *) &nlmsgsrc, &nlmsgsrclen);
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
		if (nlmsgsrclen != sizeof(struct sockaddr_nl)) {
			/* The heck? */
			printf("Sender did not have a netlink address-sized "
			       "address?\n");
			return -1;
		}
		if (nlmsgsrc.nl_family != AF_NETLINK) {
			/* The heck? */
			printf("Sender did not have a netlink address?\n");
			return -1;
		}
		printf("Received %d bytes.\n", len);
		dump_nlmsg(buf, len, &nlmsgsrc);
	}
	return 0;
}

#endif
