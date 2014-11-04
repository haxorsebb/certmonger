/*
 * Copyright (C) 2014 Red Hat, Inc.
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

#ifndef cmsrvloc_h
#define cmsrvloc_h

struct cm_srvloc {
	char *host;
	uint16_t port;
	int priority, weight;
	struct cm_srvloc *next;
};

int cm_srvloc_resolve(void *parent, const char *service, const char *domain,
		      struct cm_srvloc **results);

#endif
