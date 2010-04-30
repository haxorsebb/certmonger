/*
 * Copyright (C) 2010 Red Hat, Inc.
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

#ifndef cmsubmitd_h
#define cmsubmitd_h

char *cm_submit_d_req_status(void *parent, const char *xml);
char *cm_submit_d_req_requestid(void *parent, const char *xml);
char *cm_submit_d_check_status(void *parent, const char *xml);
char *cm_submit_d_check_cert(void *parent, const char *xml);
char *cm_submit_d_retr_status(void *parent, const char *xml);
char *cm_submit_d_retr_cert(void *parent, const char *xml);

#endif
