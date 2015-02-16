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

#ifndef cmscep_h
#define cmscep_h

#define SCEP_MSGTYPE_PKCSREQ		"19"
#define SCEP_MSGTYPE_CERTREP		"3"
#define SCEP_MSGTYPE_GETCERTINITIAL	"20"
#define SCEP_MSGTYPE_GETCERT		"21"
#define SCEP_MSGTYPE_GETCRL		"22"

#define SCEP_PKISTATUS_SUCCESS		"0"
#define SCEP_PKISTATUS_FAILURE		"2"
#define SCEP_PKISTATUS_PENDING		"3"

#define SCEP_FAILINFO_BAD_ALG		"0"
#define SCEP_FAILINFO_BAD_MESSAGE_CHECK	"1"
#define SCEP_FAILINFO_BAD_REQUEST	"2"
#define SCEP_FAILINFO_BAD_TIME		"3"
#define SCEP_FAILINFO_BAD_CERT_ID	"4"

#endif
