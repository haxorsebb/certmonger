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

#ifndef cmscepo_h
#define cmscepo_h

int cm_scep_o_get_msgtype_nid(void);
int cm_scep_o_get_pkistatus_nid(void);
int cm_scep_o_get_failinfo_nid(void);
int cm_scep_o_get_sender_nonce_nid(void);
int cm_scep_o_get_recipient_nonce_nid(void);
int cm_scep_o_get_tx_nid(void);

#endif
