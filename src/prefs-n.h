/*
 * Copyright (C) 2010,2014,2015 Red Hat, Inc.
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

#ifndef cmprefsn_h
#define cmprefsn_h

unsigned int cm_prefs_nss_sig_alg(SECKEYPrivateKey *pkey);
unsigned int cm_prefs_nss_dig_alg(void);
unsigned int cm_prefs_nss_dig_alg_len(void);

#endif
