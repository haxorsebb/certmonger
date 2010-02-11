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

#ifndef cmprefsint_h
#define cmprefsint_h

enum cm_prefs_cipher {
	cm_prefs_aes128,
	cm_prefs_aes256,
};

enum cm_prefs_digest {
	cm_prefs_sha256,
	cm_prefs_sha384,
	cm_prefs_sha512,
	cm_prefs_sha1,
};

enum cm_prefs_cipher cm_prefs_preferred_cipher(void);
enum cm_prefs_digest cm_prefs_preferred_digest(void);

#endif
