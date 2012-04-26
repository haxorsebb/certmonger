/*
 * Copyright (C) 2012 Red Hat, Inc.
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

#ifndef tlslayer_h
#define tlslayer_h

struct cm_tls_connection;
struct cm_tls_connection *cm_tls_connect(const char *hostport,
					 const char *trusted_ca_file,
					 const char *trusted_ca_dir,
					 const char *trusted_ca_db,
					 const char *client_cert_file,
					 const char *client_key_file,
					 const char *client_db,
					 const char *client_nickname);
int cm_tls_fd(struct cm_tls_connection *conn);
ssize_t cm_tls_write(struct cm_tls_connection *conn,
		     const void *buf, size_t count);
ssize_t cm_tls_read(struct cm_tls_connection *conn,
		    void *buf, size_t count);
void cm_tls_close(struct cm_tls_connection *conn);

#endif
