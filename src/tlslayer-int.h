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

#ifndef tlslayer_int_h
#define tlslayer_int_h

struct cm_tls_connection {
	struct cm_tls_connection_ops {
		int (*cm_fd)(struct cm_tls_connection *conn, void *pvt);
		ssize_t (*cm_write)(struct cm_tls_connection *conn, void *pvt,
				    const void *buf, size_t count);
		ssize_t (*cm_read)(struct cm_tls_connection *conn, void *pvt,
				   void *buf, size_t count);
		void (*cm_close)(struct cm_tls_connection *conn, void *pvt);
	} pvt_ops;
	void *pvt;
};

struct cm_tls_connection *cm_tls_n(const char *hostport,
				   const char *trusted_ca_file,
				   const char *trusted_ca_db,
				   const char *client_db,
				   const char *client_nickname);
struct cm_tls_connection *cm_tls_o(const char *hostport,
				   const char *trusted_ca_file,
				   const char *trusted_ca_dir,
				   const char *client_cert_file,
				   const char *client_key_file);

#endif
