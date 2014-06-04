/*
 * Copyright (C) 2009,2014 Red Hat, Inc.
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

#ifndef cmcertreadint_h
#define cmcertreadint_h

struct cm_certread_state_pvt {
	/* Check if something changed, for example we finished reading the
	 * cert. */
	int (*ready)(struct cm_certread_state *state);
	/* Get a selectable-for-read descriptor we can poll for status changes.
	 * */
	int (*get_fd)(struct cm_certread_state *state);
	/* Clean up after reading the certificate. */
	void (*done)(struct cm_certread_state *state);
};

void cm_certread_n_parse(struct cm_store_entry *entry,
			 unsigned char *der_cert, unsigned int der_cert_len);
void cm_certread_write_data_to_pipe(struct cm_store_entry *entry, FILE *fp);
void cm_certread_read_data_from_buffer(struct cm_store_entry *entry,
				       const char *p);

#endif
