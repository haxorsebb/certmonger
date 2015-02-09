/*
 * Copyright (C) 2009,2011,2012,2014 Red Hat, Inc.
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

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>

#include "csrgen.h"
#include "csrgen-int.h"
#include "log.h"
#include "store-int.h"

int
cm_csrgen_read_challenge_password(struct cm_store_entry *entry, char **password)
{
	const char *filename, *value;
	struct stat st;
	int fd, l, err;

	if (password == NULL) {
		return EINVAL;
	}
	*password = NULL;
	err = 0;
	filename = entry->cm_template_challenge_password_file;
	value = entry->cm_template_challenge_password;
	if ((filename != NULL) && (strlen(filename) > 0)) {
		fd = open(filename, O_RDONLY);
		if (fd != -1) {
			if ((fstat(fd, &st) == 0) && (st.st_size > 0)) {
				*password = talloc_zero_size(entry, st.st_size + 1);
				if (*password != NULL) {
					if (read(fd, *password, st.st_size) != -1) {
						l = strcspn(*password, "\r\n");
						if (l == 0) {
							talloc_free(*password);
							*password = NULL;
						} else {
							(*password)[l] = '\0';
						}
					} else {
						err = errno;
						cm_log(-1,
						       "Error reading \"%s\": "
						       "%s.\n",
						       filename, strerror(err));
						talloc_free(*password);
						*password = NULL;
					}
				}
			} else {
				err = errno;
				cm_log(-1, "Error determining size of \"%s\": "
				       "%s.\n",
				       filename, strerror(err));
			}
			close(fd);
		} else {
			err = errno;
			cm_log(-1, "Error reading challenge password from "
			       "\"%s\": %s.\n", filename, strerror(err));
		}
	}
	if ((password != NULL) && (*password == NULL) && (err == 0)) {
		if (value != NULL) {
			*password = talloc_strdup(entry, value);
		}
	}
	return err;
}

struct cm_csrgen_state *
cm_csrgen_start(struct cm_store_entry *entry)
{
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		cm_log(1, "Can't generate new CSR for %s('%s') without the "
		       "key, and we don't know where that is or should be.\n",
		       entry->cm_busname, entry->cm_nickname);
		break;
#ifdef HAVE_OPENSSL
	case cm_key_storage_file:
		return cm_csrgen_o_start(entry);
		break;
#endif
#ifdef HAVE_NSS
	case cm_key_storage_nssdb:
		return cm_csrgen_n_start(entry);
		break;
#endif
	}
	return NULL;
}

int
cm_csrgen_ready(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->ready(state);
}

int
cm_csrgen_get_fd(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->get_fd(state);
}

int
cm_csrgen_save_csr(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->save_csr(state);
}

int
cm_csrgen_need_pin(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->need_pin(state);
}

int
cm_csrgen_need_token(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	return pvt->need_token(state);
}

void
cm_csrgen_done(struct cm_csrgen_state *state)
{
	struct cm_csrgen_state_pvt *pvt = (struct cm_csrgen_state_pvt *) state;

	pvt->done(state);
}
