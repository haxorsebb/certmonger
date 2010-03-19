/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include <talloc.h>

#include "certread.h"
#include "certread-int.h"
#include "log.h"
#include "store-int.h"

/* Start refreshing the certificate and associated data from the entry from the
 * configured location. */
struct cm_certread_state *
cm_certread_start(struct cm_store_entry *entry)
{
	switch (entry->cm_cert_storage_type) {
#ifdef HAVE_OPENSSL
	case cm_cert_storage_file:
		if (entry->cm_cert_storage_location != NULL) {
			return cm_certread_o_start(entry);
		} else {
			return NULL;
		}
		break;
#endif
#ifdef HAVE_NSS
	case cm_cert_storage_nssdb:
		if ((entry->cm_cert_storage_location != NULL) &&
		    (entry->cm_cert_nickname != NULL)) {
			return cm_certread_n_start(entry);
		} else {
			return NULL;
		}
		break;
#endif
	}
	return NULL;
}

/* Check if something changed, for example we finished reading the cert. */
int
cm_certread_ready(struct cm_store_entry *entry, struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;
	pvt = (struct cm_certread_state_pvt *) state;
	return pvt->ready(entry, state);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_certread_get_fd(struct cm_store_entry *entry,
		   struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;
	pvt = (struct cm_certread_state_pvt *) state;
	return pvt->get_fd(entry, state);
}

/* Clean up after reading the certificate. */
void
cm_certread_done(struct cm_store_entry *entry, struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;
	pvt = (struct cm_certread_state_pvt *) state;
	pvt->done(entry, state);
}

/* Send what we know about this certificate down a pipe using stdio. */
void
cm_certread_write_data_to_pipe(struct cm_store_entry *entry, FILE *fp)
{
	int i;
	fprintf(fp, " %s\n", entry->cm_cert_issuer ?: "");
	fprintf(fp, " %s\n", entry->cm_cert_serial ?: "");
	fprintf(fp, " %s\n", entry->cm_cert_subject ?: "");
	fprintf(fp, " %s\n", entry->cm_cert_spki ?: "");
	fprintf(fp, " %lu\n", entry->cm_cert_not_before ?: 0);
	fprintf(fp, " %lu\n", entry->cm_cert_not_after ?: 0);
	for (i = 0;
	     (entry->cm_cert_hostname != NULL) &&
	     (entry->cm_cert_hostname[i] != NULL);
	     i++) {
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			entry->cm_cert_hostname[i]);
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	for (i = 0;
	     (entry->cm_cert_email != NULL) &&
	     (entry->cm_cert_email[i] != NULL);
	     i++) {
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			entry->cm_cert_email[i]);
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	for (i = 0;
	     (entry->cm_cert_principal != NULL) &&
	     (entry->cm_cert_principal[i] != NULL);
	     i++) {
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			entry->cm_cert_principal[i]);
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	fprintf(fp, " %s\n", entry->cm_cert_ku ?: "");
	fprintf(fp, " %s\n", entry->cm_cert_eku ?: "");
	fprintf(fp, " %s\n", entry->cm_cert_token ?: "");
	fprintf(fp, " %s\n", entry->cm_cert ?: "");
}

/* Parse what we know about this certificate from a buffer. */
void
cm_certread_read_data_from_buffer(struct cm_store_entry *entry, const char *p)
{
	const char *q, *u, *v;
	char *s;
	void *vals;
	int i = 0, j;
	while (*p != '\0') {
		/* Skip over the first character. */
		p++;
		/* Find the end of the line. */
		q = p + strcspn(p, "\r\n");
		/* Decide what to do with the data. */
		switch (i++) {
		case 0:
			talloc_free(entry->cm_cert_issuer);
			entry->cm_cert_issuer = (p == q) ? NULL :
						talloc_strndup(entry, p, q - p);
			break;
		case 1:
			talloc_free(entry->cm_cert_serial);
			entry->cm_cert_serial = (p == q) ? NULL :
						talloc_strndup(entry, p, q - p);
			break;
		case 2:
			talloc_free(entry->cm_cert_subject);
			entry->cm_cert_subject = (p == q) ? NULL :
						 talloc_strndup(entry,
								p, q - p);
			break;
		case 3:
			talloc_free(entry->cm_cert_spki);
			entry->cm_cert_spki = (p == q) ? NULL :
					      talloc_strndup(entry, p, q - p);
			break;
		case 4:
			s = talloc_strndup(entry, p, q - p);
			entry->cm_cert_not_before = atol(s);
			talloc_free(s);
			break;
		case 5:
			s = talloc_strndup(entry, p, q - p);
			entry->cm_cert_not_after = atol(s);
			talloc_free(s);
			break;
		case 6:
			talloc_free(entry->cm_cert_hostname);
			entry->cm_cert_hostname = talloc_zero_array(entry,
								    char *,
								    q - p + 2);
			vals = entry->cm_cert_hostname;
			u = p;
			j = 0;
			while ((*u != '\0') && (u < q)) {
				v = u + strcspn(u, ",\r\n");
				if (v > u) {
					entry->cm_cert_hostname[j] = talloc_strndup(vals,
										    u,
										    v - u);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 7:
			talloc_free(entry->cm_cert_email);
			entry->cm_cert_email = talloc_zero_array(entry,
								 char *,
								 q - p + 2);
			vals = entry->cm_cert_email;
			u = p;
			j = 0;
			while ((*u != '\0') && (u < q)) {
				v = u + strcspn(u, ",\r\n");
				if (v > u) {
					entry->cm_cert_email[j] = talloc_strndup(vals,
										 u,
										 v - u);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 8:
			talloc_free(entry->cm_cert_principal);
			entry->cm_cert_principal = talloc_zero_array(entry,
								     char *,
								     q - p + 2);
			vals = entry->cm_cert_principal;
			u = p;
			j = 0;
			while ((*u != '\0') && (u < q)) {
				v = u + strcspn(u, ",\r\n");
				if (v > u) {
					entry->cm_cert_principal[j] = talloc_strndup(vals,
										     u,
										     v - u);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 9:
			talloc_free(entry->cm_cert_ku);
			entry->cm_cert_ku = (p == q) ? NULL :
					    talloc_strndup(entry, p, q - p);
			break;
		case 10:
			talloc_free(entry->cm_cert_eku);
			entry->cm_cert_eku = (p == q) ? NULL :
					     talloc_strndup(entry, p, q - p);
			break;
		case 11:
			if (p != q) {
				talloc_free(entry->cm_cert_token);
				entry->cm_cert_token = talloc_strndup(entry, p,
								      q - p);
			}
			break;
		case 12:
			talloc_free(entry->cm_cert);
			entry->cm_cert = (p[strspn(p, " \r\n")] == '\0') ?
					 NULL :
					 talloc_strdup(entry, p);
			break;
		}
		/* Find the beginning of the next line. */
		p = q + strspn(q, "\r\n");
	}
}
