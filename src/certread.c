/*
 * Copyright (C) 2009,2010,2012,2014,2015 Red Hat, Inc.
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
#include <time.h>

#include <talloc.h>

#include "certread.h"
#include "certread-int.h"
#include "log.h"
#include "store.h"
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
cm_certread_ready(struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;

	pvt = (struct cm_certread_state_pvt *) state;
	return pvt->ready(state);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_certread_get_fd(struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;

	pvt = (struct cm_certread_state_pvt *) state;
	return pvt->get_fd(state);
}

/* Clean up after reading the certificate. */
void
cm_certread_done(struct cm_certread_state *state)
{
	struct cm_certread_state_pvt *pvt;

	pvt = (struct cm_certread_state_pvt *) state;
	pvt->done(state);
}

/* Send what we know about this certificate down a pipe using stdio. */
void
cm_certread_write_data_to_pipe(struct cm_store_entry *entry, FILE *fp)
{
	int i;
	unsigned char *p;

	fprintf(fp, " %s\n", entry->cm_cert_issuer_der ?: "");
	p = (unsigned char *) entry->cm_cert_issuer;
	fprintf(fp, " %s\n", p ? cm_store_base64_from_bin(NULL, p, -1) : "");
	fprintf(fp, " %s\n", entry->cm_cert_serial ?: "");
	fprintf(fp, " %s\n", entry->cm_cert_subject_der ?: "");
	p = (unsigned char *) entry->cm_cert_subject;
	fprintf(fp, " %s\n", p ? cm_store_base64_from_bin(NULL, p, -1) : "");
	fprintf(fp, " %s\n", entry->cm_cert_spki ?: "");
	fprintf(fp, " %lu\n", entry->cm_cert_not_before ?: 0);
	fprintf(fp, " %lu\n", entry->cm_cert_not_after ?: 0);
	for (i = 0;
	     (entry->cm_cert_hostname != NULL) &&
	     (entry->cm_cert_hostname[i] != NULL);
	     i++) {
		p = (unsigned char *) entry->cm_cert_hostname[i];
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			cm_store_base64_from_bin(NULL, p, -1));
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	for (i = 0;
	     (entry->cm_cert_email != NULL) &&
	     (entry->cm_cert_email[i] != NULL);
	     i++) {
		p = (unsigned char *) entry->cm_cert_email[i];
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			cm_store_base64_from_bin(NULL, p, -1));
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	for (i = 0;
	     (entry->cm_cert_principal != NULL) &&
	     (entry->cm_cert_principal[i] != NULL);
	     i++) {
		p = (unsigned char *) entry->cm_cert_principal[i];
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			cm_store_base64_from_bin(NULL, p, -1));
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	for (i = 0;
	     (entry->cm_cert_ipaddress != NULL) &&
	     (entry->cm_cert_ipaddress[i] != NULL);
	     i++) {
		p = (unsigned char *) entry->cm_cert_ipaddress[i];
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			cm_store_base64_from_bin(NULL, p, -1));
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	fprintf(fp, " %s\n", entry->cm_cert_ku ?: "");
	fprintf(fp, " %s\n", entry->cm_cert_eku ?: "");
	p = (unsigned char *) entry->cm_cert_token;
	fprintf(fp, " %s\n", p ? cm_store_base64_from_bin(NULL, p, -1) : "");
	fprintf(fp, " %d\n", entry->cm_cert_is_ca ? 1 : 0);
	fprintf(fp, " %d\n", entry->cm_cert_is_ca ?
		entry->cm_cert_ca_path_length : -1);
	for (i = 0;
	     (entry->cm_cert_ocsp_location != NULL) &&
	     (entry->cm_cert_ocsp_location[i] != NULL);
	     i++) {
		p = (unsigned char *) entry->cm_cert_ocsp_location[i];
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			cm_store_base64_from_bin(NULL, p, -1));
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	for (i = 0;
	     (entry->cm_cert_crl_distribution_point != NULL) &&
	     (entry->cm_cert_crl_distribution_point[i] != NULL);
	     i++) {
		p = (unsigned char *) entry->cm_cert_crl_distribution_point[i];
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			cm_store_base64_from_bin(NULL, p, -1));
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	for (i = 0;
	     (entry->cm_cert_freshest_crl != NULL) &&
	     (entry->cm_cert_freshest_crl[i] != NULL);
	     i++) {
		p = (unsigned char *) entry->cm_cert_freshest_crl[i];
		fprintf(fp, "%s%s", (i > 0) ? "," : " ",
			cm_store_base64_from_bin(NULL, p, -1));
	}
	fprintf(fp, "%s\n", i > 0 ? "" : " ");
	p = (unsigned char *) entry->cm_cert_ns_comment;
	fprintf(fp, " %s\n", p ? cm_store_base64_from_bin(NULL, p, -1) : "");
	p = (unsigned char *) entry->cm_cert_profile;
	fprintf(fp, " %s\n", p ? cm_store_base64_from_bin(NULL, p, -1) : "");
	fprintf(fp, " %d\n", entry->cm_cert_no_ocsp_check ? 1 : 0);
	p = (unsigned char *) entry->cm_cert_ns_certtype;
	fprintf(fp, " %s\n", p ? cm_store_base64_from_bin(NULL, p, -1) : "");
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
			talloc_free(entry->cm_cert_issuer_der);
			entry->cm_cert_issuer_der = (p == q) ? NULL :
						    talloc_strndup(entry, p,
								   q - p);
			break;
		case 1:
			talloc_free(entry->cm_cert_issuer);
			entry->cm_cert_issuer = (p == q) ? NULL :
						cm_store_base64_as_bin(entry,
								       p,
								       q - p,
								       NULL);
			break;
		case 2:
			talloc_free(entry->cm_cert_serial);
			entry->cm_cert_serial = (p == q) ? NULL :
						talloc_strndup(entry, p, q - p);
			break;
		case 3:
			talloc_free(entry->cm_cert_subject_der);
			entry->cm_cert_subject_der = (p == q) ? NULL :
						     talloc_strndup(entry, p,
								    q - p);
			break;
		case 4:
			talloc_free(entry->cm_cert_subject);
			entry->cm_cert_subject = (p == q) ? NULL :
						 cm_store_base64_as_bin(entry,
									p,
									q - p,
									NULL);
			break;
		case 5:
			talloc_free(entry->cm_cert_spki);
			entry->cm_cert_spki = (p == q) ? NULL :
					      talloc_strndup(entry, p, q - p);
			break;
		case 6:
			s = talloc_strndup(entry, p, q - p);
			entry->cm_cert_not_before = atol(s);
			talloc_free(s);
			break;
		case 7:
			s = talloc_strndup(entry, p, q - p);
			entry->cm_cert_not_after = atol(s);
			talloc_free(s);
			break;
		case 8:
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
					entry->cm_cert_hostname[j] =
						cm_store_base64_as_bin(vals, u,
								       v - u,
								       NULL);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 9:
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
					entry->cm_cert_email[j] =
						cm_store_base64_as_bin(vals, u,
								       v - u,
								       NULL);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 10:
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
					entry->cm_cert_principal[j] =
						cm_store_base64_as_bin(vals, u,
								       v - u,
								       NULL);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 11:
			talloc_free(entry->cm_cert_ipaddress);
			entry->cm_cert_ipaddress = talloc_zero_array(entry,
								     char *,
								     q - p + 2);
			vals = entry->cm_cert_ipaddress;
			u = p;
			j = 0;
			while ((*u != '\0') && (u < q)) {
				v = u + strcspn(u, ",\r\n");
				if (v > u) {
					entry->cm_cert_ipaddress[j] =
						talloc_strndup(vals, u, v - u);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 12:
			talloc_free(entry->cm_cert_ku);
			entry->cm_cert_ku = (p == q) ? NULL :
					    talloc_strndup(entry, p, q - p);
			break;
		case 13:
			talloc_free(entry->cm_cert_eku);
			entry->cm_cert_eku = (p == q) ? NULL :
					     talloc_strndup(entry, p, q - p);
			break;
		case 14:
			if (p != q) {
				talloc_free(entry->cm_cert_token);
				entry->cm_cert_token =
					cm_store_base64_as_bin(entry, p, q - p,
							       NULL);
			}
			break;
		case 15:
			entry->cm_cert_is_ca = (p != q) ? (atoi(p) != 0) : 0;
			break;
		case 16:
			entry->cm_cert_ca_path_length = (p != q) ? atoi(p) : -1;
			break;
		case 17:
			talloc_free(entry->cm_cert_ocsp_location);
			entry->cm_cert_ocsp_location = talloc_zero_array(entry,
									 char *,
									 q - p + 2);
			vals = entry->cm_cert_ocsp_location;
			u = p;
			j = 0;
			while ((*u != '\0') && (u < q)) {
				v = u + strcspn(u, ",\r\n");
				if (v > u) {
					entry->cm_cert_ocsp_location[j] =
						cm_store_base64_as_bin(vals, u,
								       v - u,
								       NULL);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 18:
			talloc_free(entry->cm_cert_crl_distribution_point);
			entry->cm_cert_crl_distribution_point =
				talloc_zero_array(entry, char *, q - p + 2);
			vals = entry->cm_cert_crl_distribution_point;
			u = p;
			j = 0;
			while ((*u != '\0') && (u < q)) {
				v = u + strcspn(u, ",\r\n");
				if (v > u) {
					entry->cm_cert_crl_distribution_point[j] = cm_store_base64_as_bin(vals,
													  u,
													  v - u,
													  NULL);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 19:
			talloc_free(entry->cm_cert_freshest_crl);
			entry->cm_cert_freshest_crl = talloc_zero_array(entry,
									char *,
									q - p + 2);
			vals = entry->cm_cert_freshest_crl;
			u = p;
			j = 0;
			while ((*u != '\0') && (u < q)) {
				v = u + strcspn(u, ",\r\n");
				if (v > u) {
					entry->cm_cert_freshest_crl[j] = cm_store_base64_as_bin(vals,
												u,
												v - u,
												NULL);
					j++;
				}
				u = v + strspn(u, ",\r\n");
			}
			break;
		case 20:
			talloc_free(entry->cm_cert_ns_comment);
			entry->cm_cert_ns_comment = (p == q) ? NULL :
						    cm_store_base64_as_bin(entry,
									   p,
									   q - p,
									   NULL);
			break;
		case 21:
			talloc_free(entry->cm_cert_profile);
			entry->cm_cert_profile = (p == q) ? NULL :
						 cm_store_base64_as_bin(entry,
									p,
									q - p,
									NULL);
			break;
		case 22:
			entry->cm_cert_no_ocsp_check = (p != q) ? (atoi(p) != 0) : 0;
			break;
		case 23:
			talloc_free(entry->cm_cert_ns_certtype);
			entry->cm_cert_ns_certtype = (p == q) ? NULL :
						     cm_store_base64_as_bin(entry,
									    p,
									    q - p,
									    NULL);
			break;
		case 24:
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
