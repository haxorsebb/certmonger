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

#ifndef cmcertext_n_h
#define cmcertext_n_h

struct cm_store_entry;
extern const SEC_ASN1Template cm_certext_cert_extension_template[];
extern const SEC_ASN1Template cm_certext_sequence_of_cert_extension_template[];
void cm_certext_read_extensions(struct cm_store_entry *entry,
				PLArenaPool *arena,
				CERTCertExtension **extensions);

#endif
