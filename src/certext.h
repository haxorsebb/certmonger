#ifndef cmcertext_h
#define cmcertext_h

struct cm_store_entry;
void cm_certext_read_extensions(struct cm_store_entry *entry,
				PLArenaPool *arena,
				CERTCertExtension **extensions);

#endif
