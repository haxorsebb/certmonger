#ifndef cmcertreadint_h
#define cmcertreadint_h

struct cm_certread_state_pvt {
	/* Check if something changed, for example we finished reading the
	 * cert. */
	int (*ready)(struct cm_store_entry *entry,
		     struct cm_certread_state *state);
	/* Get a selectable-for-read descriptor we can poll for status changes.
	 * */
	int (*get_fd)(struct cm_store_entry *entry,
		      struct cm_certread_state *state);
	/* Clean up after reading the certificate. */
	void (*done)(struct cm_store_entry *entry,
		     struct cm_certread_state *state);
};

void cm_certread_n_parse(struct cm_store_entry *entry,
			 unsigned char *der_cert, unsigned int der_cert_len);
void cm_certread_write_data_to_pipe(struct cm_store_entry *entry, FILE *fp);
void cm_certread_read_data_from_buffer(struct cm_store_entry *entry,
				       const char *p);

#endif
