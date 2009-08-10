#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>

#include "keygen.h"
#include "log.h"
#include "store.h"
#include "store-int.h"

struct cm_keygen_state {
	char msg[0x10000];
	pid_t pid;
	int fd, status;
};

static void
cm_keygen_main(int fd, struct cm_store_entry *entry)
{
	FILE *status;
	enum cm_key_algorithm cm_key_algorithm;
	int cm_key_size, cm_requested_key_size;
	CK_MECHANISM_TYPE mech;
	SECStatus error;
	PK11SlotInfo *slot = NULL;
	PK11RSAGenParams rsa_params;
	void *params;
	SECKEYPrivateKey *privkey;
	SECKEYPublicKey *pubkey;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(1);
	}
	/* Start up NSS and open the database. */
	error = NSS_InitReadWrite(entry->cm_key_storage_location);
	if (error != SECSuccess) {
		fprintf(status, "Error initializing database '%s'.\n",
			entry->cm_key_storage_location);
		cm_log(1, "Error initializing database '%s'.\n",
		       entry->cm_key_storage_location);
		_exit(1);
	}
	/* Handle defaults. */
	if (entry->cm_key_type_default) {
		cm_key_algorithm = CM_DEFAULT_PUBKEY_TYPE;
		cm_requested_key_size = CM_DEFAULT_PUBKEY_SIZE;
	} else {
		cm_key_algorithm = entry->cm_key_type.cm_key_algorithm;
		cm_requested_key_size = entry->cm_key_type.cm_key_size;
	}
	/* Convert our key type to a mechanism. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;
	default:
		fprintf(status, "Unknown key type.\n");
		cm_log(1, "Unknown key type.\n");
		_exit(2);
		break;
	}
	/* Find the token that's best equipped for key generation. */
	slot = PK11_GetBestSlot(mech, NULL);
	if (slot == NULL) {
		fprintf(status, "Error locating slot for key generation.\n");
		cm_log(1, "Error locating slot for key generation.\n");
		_exit(2);
	}
	/* Select the optimum key size. */
	cm_key_size = PK11_GetBestKeyLength(slot, mech);
	if ((entry->cm_key_type_default == 0) &&
	    (cm_key_size != cm_requested_key_size)) {
		cm_log(1, "Overriding requested key size of %d with %d.\n",
		       cm_requested_key_size, cm_key_size);
	}
	/* Initialize the key generation parameters. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		memset(&rsa_params, 0, sizeof(rsa_params));
		rsa_params.keySizeInBits = cm_key_size;
		rsa_params.pe = CM_DEFAULT_RSA_MODULUS;
		params = &rsa_params;
		break;
	default:
		params = NULL;
		break;
	}
	/* Generate the key pair. */
	pubkey = NULL;
	privkey = PK11_GenerateKeyPair(slot, mech, params, &pubkey, PR_TRUE,
				       PR_TRUE, NULL);
	if (privkey == NULL) {
		cm_log(1, "Error generating key pair.\n");
		_exit(2);
	}
	/* Attach the specified nickname to the key. */
	error = PK11_SetPrivateKeyNickname(privkey, entry->cm_key_nickname);
	if (error != SECSuccess) {
		cm_log(1, "Error setting nickname on key pair.\n");
	}
	error = PK11_SetPublicKeyNickname(pubkey, entry->cm_key_nickname);
	if (error != SECSuccess) {
		cm_log(1, "Error setting nickname on key pair.\n");
	}
	SECKEY_DestroyPrivateKey(privkey);
	SECKEY_DestroyPublicKey(pubkey);
	PK11_FreeSlot(slot);
	error = NSS_Shutdown();
	if (error != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	fclose(status);
}

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *
cm_keygen_start(struct cm_store_entry *entry)
{
	int fds[2];
	struct cm_keygen_state *state;
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		return NULL;
	}
	state = malloc(sizeof(*state));
	if (state != NULL) {
		state->fd = -1;
		if (pipe(fds) != -1) {
			state->pid = fork();
			switch (state->pid) {
			case -1:
				close(fds[0]);
				close(fds[1]);
				free(state);
				state = NULL;
				break;
			case 0:
				close(fds[0]);
				cm_keygen_main(fds[1], entry);
				_exit(0);
				break;
			default:
				state->fd = fds[0];
				close(fds[1]);
				break;
			}
		}
	}
	return state;
}

/* Check if the keypair is ready. */
int
cm_keygen_ready(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	ssize_t i, remainder;
	char *p;
	p = state->msg;
	remainder = sizeof(state->msg) - 1;
	while ((i = read(state->fd, p, remainder)) > 0) {
		p += i;
		remainder -= i;
	}
	*p = '\0';
	close(state->fd);
	state->fd = -1;
	waitpid(state->pid, &state->status, 0);
	state->pid = -1;
	return 0;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_keygen_get_fd(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	return state->fd;
}

/* Tell us if the keypair was saved to the location specified in the entry. */
int
cm_keygen_saved_keypair(struct cm_store_entry *entry,
		        struct cm_keygen_state *state)
{

	if (WIFEXITED(state->status) && (WEXITSTATUS(state->status) == 0)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
void
cm_keygen_done(struct cm_store_entry *entry, struct cm_keygen_state *state)
{
	if (state->pid != -1) {
		kill(state->pid, SIGKILL);
	}
	if (state->fd != -1) {
		close(state->fd);
	}
	free(state);
}
