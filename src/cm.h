#ifndef cmcm_h
#define cmcm_h

struct cm_context;
int cm_init(void *parent, struct cm_context **context);
int cm_next(struct cm_context *context,
	    int **fds, int *nfds, int *timeout);
void cm_done(struct cm_context *context, int **fds);

#endif
