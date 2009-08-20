#ifndef cmcm_h
#define cmcm_h

struct cm_context;
struct tevent_context;

int cm_init(struct tevent_context *parent, struct cm_context **context);
int cm_start_all(struct cm_context *context);
int cm_keep_going(struct cm_context *context);
void cm_done(struct cm_context *context);

#endif
