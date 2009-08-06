#ifndef cmlog_h
#define cmlog_h

enum cm_log_method {
	cm_log_syslog = 0,
	cm_log_stderr,
};

int cm_log_set_level(int level);
enum cm_log_method cm_log_set_method(enum cm_log_method method);
void cm_log(int level, const char *fmt, ...);

#endif
