AM_CFLAGS = @OPENSSL_CFLAGS@
lib_LIBRARIES = libcm.a
libcm_a_SOURCES = \
	cm.c \
	cm.h \
	csrgen.h \
	iterate.c \
	iterate.h \
	keygen.h \
	keygen-o.c \
	notify.h \
	store.h \
	store-int.h \
	submit.h
sbin_PROGRAMS = cmd
cmd_SOURCES = cmd.c
cmd_LDADD = libcm.a @OPENSSL_LIBS@
