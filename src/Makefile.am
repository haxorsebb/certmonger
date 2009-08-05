AM_CFLAGS = @OPENSSL_CFLAGS@
lib_LIBRARIES = libcm.a
libcm_a_SOURCES = \
	cm.c \
	cm.h \
	csrgen.h \
	csrgen-o.c \
	iterate.c \
	iterate.h \
	keygen.h \
	keygen-o.c \
	notify.h \
	store.h \
	store-int.h \
	store-files.c \
	store-gen.c \
	submit.h \
	submit-d.c
sbin_PROGRAMS = cmd
cmd_SOURCES = cmd.c
cmd_LDADD = libcm.a @OPENSSL_LIBS@
