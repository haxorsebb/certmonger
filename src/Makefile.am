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
	log.h \
	log.c \
	notify.h \
	store.h \
	store-int.h \
	store-files.c \
	store-gen.c \
	submit.h \
	submit-d.c
sbin_PROGRAMS = certmongerd
certmongerd_SOURCES = cmd.c
certmongerd_LDADD = libcm.a @OPENSSL_LIBS@
