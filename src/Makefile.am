noinst_LIBRARIES = libcm.a libcm-o.a libcm-n.a
libcm_a_SOURCES = \
	cm.c \
	cm.h \
	csrgen.h \
	iterate.c \
	iterate.h \
	keygen.h \
	log.h \
	log.c \
	notify.h \
	store.h \
	store-int.h \
	store-files.c \
	store-gen.c \
	submit.h
libcm_o_a_SOURCES = \
	csrgen-o.c \
	keygen-o.c \
	submit-d.c
libcm_o_a_CFLAGS = @OPENSSL_CFLAGS@
libcm_n_a_SOURCES =
libcm_n_a_CFLAGS = @NSS_CFLAGS@
libcm_a_LIBADD = $(libcm_o_a_OBJECTS) $(libcm_n_a_OBJECTS)
sbin_PROGRAMS = certmongerd
certmongerd_SOURCES = cmd.c
certmongerd_LDADD = libcm.a @OPENSSL_LIBS@ @NSS_LIBS@
