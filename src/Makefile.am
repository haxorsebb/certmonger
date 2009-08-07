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
	notify.c \
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
bin_PROGRAMS = cm
sbin_PROGRAMS = cmd
cm_SOURCES = cli.c
cm_LDADD = libcm.a @OPENSSL_LIBS@ @NSS_LIBS@
cmd_SOURCES = cmd.c
cmd_LDADD = libcm.a @OPENSSL_LIBS@ @NSS_LIBS@
