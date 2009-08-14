noinst_LIBRARIES = libcm.a libcm-o.a libcm-n.a
libcm_a_SOURCES = \
	certread.h \
	certsave.h \
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
libcm_o_a_SOURCES =
if FALSE
libcm_o_a_SOURCES += certsave-o.c keygen-o.c csrgen-o.c submit-do.c
endif
libcm_o_a_CFLAGS = @OPENSSL_CFLAGS@
libcm_n_a_SOURCES =
if TRUE
libcm_n_a_SOURCES += certsave-n.c keygen-n.c csrgen-n.c submit-dn.c
endif
libcm_n_a_CFLAGS = @NSS_CFLAGS@
libcm_a_LIBADD = $(libcm_o_a_OBJECTS) $(libcm_n_a_OBJECTS)
bin_PROGRAMS = cm
sbin_PROGRAMS = cmd
cm_SOURCES = cli.c
cm_LDADD = libcm.a @OPENSSL_LIBS@ @NSS_LIBS@
cmd_SOURCES = cmd.c
cmd_LDADD = libcm.a @OPENSSL_LIBS@ @NSS_LIBS@
