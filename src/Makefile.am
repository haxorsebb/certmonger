AM_CFLAGS = @TALLOC_CFLAGS@ @TEVENT_CFLAGS@ @DBUS_CFLAGS@
noinst_LIBRARIES = libcm.a libcm-o.a libcm-n.a
libcm_a_SOURCES = \
	certread.c \
	certread.h \
	certread-int.h \
	certsave.c \
	certsave.h \
	certsave-int.h \
	cm.c \
	cm.h \
	csrgen.c \
	csrgen.h \
	csrgen-int.h \
	iterate.c \
	iterate.h \
	keygen.c \
	keygen.h \
	keygen-int.h \
	log.h \
	log.c \
	notify.h \
	notify.c \
	store.h \
	store-int.h \
	store-files.c \
	store-gen.c \
	submit.c \
	submit.h \
	submit-int.h \
	tdbus.c \
	tdbus.h
libcm_o_a_SOURCES =
if HAVE_OPENSSL
libcm_o_a_SOURCES += certread-o.c certsave-o.c keygen-o.c csrgen-o.c submit-do.c
endif
libcm_o_a_CFLAGS = @OPENSSL_CFLAGS@
libcm_n_a_SOURCES =
libcm_n_a_SOURCES += certread-n.c certsave-n.c keygen-n.c csrgen-n.c submit-dn.c
libcm_n_a_SOURCES += certext.c certext.h
libcm_n_a_CFLAGS = @NSS_CFLAGS@
libcm_a_LIBADD = $(libcm_o_a_OBJECTS) $(libcm_n_a_OBJECTS)
bin_PROGRAMS = cm
sbin_PROGRAMS = cmd
cm_SOURCES = cli.c
cm_LDADD = libcm.a @OPENSSL_LIBS@ @NSS_LIBS@ @TEVENT_LIBS@ @TALLOC_LIBS@ @DBUS_LIBS@
cmd_SOURCES = cmd.c
cmd_LDADD = libcm.a @OPENSSL_LIBS@ @NSS_LIBS@ @TEVENT_LIBS@ @TALLOC_LIBS@ @DBUS_LIBS@
