AM_CFLAGS = @TALLOC_CFLAGS@ @TEVENT_CFLAGS@ @DBUS_CFLAGS@ @KRB5_CFLAGS@
noinst_LIBRARIES = libcm.a libcm-o.a libcm-n.a
libcm_a_SOURCES = \
	certext.h \
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
	keyiread.c \
	keyiread.h \
	keyiread-int.h \
	log.h \
	log.c \
	notify.h \
	notify.c \
	store.h \
	store-int.h \
	store-files.c \
	store-gen.c \
	submit.c \
	submit-e.c \
	submit.h \
	submit-int.h \
	tdbus.c \
	tdbus.h \
	tdbush.c \
	tdbush.h \
	tdbusm.c \
	tdbusm.h
libcm_o_a_SOURCES =
if HAVE_OPENSSL
libcm_o_a_SOURCES += \
	certread-o.c \
	certsave-o.c \
	csrgen-o.c \
	keygen-o.c \
	keyiread-o.c \
	submit-so.c
endif
libcm_o_a_CFLAGS = @OPENSSL_CFLAGS@
libcm_n_a_SOURCES =
libcm_n_a_SOURCES += \
	certext.c \
	certext-n.h \
	certread-n.c \
	certsave-n.c \
	csrgen-n.c \
	keygen-n.c \
	keyiread-n.c \
	submit-sn.c
libcm_n_a_CFLAGS = @NSS_CFLAGS@
libcm_a_LIBADD = $(libcm_o_a_OBJECTS) $(libcm_n_a_OBJECTS)
bin_PROGRAMS = getcert ipa-getcert
sbin_PROGRAMS = certmonger
getcert_SOURCES = getcert.c
getcert_LDADD = libcm.a @GETCERT_LIBS@
ipa_getcert_SOURCES = ipa-getcert.c
ipa_getcert_LDADD = $(getcert_LDADD)
certmonger_SOURCES = main.c
certmonger_LDADD = libcm.a @OPENSSL_LIBS@ @CERTMONGER_LIBS@ @KRB5_LIBS@
noinst_PROGRAMS = tdbusm-check serial-check
tdbusm_check_SOURCES = tdbusm-check.c
tdbusm_check_LDADD = libcm.a @CERTMONGER_LIBS@
serial_check_SOURCES = serial-check.c
serial_check_LDADD = libcm.a @CERTMONGER_LIBS@
