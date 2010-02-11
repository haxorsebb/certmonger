AM_CFLAGS = $(TALLOC_CFLAGS) $(TEVENT_CFLAGS) $(DBUS_CFLAGS) $(KRB5_CFLAGS)
man_MANS = certmonger.8 getcert.1 getcert-request.1 getcert-list.1 getcert-list-cas.1 getcert-start-tracking.1 getcert-stop-tracking.1 selfsign-getcert.1 ipa-getcert.1 certmaster-getcert.1 getcert-resubmit.1 certmonger-ipa-submit.8 certmonger-certmaster-submit.8
noinst_LIBRARIES = libcm.a libcm-o.a
libcm_a_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
libcm_a_SOURCES = \
	certext.c \
	certext.h \
	certext-n.h \
	certread.c \
	certread.h \
	certread-int.h \
	certread-n.c \
	certsave.c \
	certsave.h \
	certsave-int.h \
	certsave-n.c \
	cm.c \
	cm.h \
	csrgen.c \
	csrgen.h \
	csrgen-int.h \
	csrgen-n.c \
	iterate.c \
	iterate.h \
	keygen.c \
	keygen.h \
	keygen-int.h \
	keygen-n.c \
	keyiread.c \
	keyiread.h \
	keyiread-int.h \
	keyiread-n.c \
	keyiread-n.h \
	log.c \
	log.h \
	netlink.c \
	netlink.h \
	notify.c \
	notify.h \
	oiddict.c \
	oiddict.h \
	pin.c \
	pin.h \
	store-files.c \
	store-gen.c \
	store.h \
	store-int.h \
	submit.c \
	submit-e.c \
	submit-e.h \
	submit.h \
	submit-int.h \
	submit-sn.c \
	submit-x.c \
	submit-x.h \
	subproc.c \
	subproc.h \
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
libcm_o_a_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(OPENSSL_CFLAGS)
libcm_a_LIBADD = $(libcm_o_a_OBJECTS)
bin_PROGRAMS = getcert
pkglibexec_PROGRAMS =
pkglibexecdir = $(libexecdir)/$(PACKAGE)
getcert_SOURCES = getcert.c
getcert_LDADD = libcm.a $(GETCERT_LIBS) $(KRB5_LIBS)
if WITH_IPA
bin_PROGRAMS += ipa-getcert
ipa_getcert_SOURCES = ipa-getcert.c
ipa_getcert_LDADD = $(getcert_LDADD)
endif
if WITH_IPA
bin_PROGRAMS += certmaster-getcert
certmaster_getcert_SOURCES = certmaster-getcert.c
certmaster_getcert_LDADD = $(getcert_LDADD)
endif
bin_PROGRAMS += selfsign-getcert
selfsign_getcert_SOURCES = selfsign-getcert.c
selfsign_getcert_LDADD = $(getcert_LDADD)
sbin_PROGRAMS = certmonger
certmonger_SOURCES = main.c
certmonger_LDADD = libcm.a $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS)
noinst_PROGRAMS = tdbusm-check serial-check nl-check submit-x
tdbusm_check_LDADD = libcm.a $(CERTMONGER_LIBS)
serial_check_LDADD = libcm.a $(CERTMONGER_LIBS)
nl_check_LDADD = libcm.a $(CERTMONGER_LIBS)
submit_x_CFLAGS = $(AM_CFLAGS) -DCM_SUBMIT_X_MAIN
submit_x_SOURCES = submit-x.c submit-e.h submit-x.h
submit_x_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS)
if WITH_CERTMASTER
pkglibexec_PROGRAMS += certmaster-submit
endif
if WITH_IPA
pkglibexec_PROGRAMS += ipa-submit
endif
ipa_submit_SOURCES = ipa.c submit-x.c submit-x.h submit-e.h util.c util.h
ipa_submit_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS)
certmaster_submit_SOURCES = certmaster.c submit-x.c submit-x.h submit-e.h util.c util.h
certmaster_submit_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS)
