AM_CFLAGS = $(TALLOC_CFLAGS) $(TEVENT_CFLAGS) $(DBUS_CFLAGS) $(KRB5_CFLAGS) $(XMLRPC_CFLAGS) $(UUID_CFLAGS)
man_MANS = certmonger.8 getcert.1 getcert-request.1 getcert-list.1 getcert-list-cas.1 getcert-start-tracking.1 getcert-stop-tracking.1 selfsign-getcert.1 ipa-getcert.1 certmaster-getcert.1 getcert-resubmit.1 certmonger-ipa-submit.8 certmonger-certmaster-submit.8 certmonger.conf.5
pkgsysconfdir = $(sysconfdir)/$(PACKAGE)
pkgsysconf_DATA = certmonger.conf
EXTRA_PROGRAMS =
install-data-hook::
	chmod go-rwx $(DESTDIR)/$(pkgsysconfdir)/certmonger.conf
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
	env.h \
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
	prefs.c \
	prefs.h \
	prefs-n.c \
	prefs-n.h \
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
	submit-u.c \
	submit-u.h \
	submit-x.c \
	submit-x.h \
	subproc.c \
	subproc.h \
	tdbus.c \
	tdbus.h \
	tdbush.c \
	tdbush.h \
	tdbusm.c \
	tdbusm.h \
	util.c \
	util.h
libcm_o_a_SOURCES =
if HAVE_OPENSSL
libcm_o_a_SOURCES += \
	certread-o.c \
	certsave-o.c \
	csrgen-o.c \
	keygen-o.c \
	keyiread-o.c \
	prefs-o.h \
	prefs-o.c \
	submit-so.c \
	util-o.c \
	util-o.h
endif
libcm_o_a_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(OPENSSL_CFLAGS)
libcm_a_LIBADD = $(libcm_o_a_OBJECTS)
bin_PROGRAMS = getcert
pkglibexec_PROGRAMS = certmonger-session
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
certmonger_SOURCES = main.c env-system.c
certmonger_LDADD = libcm.a \
		   $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(UUID_LIBS)
certmonger_session_SOURCES = main.c env-session.c
certmonger_session_LDADD = libcm.a \
		   $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(UUID_LIBS)
noinst_PROGRAMS = tdbusm-check serial-check nl-check submit-x
tdbusm_check_LDADD = libcm.a $(CERTMONGER_LIBS)
serial_check_LDADD = libcm.a $(CERTMONGER_LIBS)
nl_check_LDADD = libcm.a $(CERTMONGER_LIBS)
submit_x_CFLAGS = $(AM_CFLAGS) -DCM_SUBMIT_X_MAIN
submit_x_SOURCES = submit-x.c submit-x.h submit-u.c submit-u.h log.c log.h
submit_x_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) $(UUID_LIBS)
if WITH_CERTMASTER
pkglibexec_PROGRAMS += certmaster-submit
endif
if WITH_IPA
pkglibexec_PROGRAMS += ipa-submit
endif
if WITH_CURL_AND_XML
EXTRA_PROGRAMS += dogtag-submit
noinst_PROGRAMS += submit-h submit-d
endif
ipa_submit_SOURCES = ipa.c submit-x.c submit-x.h submit-u.c submit-u.h \
		submit-e.h util.c util.h log.c log.h
ipa_submit_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) $(UUID_LIBS)
certmaster_submit_SOURCES = certmaster.c submit-x.c submit-x.h \
		submit-e.h submit-u.c submit-u.h util.c util.h log.c log.h
certmaster_submit_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) \
			  $(UUID_LIBS)
dogtag_submit_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS) $(CURL_LIBS)
dogtag_submit_SOURCES = dogtag.c submit-d.c submit-d.h submit-h.c submit-h.h \
		submit-u.c submit-u.h submit-e.h util.c util.h log.c log.h
dogtag_submit_LDADD = $(CURL_LIBS) $(XML_LIBS) $(TALLOC_LIBS) $(UUID_LIBS)
submit_d_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS) $(XML_CFLAGS) -DCM_SUBMIT_D_MAIN
submit_d_SOURCES = submit-d.c submit-d.h submit-h.c submit-h.h \
		   submit-u.c submit-u.h log.c log.h
submit_d_LDADD = $(CURL_LIBS) $(XML_LIBS) $(TALLOC_LIBS) $(UUID_LIBS)
submit_h_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS) $(XML_CFLAGS) -DCM_SUBMIT_H_MAIN
submit_h_SOURCES = submit-h.c submit-h.h log.c log.h
submit_h_LDADD = $(CURL_LIBS) $(XML_LIBS) $(TALLOC_LIBS)
