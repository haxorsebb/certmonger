AM_CFLAGS = $(TALLOC_CFLAGS) $(TEVENT_CFLAGS) $(DBUS_CFLAGS) $(KRB5_CFLAGS) \
	    $(XMLRPC_CFLAGS) $(IDN_CFLAGS) $(UUID_CFLAGS) $(LDAP_CFLAGS)
LDFLAGS =
if PIE
CFLAGS += -fPIC
LDFLAGS += -fPIC -pie
endif
if NOW
LDFLAGS += -Wl,-z,relro,-z,now
endif
man_MANS = certmonger.8 getcert.1 getcert-request.1 getcert-list.1 getcert-list-cas.1 getcert-start-tracking.1 getcert-stop-tracking.1 selfsign-getcert.1 ipa-getcert.1 certmaster-getcert.1 getcert-resubmit.1 certmonger-ipa-submit.8 certmonger-certmaster-submit.8 certmonger-dogtag-ipa-renew-agent-submit.8 certmonger.conf.5 getcert-refresh.1 getcert-refresh-ca.1 local-getcert.1 certmonger-local-submit.8 getcert-status.1
pkgsysconfdir = $(sysconfdir)/$(PACKAGE)
pkgsysconf_DATA = certmonger.conf
EXTRA_PROGRAMS =
install-data-hook::
	chmod go-rwx $(DESTDIR)$(pkgsysconfdir)/certmonger.conf
	mkdir -m 700 -p $(DESTDIR)@CM_STORE_CAS_DIRECTORY@
	mkdir -m 700 -p $(DESTDIR)@CM_STORE_REQUESTS_DIRECTORY@
	mkdir -m 700 -p $(DESTDIR)@CM_STORE_LOCAL_CA_DIRECTORY@
noinst_LIBRARIES = libcm.a libcm-o.a
libcm_a_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
libcm_a_SOURCES = \
	cadata.c \
	cadata.h \
	casave.c \
	casave.h \
	canalyze.c \
	canalyze.h \
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
	env-shared.c \
	hook.c \
	hook.h \
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
	kudict.c \
	kudict.h \
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
	util.h \
	util-m.c \
	util-m.h \
	util-n.c \
	util-n.h
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
	submit-o.c \
	submit-o.h \
	util-o.c \
	util-o.h
endif
libcm_o_a_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(OPENSSL_CFLAGS)
libcm_a_LIBADD = $(libcm_o_a_OBJECTS)
bin_PROGRAMS = getcert
pkglibexec_PROGRAMS = certmonger-session
pkglibexecdir = $(libexecdir)/$(PACKAGE)
getcert_SOURCES = getcert.c tm.c tm.h
getcert_LDADD = libcm.a $(GETCERT_LIBS) $(KRB5_LIBS) $(LTLIBICONV)
if WITH_IPA
bin_PROGRAMS += ipa-getcert
ipa_getcert_SOURCES = ipa-getcert.c tm.c tm.h
ipa_getcert_LDADD = $(getcert_LDADD)
endif
if WITH_IPA
bin_PROGRAMS += certmaster-getcert
certmaster_getcert_SOURCES = certmaster-getcert.c tm.c tm.h
certmaster_getcert_LDADD = $(getcert_LDADD)
endif
bin_PROGRAMS += selfsign-getcert
selfsign_getcert_SOURCES = selfsign-getcert.c tm.c tm.h
selfsign_getcert_LDADD = $(getcert_LDADD)
bin_PROGRAMS += local-getcert
local_getcert_SOURCES = local-getcert.c tm.c tm.h
local_getcert_LDADD = $(getcert_LDADD)
sbin_PROGRAMS = certmonger
certmonger_SOURCES = main.c env-system.c tm.c tm.h
certmonger_LDADD = libcm.a \
		   $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(IDN_LIBS) \
		   $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV)
certmonger_session_SOURCES = main.c env-session.c tm.c tm.h
certmonger_session_LDADD = libcm.a \
		   $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(IDN_LIBS) \
		   $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV)
noinst_PROGRAMS = tdbusm-check serial-check nl-check submit-x tlslayer toklist
tdbusm_check_SOURCES = tdbusm-check.c tm.c tm.h
tdbusm_check_LDADD = libcm.a $(CERTMONGER_LIBS)
serial_check_LDADD = libcm.a $(CERTMONGER_LIBS) $(LTLIBICONV)
nl_check_LDADD = libcm.a $(CERTMONGER_LIBS)
submit_x_CFLAGS = $(AM_CFLAGS) -DCM_SUBMIT_X_MAIN
submit_x_SOURCES = submit-x.c submit-x.h submit-u.c submit-u.h log.c log.h \
	tm.c tm.h
submit_x_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) \
		 $(GMP_LIBS) $(UUID_LIBS)
toklist_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
toklist_LDADD = $(NSS_LIBS)
if WITH_CERTMASTER
pkglibexec_PROGRAMS += certmaster-submit
endif
if WITH_IPA
pkglibexec_PROGRAMS += ipa-submit
endif
pkglibexec_PROGRAMS += dogtag-ipa-renew-agent-submit local-submit
noinst_PROGRAMS += submit-h submit-d
ipa_submit_SOURCES = ipa.c store.h store-gen.c \
		submit-x.c submit-x.h submit-u.c submit-u.h \
		submit-e.h util.c util.h log.c log.h tm.c tm.h
ipa_submit_LDADD = $(XMLRPC_LIBS) $(LDAP_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) \
		   $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV)
certmaster_submit_SOURCES = certmaster.c submit-x.c submit-x.h \
		submit-e.h submit-u.c submit-u.h util.c util.h log.c log.h \
		tm.c tm.h
certmaster_submit_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) \
			  $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV)
dogtag_ipa_renew_agent_submit_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS) \
				       $(NSS_CFLAGS) $(CURL_CFLAGS)
dogtag_ipa_renew_agent_submit_SOURCES = dogtag.c submit-d.c submit-d.h \
		submit-h.c submit-h.h util-m.c util-m.h util-n.c util-n.h \
		submit-u.c submit-u.h submit-e.h util.c util.h log.c log.h \
		store.h store-gen.c tm.c tm.h prefs.c prefs.h env.h env-system.c
dogtag_ipa_renew_agent_submit_LDADD = $(CURL_LIBS) $(XML_LIBS) $(NSS_LIBS) \
				      $(OPENSSL_LIBS) $(TALLOC_LIBS) \
				      $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV)
local_submit_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
local_submit_SOURCES = local.c env.h store.h store-gen.c submit-o.c submit-o.h \
		       submit-u.c submit-u.h env-session.c log.c log.h \
		       prefs.c prefs.h prefs-o.c prefs-o.h tm.c tm.h \
		       util.c util.h util-o.c util-o.h
local_submit_LDADD = $(NSS_LIBS) $(OPENSSL_LIBS) $(TALLOC_LIBS) $(UUID_LIBS)
submit_d_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS) $(XML_CFLAGS) -DCM_SUBMIT_D_MAIN
submit_d_SOURCES = submit-d.c submit-d.h submit-h.c submit-h.h \
		   submit-u.c submit-u.h log.c log.h tm.c tm.h util-m.c util-m.h
submit_d_LDADD = libcm-o.a $(CURL_LIBS) $(OPENSSL_LIBS) $(XML_LIBS) \
		 $(TALLOC_LIBS) $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV)
submit_h_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS) $(XML_CFLAGS) -DCM_SUBMIT_H_MAIN
submit_h_SOURCES = submit-h.c submit-h.h log.c log.h tm.c tm.h
submit_h_LDADD = $(CURL_LIBS) $(XML_LIBS) $(TALLOC_LIBS) $(LTLIBICONV)
tlslayer_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(OPENSSL_SSL_CFLAGS) \
	-DCM_TLSLAYER_MAIN
tlslayer_SOURCES = tlslayer.c tlslayer-n.c \
	tlslayer.h tlslayer-int.h
if HAVE_OPENSSL
tlslayer_SOURCES += tlslayer-o.c
endif
tlslayer_LDADD = $(NSS_LIBS) $(OPENSSL_SSL_LIBS) $(TALLOC_LIBS)
