AM_CFLAGS = $(TALLOC_CFLAGS) $(TEVENT_CFLAGS) $(DBUS_CFLAGS) $(KRB5_CFLAGS) \
	    $(XMLRPC_CFLAGS) $(IDN_CFLAGS) $(UUID_CFLAGS) $(LDAP_CFLAGS) \
	    -I$(builddir)/../../src
LDADD = libtools.a ../../src/libcm.a $(srcdir)/../../src/env-system.c \
	libtools.a $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(IDN_LIBS) \
	$(GMP_LIBS) $(UUID_LIBS) $(RESOLV_LIBS) $(LTLIBICONV)

noinst_SCRIPTS = cachain.sh

if PIE
CFLAGS += -fPIC
LDFLAGS += -fPIC -pie
endif

noinst_PROGRAMS = keyiread keygen csrgen submit certread certsave oid2name name2oid iterate prefs dates listnicks pem2base base2pem dparse payload checksig base64 cadata citerate casave hooks libexecdir canon srv addcinfo
noinst_LIBRARIES = libtools.a
if HAVE_OPENSSL
noinst_PROGRAMS += pk7parse pk7env scepgen pk7verify pk7decrypt
endif

libtools_a_SOURCES = ../../src/tm.h tm.c tools.h tools.c
listnicks_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)

payload_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
checksig_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
addcinfo_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)

dparse_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS)
dparse_SOURCES = dparse.c ../../src/submit-d.c
dparse_LDADD = $(LDADD) $(XML_LIBS)

citerate_SOURCES = citerate.c ../../src/store-gen.c

srv_SOURCES = srv.c ../../src/srvloc.c
srv_LDADD = $(LDADD)
