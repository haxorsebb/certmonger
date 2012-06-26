AM_CFLAGS = $(TALLOC_CFLAGS) $(TEVENT_CFLAGS) $(DBUS_CFLAGS) \
	-I$(builddir)/../../src
LDADD = ../../src/libcm.a $(srcdir)/../../src/env-system.c libtm.a $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(UUID_LIBS)

noinst_PROGRAMS = keyiread keygen csrgen submit certread certsave oid2name name2oid iterate prefs dates listnicks pem2base base2pem dparse
noinst_LIBRARIES = libtm.a

libtm_a_SOURCES = ../../src/tm.h tm.c

listnicks_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)

dparse_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS)
dparse_SOURCES = dparse.c ../../src/submit-d.c
dparse_LDADD = $(LDADD) $(XML_LIBS)
