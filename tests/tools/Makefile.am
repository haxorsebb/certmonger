AM_CFLAGS = $(TALLOC_CFLAGS) $(TEVENT_CFLAGS) $(DBUS_CFLAGS) \
	-I$(builddir)/../../src
listnicks_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
noinst_PROGRAMS = keyiread keygen csrgen submit certread certsave oid2name name2oid iterate prefs notty dates listnicks
LDADD = ../../src/libcm.a $(srcdir)/../../src/env-system.c @OPENSSL_LIBS@ @CERTMONGER_LIBS@ @KRB5_LIBS@ @UUID_LIBS@
