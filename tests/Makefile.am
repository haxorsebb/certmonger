SUBDIRS = tools
EXTRA_DIST = \
	run-tests.sh functions certmonger.conf \
	001-keyiread/run.sh \
	001-keyiread/expected.out \
	002-keygen/run.sh \
	002-keygen/expected.out \
	003-csrgen/run.sh \
	003-csrgen/expected.out \
	004-selfsign/run.sh \
	004-selfsign/expected.out \
	005-dbusm/run.sh \
	005-dbusm/expected.out \
	006-serial/run.sh \
	006-serial/expected.out \
	007-certsave/run.sh \
	007-certsave/expected.out \
	007-certsave-dbm/run.sh \
	007-certsave-dbm/expected.out \
	007-certsave-sql/run.sh \
	007-certsave-sql/expected.out \
	008-certread/run.sh \
	008-certread/expected.out \
	009-oiddict/run.sh \
	009-oiddict/expected.out \
	010-iterate/run.sh \
	010-iterate/expected.out \
	011-dbinit/expected.out \
	011-dbinit/run.sh \
	011-dbinit-dbm/expected.out \
	011-dbinit-dbm/run.sh \
	011-dbinit-sql/expected.out \
	011-dbinit-sql/run.sh \
	012-dbadd/expected.out \
	012-dbadd/run.sh \
	012-dbadd-dbm/expected.out \
	012-dbadd-dbm/run.sh \
	012-dbadd-sql/expected.out \
	012-dbadd-sql/run.sh \
	013-enckey/expected.out \
	013-enckey/run.sh \
	013-enckey-dbm/expected.out \
	013-enckey-dbm/run.sh \
	013-enckey-sql/expected.out \
	013-enckey-sql/run.sh \
	014-prefs/expected.out \
	014-prefs/run.sh \
	015-lockedkey/expected.out \
	015-lockedkey/run.sh \
	015-lockedkey-dbm/expected.out \
	015-lockedkey-dbm/run.sh \
	015-lockedkey-sql/expected.out \
	015-lockedkey-sql/run.sh \
	016-dates/expected.out \
	016-dates/run.sh \
	017-notoken/expected.out \
	017-notoken/run.sh \
	017-notoken-dbm/expected.out \
	017-notoken-dbm/run.sh \
	017-notoken-sql/expected.out \
	017-notoken-sql/run.sh \
	018-pembase/expected.out \
	018-pembase/run.sh \
	019-dparse/expected.out \
	019-dparse/run.sh \
	019-dparse/good.* \
	019-dparse/bad.* \
	020-xparse/*.xml

subdirs = \
	001-keyiread \
	002-keygen \
	003-csrgen \
	004-selfsign \
	005-dbusm \
	006-serial \
	007-certsave \
	008-certread \
	009-oiddict \
	010-iterate \
	011-dbinit \
	012-dbadd \
	013-enckey \
	014-prefs \
	015-lockedkey \
	016-dates \
	017-notoken \
	018-pembase \
	019-dparse

if HAVE_DBM_NSSDB
subdirs += \
	007-certsave-dbm \
	011-dbinit-dbm \
	012-dbadd-dbm \
	013-enckey-dbm \
	015-lockedkey-dbm \
	017-notoken-dbm
endif

if HAVE_SQL_NSSDB
subdirs += \
	007-certsave-sql \
	011-dbinit-sql \
	012-dbadd-sql \
	013-enckey-sql \
	015-lockedkey-sql \
	017-notoken-sql
endif

check: all
	for required in certutil pk12util openssl expect diff cmp mktemp dos2unix unix2dos dbus-launch ; do \
		which $$required || exit 1; \
	done
	env	srcdir=$(srcdir) \
	builddir=$(top_builddir)/tests \
	$(srcdir)/run-tests.sh $(subdirs)
