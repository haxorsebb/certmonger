SUBDIRS = tools
EXTRA_DIST = \
	run-tests.sh functions certmonger.conf \
	001-keyiread/run.sh \
	001-keyiread/expected.out \
	001-keyiread-rsa/run.sh \
	001-keyiread-rsa/expected.out \
	001-keyiread-dsa/run.sh \
	001-keyiread-dsa/expected.out \
	001-keyiread-ec/run.sh \
	001-keyiread-ec/expected.out \
	001-keyiread-ec/expected.out.2 \
	001-keyiread-ec/expected.out.3 \
	001-keyiread-ec/expected.out.4 \
	002-keygen/prequal.sh \
	002-keygen/run.sh \
	002-keygen/expected.out \
	002-keygen-rsa/prequal.sh \
	002-keygen-rsa/run.sh \
	002-keygen-rsa/expected.out \
	002-keygen-dsa/prequal.sh \
	002-keygen-dsa/run.sh \
	002-keygen-dsa/expected.out \
	002-keygen-ec/prequal.sh \
	002-keygen-ec/run.sh \
	002-keygen-ec/expected.out \
	002-keygen-ec/expected.out.2 \
	002-keygen-ec/expected.out.3 \
	002-keygen-ec/expected.out.4 \
	003-csrgen/run.sh \
	003-csrgen/expected.out \
	003-csrgen-rsa/run.sh \
	003-csrgen-rsa/expected.out \
	003-csrgen-dsa/run.sh \
	003-csrgen-dsa/expected.out \
	003-csrgen-ec/run.sh \
	003-csrgen-ec/expected.out \
	004-selfsign/run.sh \
	004-selfsign/expected.out \
	004-selfsign-rsa/run.sh \
	004-selfsign-rsa/expected.out \
	004-selfsign-dsa/run.sh \
	004-selfsign-dsa/expected.out \
	004-selfsign-ec/run.sh \
	004-selfsign-ec/expected.out \
	005-dbusm/run.sh \
	005-dbusm/expected.out \
	006-serial/run.sh \
	006-serial/expected.out \
	007-certsave/prequal.sh \
	007-certsave/run.sh \
	007-certsave/expected.out \
	007-certsave-dbm/prequal.sh \
	007-certsave-dbm/run.sh \
	007-certsave-dbm/expected.out \
	007-certsave-sql/prequal.sh \
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
	020-xparse/*.xml \
	021-resume/expected.out \
	021-resume/run.sh \
	022-base64/expected.out \
	022-base64/run.sh \
	023-cadata/expected.out \
	023-cadata/run.sh \
	024-citerate/expected.out \
	024-citerate/run.sh \
	025-casave/expected.out \
	025-casave/run.sh \
	026-local/expected.out \
	026-local/run.sh \
	027-hooks/expected.out \
	027-hooks/run.sh \
	028-dbus/expected.out \
	028-dbus/entry 028-dbus/bogus-entry \
	028-dbus/prequal.sh \
	028-dbus/run.sh \
	028-dbus/runsub.sh \
	028-dbus/simpleprop.py \
	028-dbus/walk.py

subdirs = \
	001-keyiread \
	001-keyiread-rsa \
	002-keygen \
	002-keygen-rsa \
	003-csrgen \
	003-csrgen-rsa \
	004-selfsign \
	004-selfsign-rsa \
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
	019-dparse \
	021-resume \
	022-base64 \
	023-cadata \
	024-citerate \
	025-casave \
	026-local \
	027-hooks \
	028-dbus

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

if HAVE_DSA
subdirs += \
	001-keyiread-dsa \
	002-keygen-dsa \
	003-csrgen-dsa \
	004-selfsign-dsa
endif

if HAVE_EC
subdirs += \
	001-keyiread-ec \
	002-keygen-ec \
	003-csrgen-ec \
	004-selfsign-ec
endif

check: all
	for required in certutil pk12util openssl diff cmp mktemp dos2unix unix2dos dbus-launch ; do \
		which $$required || exit 1; \
	done
	env	srcdir=$(srcdir) \
	builddir=$(top_builddir)/tests \
	$(srcdir)/run-tests.sh $(subdirs)
