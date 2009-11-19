SUBDIRS = tools
EXTRA_DIST = \
	run-tests.sh functions \
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
	008-certread/run.sh \
	008-certread/expected.out \
	009-oiddict/run.sh \
	009-oiddict/expected.out \
	010-iterate/run.sh \
	010-iterate/expected.out

check:
	env	srcdir=$(abs_srcdir) \
	builddir=$(abs_builddir) \
	$(abs_srcdir)/run-tests.sh
