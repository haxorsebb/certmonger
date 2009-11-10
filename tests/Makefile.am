SUBDIRS = tools
EXTRA_DIST = \
	run-tests.sh functions \
	001-keyiread/run.sh \
	001-keyiread/expected.out \
	002-keygen/run.sh \
	002-keygen/expected.out

check:
	env	srcdir=$(abs_srcdir) \
	builddir=$(abs_builddir) \
	$(srcdir)/run-tests.sh
