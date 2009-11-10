SUBDIRS = tools
EXTRA_DIST = \
	run-tests.sh functions \
	001-keyiread/run.sh \
	001-keyiread/expected.out \
	002-keygen/run.sh \
	002-keygen/expected.out \
	003-csrgen/run.sh \
	003-csrgen/expected.out

check:
	env	srcdir=$(abs_srcdir) \
	builddir=$(abs_builddir) \
	$(abs_srcdir)/run-tests.sh
