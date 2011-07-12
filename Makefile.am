ACLOCAL_AMFLAGS = -I m4
EXTRA_FILES = doc/*.txt
SUBDIRS = po src dbus systemd sysvinit tests
EXTRA_DIST = config.rpath \
	     certmonger.spec LICENSE README STATUS doc src/certmonger.conf.in

DISTCHECK_CONFIGURE_FLAGS = --enable-systemd --enable-sysvinit --with-tmpdir=/var/run/certmonger

VERSION=$(PACKAGE_VERSION)
RELEASE=
GITTAG=certmonger-$(VERSION)

tag:
	tx pull
	git tag $(GITTAG)

force-tag:
	git tag -f $(GITTAG)

ORIGIN=$(shell git config remote.origin.url 2> /dev/null || /bin/pwd)
ARCHIVEOUTDIR=$(shell cd $(top_srcdir) && pwd)

local-archive:
	$(MAKE) archive ORIGIN=$(ARCHIVEOUTDIR)

archive:
	repo=`pwd`; \
	tmpdir=`mktemp -d /tmp/make_archive_XXXXXX`; \
	if test -d "$$tmpdir" ; then \
		git clone $(ORIGIN) $$tmpdir/certmonger;\
		cd $$tmpdir/certmonger;\
		git checkout $(GITTAG);\
		./autogen.sh;\
		tx pull;\
		make distcheck;\
		mkdir -p $$tmpdir/rpm-build-top;\
		rpmbuild \
			--define "_topdir $$tmpdir/rpm-build-top" \
			--define "_sourcedir $$tmpdir/rpm-build-top" \
			--define "_specdir $$tmpdir/rpm-build-top" \
			--define "_builddir $$tmpdir/rpm-build-top" \
			--define "_buildrootdir $$tmpdir/rpm-build-top" \
			--define "_srpmdir $$tmpdir/rpm-build-top" \
			--define "_srcrpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			-tb $(distdir).tar.gz;\
		cp -v $(distdir).tar.gz $(ARCHIVEOUTDIR)/;\
		rm -fr $$tmpdir;\
	fi
