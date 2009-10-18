EXTRA_FILES = doc/*.txt
SUBDIRS = src dbus
EXTRA_DIST = certmonger.spec LICENSE README STATUS doc

VERSION=$(shell rpm -q --specfile $(top_srcdir)/certmonger.spec --qf '%{version}\n' --define 'dist %{nil}' | head -n1)
RELEASE=$(shell rpm -q --specfile $(top_srcdir)/certmonger.spec --qf '%{release}\n' --define 'dist %{nil}' | head -n1)
GITTAG=certmonger-$(shell rpm -q --specfile $(top_srcdir)/certmonger.spec --qf '%{version}\n' --define 'dist %{nil}' 2> /dev/null | head -n1)
distdir=$(shell rpm -q --specfile --qf '%{name}-%{version}\n' --define 'dist %{nil}' $(top_srcdir)/certmonger.spec | head -n1)

tag:
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
		make dist;\
		mkdir -p $$tmpdir/rpm-build-top;\
		rpmbuild \
			--define "_topdir $$tmpdir/rpm-build-top" \
			--define "_sourcedir $$tmpdir/rpm-build-top" \
			--define "_specdir $$tmpdir/rpm-build-top" \
			--define "_builddir $$tmpdir/rpm-build-top" \
			--define "_srpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			-tb $(distdir).tar.gz;\
		cp -v $(distdir).tar.gz $(ARCHIVEOUTDIR)/;\
		rm -fr $$tmpdir;\
	fi
