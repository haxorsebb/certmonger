Name:		certmonger
Version:	0.13
Release:	1%{?dist}
Summary:	Certificate status monitor and PKI enrollment client

Group:		System Environment/Daemons
License:	GPLv3+
URL:		http://certmonger.fedorahosted.org
Source0:	http://fedorahosted.org/released/certmonger/certmonger-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	dbus-devel, nspr-devel, nss-devel, openssl-devel
BuildRequires:	libtalloc-devel, libtevent-devel
BuildRequires:	xmlrpc-c-devel
%if 0
# Required for 'make check':
#  for diff and cmp
BuildRequires:	diffutils
#  for expect
BuildRequires:	expect
#  for mktemp, which was absorbed into coreutils at some point
BuildRequires:	mktemp
#  for certutil and pk12util
BuildRequires:	nss-tools
#  for openssl
BuildRequires:	openssl
%endif
Requires(post):	/sbin/chkconfig, /sbin/service
Requires(preun):	/sbin/chkconfig, /sbin/service

%description
Certmonger is a service which is primarily concerned with getting your
system enrolled with a certificate authority (CA) and keeping it enrolled.

%prep
%setup -q

%build
%configure --with-file-store-dir=%{_localstatedir}/lib/certmonger
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_localstatedir}/lib/certmonger/{cas,requests}
%if 0%{?fedora} <= 9
mkdir -p $RPM_BUILD_ROOT/%{_initrddir}
install -m755 src/certmonger.init $RPM_BUILD_ROOT/%{_initrddir}/certmonger
%else
mkdir -p $RPM_BUILD_ROOT/%{_initddir}
install -m755 src/certmonger.init $RPM_BUILD_ROOT/%{_initddir}/certmonger
%endif

%check
# Needs to be able to create pseudoterminals to drive certutil.
: make check

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add certmonger

%postun
if test $1 -gt 0 ; then
	/sbin/service certmonger condrestart 2>&1 > /dev/null
fi
exit 0

%preun
if test $1 -eq 0 ; then
	/sbin/service certmonger stop 2>&1 > /dev/null
	/sbin/chkconfig --del certmonger
fi
exit 0

%files
%defattr(-,root,root,-)
%doc README LICENSE STATUS doc/*.txt
%config /etc/dbus-1/system.d/*
%if 0%{?fedora} <= 9
%{_initrddir}/certmonger
%else
%{_initddir}/certmonger
%endif
%{_bindir}/*
%{_sbindir}/certmonger
%{_mandir}/man*/*
%{_libexecdir}/%{name}
%{_localstatedir}/lib/certmonger

%changelog
* Tue Nov 24 2009 Nalin Dahyabhai <nalin@redhat.com> 0.13-1
- update to 0.13
  - change the default so that we default to trying to auto-refresh
    certificates unless told otherwise
  - preemptively enforce limitations on request nicknames so that they
    make valid D-Bus object path components

* Tue Nov 24 2009 Nalin Dahyabhai <nalin@redhat.com> 0.12-1
- update to 0.12
  - add a crucial bit of error reporting when CAs reject our requests
  - count the number of configured CAs correctly

* Mon Nov 23 2009 Nalin Dahyabhai <nalin@redhat.com> 0.11-1
- update to 0.11
  - add XML-RPC submission for certmaster and IPA
  - prune entries with duplicate names from the data store

* Fri Nov 13 2009 Nalin Dahyabhai <nalin@redhat.com> 0.10-1
- update to 0.10
  - add some compiler warnings and then fix them

* Fri Nov 13 2009 Nalin Dahyabhai <nalin@redhat.com> 0.9-1
- update to 0.9
  - run external submission helpers correctly
  - fix signing of signing requests generated for keys stored in files
  - only care about new interface and route notifications from netlink,
    and ignore notifications that don't come from pid 0
  - fix logic for determining expiration status
  - correct the version number in self-signed certificates

* Tue Nov 10 2009 Nalin Dahyabhai <nalin@redhat.com> 0.8-1
- update to 0.8
  - encode windows UPN values in requests correctly
  - watch for netlink routing changes and restart stalled submission requests
  - 'getcert resubmit' can force a regeneration of the CSR and submission

* Fri Nov  6 2009 Nalin Dahyabhai <nalin@redhat.com> 0.7-1
- update to 0.7
  - first cut at a getting-started document
  - refactor some internal key handling with NSS
  - check for duplicate request nicknames at add-time

* Tue Nov  3 2009 Nalin Dahyabhai <nalin@redhat.com> 0.6-1
- update to 0.6
  - man pages
  - 'getcert stop-tracking' actually makes the server forget now
  - 'getcert request -e' was redundant, dropped the -e option
  - 'getcert request -i' now sets the request nickname
  - 'getcert start-tracking -i' now sets the request nickname

* Mon Nov  2 2009 Nalin Dahyabhai <nalin@redhat.com> 0.5-1
- update to 0.5
  - packaging fixes
  - add a selfsign-getcert client
  - self-signed certs now get basic constraints and their own serial numbers
  - accept id-ms-kp-sc-logon as a named EKU value in a request

* Thu Oct 29 2009 Nalin Dahyabhai <nalin@redhat.com> 0.4-1
- update to 0.4

* Thu Oct 22 2009 Nalin Dahyabhai <nalin@redhat.com> 0.1-1
- update to 0.1

* Sun Oct 18 2009 Nalin Dahyabhai <nalin@redhat.com> 0.0-1
- initial package
