Name:		certmonger
Version:	0.4
Release:	1%{?dist}
Summary:	Certificate status monitor and PKI enrollment client

Group:		System Environment/Daemons
License:	GPLv3+
URL:		http://certmonger.fedorahosted.org
Source0:	certmonger-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	dbus-devel, nspr-devel, nss-devel, openssl-devel
BuildRequires:	libtalloc-devel, libtevent-devel
Requires(post):	/sbin/chkconfig
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
mkdir -p $RPM_BUILD_ROOT/%{_initddir}
mkdir -p $RPM_BUILD_ROOT/%{_localstatedir}/lib/certmonger/{cas,requests}
install -m755 src/certmonger.init $RPM_BUILD_ROOT/%{_initddir}/certmonger

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
%doc README LICENSE STATUS doc
/etc/dbus-1/system.d/*
%config(noreplace) %{_initddir}/certmonger
%{_bindir}/*
%{_sbindir}/*
%{_libexecdir}/*
%{_localstatedir}/lib/certmonger

%changelog
* Thu Oct 22 2009 Nalin Dahyabhai <nalin@redhat.com> 0.1-1
* Sun Oct 18 2009 Nalin Dahyabhai <nalin@redhat.com> 0.0-1
- initial package
