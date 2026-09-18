# https://fedoraproject.org/wiki/How_to_create_an_RPM_package
Name:           pimd
Version:        3.0.0
Release:        1%{?dist}
Summary:        pimd, the PIM-SM/SSM v2 multicast daemon

Group:          System Environment/Daemons
License:        BSD
URL:            https://github.com/ocochard/%{name}
Source0:        %{url}/releases/download/%{version}/%{name}-%{version}.tar.gz
Source1:        %{name}.init
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}

BuildRequires:  make gcc

%description
This is pimd, a lightweight, stand-alone implementation of Protocol Independent
Multicast-Sparse Mode that may be freely distributed and/or deployed under the
BSD license.  The project implements PIM-SM as specified in RFC 7761 (STD 83),
with the Bootstrap Router mechanism of RFC 5059 and Source Specific Multicast,
with a few noted exceptions (see doc/rfc7761-compliance.md for details).


%prep
%setup -q


%build
[ -x configure ] || ./autogen.sh
%configure
%make_build


%install
%{__mkdir_p} %{buildroot}%{_sysconfdir}
%{__install} -m 0644 pimd.conf %{buildroot}%{_sysconfdir}/
%{__mkdir_p} %{buildroot}%{_initrddir}
%{__install} -m 0755 %{SOURCE1} %{buildroot}%{_initrddir}/%{name}
%{__mkdir_p} %{buildroot}%{_sbindir}
%{__install} -m 0755 src/%{name} %{buildroot}%{_sbindir}/%{name}
%{__install} -m 0755 src/pimctl %{buildroot}%{_sbindir}/pimctl
%{__mkdir_p} %{buildroot}%{_mandir}/man5
%{__install} -m 0644 man/pimd.conf.5 %{buildroot}%{_mandir}/man5/pimd.conf.5
%{__mkdir_p} %{buildroot}%{_mandir}/man8
%{__install} -m 0644 man/pimd.8 %{buildroot}%{_mandir}/man8/pimd.8
%{__install} -m 0644 man/pimctl.8 %{buildroot}%{_mandir}/man8/pimctl.8


%clean
%{__rm} -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc doc/AUTHORS doc/CREDITS doc/LICENSE.mrouted doc/rfc7761-compliance.md
%license LICENSE
%config %{_sysconfdir}/pimd.conf
%{_initrddir}/%{name}
%{_sbindir}/%{name}
%{_sbindir}/pimctl
%{_mandir}/man5/pimd.conf.5.gz
%{_mandir}/man8/pimd.8.gz
%{_mandir}/man8/pimctl.8.gz


%post
chkconfig --add %{name}


%changelog
* Fri Sep 18 2026 cochard@gmail.com - 3.0.0
  Build from a release tarball rather than a branch export, package pimctl
  and the pimctl(8) and pimd.conf(5) manual pages, and take the binaries
  and manual pages from where GNU Configure and Build leaves them.

* Sun May 21 2017 troglobit@gmail.com - 2.4.0

* Mon Jan 27 2014 timeos@zssos.sk - 2.1.8

  fix for - pimd segfaults in igmp_read() (https://github.com/troglobit/pimd/issues/29)
* Thu Dec 31 2013 timeos@zssos.sk - 2.1.8

  Initial - Built from upstream version.
