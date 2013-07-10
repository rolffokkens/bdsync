Summary: A alterneta sudo utility
Name: bdsync
Version: 0.5
Release: 0
Group: Applications/Internet
Source: bdsync-%{version}.tgz
License: GPL
Buildroot: /tmp/%{name}-%{version}-root
Requires: openssl
BuildRequires: openssl-devel gcc

%description
bdsync is a kind of rsync for block devices. Bdsync lacks most of of the rsync
functionality and options, but rsync lacks good block device synchronization.

%prep
%setup -q 

%build
make

%install
rm -rf $RPM_BUILD_ROOT/ 
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man1
cp %{name} $RPM_BUILD_ROOT/%{_bindir}/
cp %{name}.1* $RPM_BUILD_ROOT/%{_mandir}/man1/

%clean
rm -rf $RPM_BUILD_ROOT

%files 
%defattr(-,root,root)
%doc README
%attr(755,root,root) %{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*

%postun

%changelog
* Tue Jun 28 2012 Rolf Fokkens <rolf@rolffokkens.nl>
- bump release (0.3)
* Sun Jun 24 2012 Rolf Fokkens <rolf@rolffokkens.nl>
- initial package (0.1)
