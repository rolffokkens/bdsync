%global gitcommit 0c1d3f79

Name: bdsync
Summary: Kind of rsync for block devices
Version: 0.8
Release: 0.2.%{gitcommit}_git%{?dist}
Group: Applications/Internet
# git clone https://github.com/TargetHolding/bdsync.git
# cd bdsync
# COMMIT=bf31b1d8 ; git archive --format=tar --prefix=bdsync-0.8-$COMMIT/ $COMMIT | gzip > ../bdsync-0.8-$COMMIT.tar.gz
Source: bdsync-%{version}-%{gitcommit}.tar.gz
License: GPL
Requires: openssl
BuildRequires: openssl-devel gcc

%description
bdsync is a kind of rsync for block devices. Bdsync lacks most of of the rsync
functionality and options, but rsync lacks good block device synchronization.

%prep
%setup -q -n bdsync-%{version}-%{gitcommit}

%build
make "CFLAGS=-g -O3"

%check
make test

%install
rm -rf $RPM_BUILD_ROOT/ 
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man1
cp %{name} $RPM_BUILD_ROOT/%{_bindir}/%{name}
cp %{name}.1 $RPM_BUILD_ROOT/%{_mandir}/man1/%{name}.1

%clean
rm -rf $RPM_BUILD_ROOT

%files 
%defattr(-,root,root)
%doc README.md
%attr(755,root,root) %{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*

%postun

%changelog
* Tue Jan 20 2015 Rolf Fokkens <rolf.fokkens@target-holding.nl>
- rebased on github 0.8

* Thu Oct 02 2014 Rolf Fokkens <rolf.fokkens@target-holding.nl>
- rebased on github 0.7

* Thu Jun 28 2012 Rolf Fokkens <rolf@rolffokkens.nl>
- bump release (0.3)

* Sun Jun 24 2012 Rolf Fokkens <rolf@rolffokkens.nl>
- initial package (0.1)
