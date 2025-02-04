# Generated by rust2rpm 27
%bcond check 1

# the only binary we provide now is conformance, which does not do anything useful
%global cargo_install_bin 0
# prevent library files from being installed
%global cargo_install_lib 0

%global revision 6166f28a939242ee454fc846de5ed87d2ac5a69c
%global short_revision 6166f28a
%global revision_date 20241219

Name:           kryoptic
Version:        0.1.0^%{revision_date}.git%{short_revision}
Release:        %autorelease
Summary:        PKCS #11 software token written in Rust

SourceLicense:  GPL-3.0-or-later
# Apache-2.0
# Apache-2.0 OR BSL-1.0
# Apache-2.0 OR MIT
# BSD-2-Clause OR Apache-2.0 OR MIT
# BSD-3-Clause
# MIT
# MIT OR Apache-2.0
# MIT-0 OR Apache-2.0
# Unlicense OR MIT
License: Apache-2.0 AND (Apache-2.0 OR BSL-1.0) AND (Apache-2.0 OR MIT) AND (BSD-2-Clause OR Apache-2.0 OR MIT) AND (BSD-3-Clause) AND (MIT) AND (MIT OR Apache-2.0) AND (MIT-0 OR Apache-2.0) AND (Unlicense OR MIT)
# LICENSE.dependencies contains a full license breakdown

URL:            https://github.com/latchset/kryoptic
Source:         https://github.com/latchset/kryoptic/archive/%{revision}.zip

BuildRequires:  cargo-rpm-macros >= 26
BuildRequires:  openssl-devel

%global _description %{expand:
A PKCS #11 software token written in Rust.}

%description %{_description}

%prep
%autosetup -n %{name}-%{revision} -p1
%cargo_prep

%generate_buildrequires
%cargo_generate_buildrequires -f dynamic,nssdb,standard

%build
CONFDIR=%{_sysconfdir} %cargo_build -f dynamic,nssdb,standard
%{cargo_license_summary -f dynamic,nssdb,standard}
%{cargo_license -f dynamic,nssdb,standard} > LICENSE.dependencies

%install
%cargo_install -f dynamic,nssdb,standard
install -Dp target/rpm/libkryoptic_pkcs11.so $RPM_BUILD_ROOT/%{_libdir}/libkryoptic_pkcs11.so

%if %{with check}
%check
%cargo_test -f dynamic,nssdb,standard
%endif

%files
%license LICENSE.txt
%license LICENSE.dependencies
%doc README.md
%doc dummy.txt
%{_libdir}/libkryoptic_pkcs11.so


%changelog
%autochangelog
