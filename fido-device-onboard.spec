%define dracutlibdir %{_prefix}/lib/dracut
%bcond_without check
%global __cargo_skip_build 0
%global __cargo_is_lib() false
%global gitversion 43f7674dad4abc470cdab505fbf49f571539cea8

Name:           fido-device-onboard
Version:        0.1.0
Release:        1%{?dist}
Summary:        An implementation of the FIDO Device Onboard Specification written in rust

License:        BSD 3
URL:            https://github.com/fedora-iot/fido-device-onboard-rs/
Source:         %{url}/archive/%{gitversion}/%{name}-rs-%{gitversion}.tar.gz
Source1:        %{name}-rs-%{gitversion}-vendor.tar.gz

ExclusiveArch:  %{rust_arches}
# RHBZ 1869980
ExcludeArch:    s390x i686 %{power64}

BuildRequires: rust-toolset
BuildRequires: systemd

%description
%{summary}.

%prep
%autosetup -n %{name}-rs-%{gitversion} -p1
%cargo_prep -V 1

%build
%cargo_build

%install
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-client-linuxapp
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-manufacturing-client
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-manufacturing-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-owner-onboarding-server
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-rendezvous-server
# TODO(runcom): we may want to move this to {_bindir} so admins can use it directly
install -D -m 0755 -t %{buildroot}%{_libexecdir}/fdo target/release/fdo-owner-tool
install -D -m 0644 -t %{buildroot}%{_unitdir} examples/systemd/*
install -D -m 0644 -t %{buildroot}%{_datadir}/fdo examples/config/*
# 52fdo
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/module-setup.sh
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client-generator
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client-service
install -D -m 0755 -t %{buildroot}%{dracutlibdir}/modules.d/52fdo dracut/52fdo/manufacturing-client.service

%package -n fdo-init
Summary: dracut module for device initialization
License: BSD 3
%description -n fdo-init
%{summary}

%files -n fdo-init
%license LICENSE
%{dracutlibdir}/modules.d/52fdo/*
%{_libexecdir}/fdo/fdo-manufacturing-client

%package -n fdo-owner-onboarding-server
Summary: FDO Owner Onboarding Server implementation
License: BSD 3
%description -n fdo-owner-onboarding-server
%{summary}

%files -n fdo-owner-onboarding-server
%license LICENSE
%{_libexecdir}/fdo/fdo-owner-onboarding-server
%{_datadir}/fdo/owner-onboarding-server.yml
%{_unitdir}/fdo-owner-onboarding-server.service

%package -n fdo-rendezvous-server
Summary: FDO Rendezvous Server implementation
License: BSD 3
%description -n fdo-rendezvous-server
%{summary}

%files -n fdo-rendezvous-server
%license LICENSE
%{_libexecdir}/fdo/fdo-rendezvous-server
%{_datadir}/fdo/rendezvous-server.yml
%{_unitdir}/fdo-rendezvous-server.service

%package -n fdo-manufacturing-server
Summary: FDO Manufacturing Server implementation
License: BSD 3
%description -n fdo-manufacturing-server
%{summary}

%files -n fdo-manufacturing-server
%license LICENSE
%{_libexecdir}/fdo/fdo-manufacturing-server
%{_datadir}/fdo/manufacturing-server.yml
%{_datadir}/fdo/rendezvous-info.yml
%{_unitdir}/fdo-manufacturing-server.service

%package -n fdo-client
Summary: FDO Client implementation
License: BSD 3
%description -n fdo-client
%{summary}

%files -n fdo-client
%license LICENSE
%{_libexecdir}/fdo/fdo-client-linuxapp
%{_unitdir}/fdo-client-linuxapp.service

%package -n fdo-owner-cli
Summary: FDO Owner tools implementation
License: BSD 3
%description -n fdo-owner-cli
%{summary}

%files -n fdo-owner-cli
%license LICENSE
%{_libexecdir}/fdo/fdo-owner-tool
%{_datadir}/fdo/owner-addresses.yml

%changelog
* Tue Oct 5 2021 Antonio Murdaca <amurdaca@redhat.com> - 0.1.0-1
- initial release