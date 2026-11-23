Name:    redborder-vortex
Version: %{__version}
Release: %{__release}%{?dist}

License: GNU AGPLv3
URL: https://github.com/redBorder/redborder-vortex
Source0: %{name}-%{version}.tar.gz

BuildRequires: rust cargo gcc gcc-c++ cmake python3-devel openssl-devel libcurl-devel
Requires: python3-libs redborder-pythonlibs
Requires(pre): shadow-utils
Provides: logstash = %{version}-%{release}

Summary: High-performance Rust and Python telemetry pipeline engine for redBorder NG.
Group:   System Environment/Daemons

%global debug_package %{nil}

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi
cargo build --release

%install
mkdir -p %{buildroot}/usr/bin
install -p -m 755 target/release/redborder-vortex %{buildroot}/usr/bin/redborder-vortex
mkdir -p %{buildroot}/usr/share/%{name}/plugins
install -p -m 644 plugins/*.py %{buildroot}/usr/share/%{name}/plugins/
mkdir -p %{buildroot}/etc/%{name}
install -D -m 644 redborder-vortex.service %{buildroot}/usr/lib/systemd/system/%{name}.service
install -D -m 644 packaging/rpm/config.yml %{buildroot}/etc/%{name}/config.yml

%clean
rm -rf %{buildroot}

%pre
getent group %{name} >/dev/null || groupadd -r %{name}
getent passwd %{name} >/dev/null || \
    useradd -r -g %{name} -d / -s /sbin/nologin \
    -c "User of %{name} service" %{name}
exit 0

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(755,root,root)
/usr/bin/redborder-vortex
%defattr(644,root,root)
/usr/share/%{name}/plugins/*.py
%config(noreplace) /etc/%{name}/config.yml
/usr/lib/systemd/system/%{name}.service

%changelog
* Mon Oct 26 2026 redBorder <support@redborder.com> - 0.1.0-1
- Initial Rust + PyO3 release of redborder-vortex replacing Logstash
