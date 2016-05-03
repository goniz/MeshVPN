Name: peervpn
Version: 0.44
Release: 4%{?dist}
Summary: PeerVPN allows you to create full-mesh VPN networks	

Group: Applications/Internet	
License: GPLv2+
URL: http://www.peervpn.net	
%global commit0 CURRENT_COMMIT
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})
%global gittag0 master
Source0: https://github.com/hideman-ltd/%{name}/archive/%{commit0}.tar.gz#/%{commit0}.tar.gz

BuildRequires: openssl-devel
Requires: openssl

%description
PeerVPN is a simple to use full-mesh VPN implementation

%prep
%setup -n peervpn-%{commit0}

%build
make %{?_smp_mflags}

%install
%make_install 

%files
%defattr(-,root,root,-)
/sbin/peervpn
%doc

%changelog

