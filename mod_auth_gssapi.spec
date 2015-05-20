Summary: GSSAPI authentication module for the Apache HTTP Server
Name: mod_auth_gssapi
Version: 1.0
Release: 1%{?dist}
License: BSD
Group: System Environment/Daemons
URL: http://wiki.moonshot.ja.net/
Source0:	%{name}-%{version}.tar.gz
BuildRequires: httpd-devel, krb5-devel, libtool

%description
The mod_auth_gssapi package provides support for authenticating
users of the Apache HTTP server using the SPNEGO-based HTTP 
Authentication protocol defined in RFC4559.

%prep
%setup -q -n mod_auth_kerb-moonshot

%build
%configure
make

%install
rm -rf $RPM_BUILD_ROOT

# install the DSO
mkdir -p $RPM_BUILD_ROOT%{_libdir}/httpd/modules
install -m 755 .libs/mod_auth_gssapi.so $RPM_BUILD_ROOT%{_libdir}/httpd/modules

# install the conf.d fragment
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d
install -m 644 $RPM_SOURCE_DIR/mod_auth_gssapi.conf \
   $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/auth_gssapi.conf

rm -f $RPM_BUILD_ROOT%{_libdir}/httpd/modules/{*.la,*.so.*}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_sysconfdir}/httpd/conf.d/auth_gssapi.conf
%{_libdir}/httpd/modules/*.so

%changelog
* Fri Jan 16 2015 Stefan Paetow <stefan.paetow@jisc.ac.uk> 1.0-1
- Initial build.
