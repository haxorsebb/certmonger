#!/bin/bash
set -x
autoreconf -i -f
configure_dist_target_only=true \
./configure --disable-maintainer-mode --disable-systemd --disable-sysvinit \
	--without-idn --without-openssl --without-gmp \
	--disable-ec --disable-dsa \
	"$@"
VERSION=`grep AC_INIT configure.ac | sed -e 's:^.*,::g' -e 's:).*::g'`
make dist
rpmbuild -ts --nodeps certmonger-$VERSION.tar.gz
