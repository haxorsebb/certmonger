#!/bin/bash -x
set -e
if test -s /etc/os-release; then
	source /etc/os-release
else
	if test -s /etc/system-release ; then
		PRETTY_NAME=`cat /etc/system-release`
	else
		PRETTY_NAME=unknown
	fi
fi
# Print PRETTY_NAME periodically, so it's easier to know where we are if we're
# paging through a log of results from multiple containers.
echo '['"${PRETTY_NAME}"']'
rm -fr /build/certmonger
cp -a /source /build/certmonger
cd /build/certmonger
echo '['"${PRETTY_NAME}"']'
export CFLAGS="-Wall -Wextra -Wno-unused-parameter"
./configure --prefix=/usr --sysconfdir=/etc --with-tmpdir=/var/run/certmonger  --localstatedir=/var --disable-maintainer-mode --enable-srv-location --disable-systemd --disable-sysvinit
echo '['"${PRETTY_NAME}"']'
make distcheck
