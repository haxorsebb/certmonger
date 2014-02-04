CFLAGS=`rpm --eval '%{optflags} -Wall -Wextra -Wno-unused-parameter -g3 -O0'`"${CFLAGS:+ $CFLAGS}"
export CFLAGS
set -x
autoreconf -i -f
./configure --prefix=/usr --sysconfdir=/etc --enable-systemd --enable-sysvinit=/etc/rc.d/init.d --with-tmpdir=/var/run/certmonger  --localstatedir=/var --enable-maintainer-mode "$@"
