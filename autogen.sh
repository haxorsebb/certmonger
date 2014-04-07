CFLAGS=`rpm --eval '%{optflags} -Wall -Wextra -Wno-unused-parameter -g3 -O0'`"${CFLAGS:+ $CFLAGS}"
export CFLAGS
set -x
autoreconf -i -f
./configure --prefix=/usr --sysconfdir=/etc --with-tmpdir=/var/run/certmonger  --localstatedir=/var --enable-maintainer-mode --disable-systemd --disable-sysvinit "$@"
