CFLAGS=`rpm --eval '%{optflags} -Wall -Wextra -Wno-unused-parameter -g3 -O0'`
export CFLAGS
set -x
autoreconf -i -f
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-maintainer-mode "$@"
