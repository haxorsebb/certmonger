CFLAGS=`rpm --eval '%{optflags} -Wall -Wextra -Wno-unused-parameter -g3 -O0'`
export CFLAGS
set -x
autoheader
autoreconf -i
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-maintainer-mode "$@"
