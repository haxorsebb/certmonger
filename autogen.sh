CFLAGS=`rpm --eval '%{optflags} -Wall -Wextra -Wno-unused-parameter'`
export CFLAGS
set -x
autoreconf -i
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-maintainer-mode "$@"
