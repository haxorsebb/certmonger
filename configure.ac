AC_INIT(certmonger,0.0)
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_PROG_RANLIB
AC_CONFIG_HEADER(src/config.h)
if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Wextra"
fi
AC_OUTPUT(Makefile src/Makefile)
