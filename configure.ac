AC_INIT(certmonger,0.0)
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_PROG_RANLIB
AC_CONFIG_HEADER(src/config.h)
if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Wextra"
fi

AC_ARG_WITH(file-store-dir,
AS_HELP_STRING([--with-file-store-dir=/var/lib/certmonger],[directory to use for storing data]),
mylocalstatedir=$withval,
mylocalstatedir="$localstatedir/lib/${PACKAGE_NAME}")
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,$prefix,g"`
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,$ac_default_prefix,g"`
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,,g"`
AC_DEFINE_UNQUOTED(CM_FILE_STORE_DIRECTORY,"$mylocalstatedir",
		   [Define to the default path for tracking files.])
AC_DEFINE_UNQUOTED(CM_FILE_STORE_DIRECTORY_ENV,"${PACKAGE_NAME}_FILE_STORE_DIR",
		   [Define to the name of the environment variable which can specify the path for tracking files.])

PKG_CHECK_MODULES(OPENSSL,openssl)

AC_OUTPUT(Makefile src/Makefile)
