AC_INIT(certmonger,0.0)
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE
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
UPCASE_PACKAGE_NAME=`echo "${PACKAGE_NAME}" | tr '[a-z]' '[A-Z]'`
AC_DEFINE_UNQUOTED(CM_FILE_STORE_DIRECTORY_ENV,"${UPCASE_PACKAGE_NAME}_FILE_STORE_DIR",
		   [Define to the name of the environment variable which can specify the path for tracking files.])

PKG_CHECK_MODULES(OPENSSL,openssl)

if pkg-config mozilla-nss 2> /dev/null ; then
	PKG_CHECK_MODULES(NSS,mozilla-nss)
else
	PKG_CHECK_MODULES(NSS,nss)
fi

AC_DEFINE_UNQUOTED(CM_DEFAULT_PUBKEY_TYPE,cm_key_rsa,[Define to the default public key type.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_RSA_MODULUS,65537,[Define to the default RSA key modulus.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_PUBKEY_SIZE,2048,[Define to the default public key size.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_TTL_LIST,[30*24*60*60,7*24*60*60,3*24*60*60,2*24*60*60,1*24*60*60],[Define to the list of default time-left thresholds at which we need to warn the user.])

AC_OUTPUT(Makefile src/Makefile)
