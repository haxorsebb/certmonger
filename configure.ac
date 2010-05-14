AC_INIT(certmonger,0.22)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_MACRO_DIR(m4)
AM_MAINTAINER_MODE
AC_PROG_CC
AC_PROG_RANLIB
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION(0.17)
ALL_LINGUAS="`ls -1 $srcdir/po/*.po | xargs -n 1 basename | xargs -n 1 -I'{}' basename '{}' .po`"
AC_CHECK_HEADERS(sys/types.h sys/socket.h linux/types.h linux/netlink.h linux/rtnetlink.h,,,[
	#ifdef HAVE_SYS_TYPES_H
	#include <sys/types.h>
	#endif
	#ifdef HAVE_SYS_SOCKET_H
	#include <sys/socket.h>
	#endif
	#ifdef HAVE_LINUX_TYPES_H
	#include <linux/types.h>
	#endif
	#ifdef HAVE_LINUX_NETLINK_H
	#include <linux/netlink.h>
	#endif
])
AC_CONFIG_HEADER(src/config.h)
if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Wextra"
fi

mysbindir="$sbindir"
mysbindir=`eval echo $mysbindir | sed "s,NONE,$prefix,g"`
mysbindir=`eval echo $mysbindir | sed "s,NONE,$exec_prefix,g"`
mysbindir=`eval echo $mysbindir | sed "s,NONE,$ac_default_prefix,g"`
mysbindir=`eval echo $mysbindir | sed "s,NONE,,g"`
AC_SUBST(mysbindir)

UPCASE_PACKAGE_NAME=`echo "${PACKAGE_NAME}" | tr '[a-z]' '[A-Z]'`
mysysconfdir="$sysconfdir/${PACKAGE_NAME}"
mysysconfdir=`eval echo $mysysconfdir | sed "s,NONE,$prefix,g"`
mysysconfdir=`eval echo $mysysconfdir | sed "s,NONE,$ac_default_prefix,g"`
mysysconfdir=`eval echo $mysysconfdir | sed "s,NONE,,g"`
AC_DEFINE_UNQUOTED(CM_STORE_CONFIG_DIRECTORY,"$mysysconfdir",
		   [Define to the directory which holds configuration files.])
AC_DEFINE_UNQUOTED(CM_STORE_CONFIG_DIRECTORY_ENV,"${UPCASE_PACKAGE_NAME}_CONFIG_DIR",
		   [Define to the name of the environment variable which can specify the directory which holds configuration files.])
CM_STORE_CONFIG_DIRECTORY_ENV="${UPCASE_PACKAGE_NAME}_CONFIG_DIR"
AC_SUBST(CM_STORE_CONFIG_DIRECTORY_ENV)
mylibexecdir="$libexecdir/${PACKAGE_NAME}"
mylibexecdir=`eval echo $mylibexecdir | sed "s,NONE,$prefix,g"`
mylibexecdir=`eval echo $mylibexecdir | sed "s,NONE,$ac_default_prefix,g"`
mylibexecdir=`eval echo $mylibexecdir | sed "s,NONE,,g"`
AC_ARG_WITH(file-store-dir,
AS_HELP_STRING([--with-file-store-dir=/var/lib/certmonger],[directory to use for storing data]),
mylocalstatedir=$withval,
mylocalstatedir="$localstatedir/lib/${PACKAGE_NAME}")
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,$prefix,g"`
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,$ac_default_prefix,g"`
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,,g"`
AC_DEFINE_UNQUOTED(CM_STORE_REQUESTS_DIRECTORY,"$mylocalstatedir/requests",
		   [Define to the default path for request tracking files.])
CM_STORE_REQUESTS_DIRECTORY="$mylocalstatedir/requests"
AC_SUBST(CM_STORE_REQUESTS_DIRECTORY)
AC_DEFINE_UNQUOTED(CM_STORE_REQUESTS_DIRECTORY_ENV,"${UPCASE_PACKAGE_NAME}_REQUESTS_DIR",
		   [Define to the name of the environment variable which can specify the directory for tracking requests.])
CM_STORE_REQUESTS_DIRECTORY_ENV="${UPCASE_PACKAGE_NAME}_REQUESTS_DIR"
AC_SUBST(CM_STORE_REQUESTS_DIRECTORY_ENV)
AC_DEFINE_UNQUOTED(CM_STORE_REQUEST_DEFAULTS,"$mylocalstatedir/defaults",
		   [Define to the location of run-time defaults for requests.])
UPCASE_PACKAGE_NAME=`echo "${PACKAGE_NAME}" | tr '[a-z]' '[A-Z]'`
AC_DEFINE_UNQUOTED(CM_STORE_REQUEST_DEFAULTS_ENV,"${UPCASE_PACKAGE_NAME}_REQUEST_DEFAULTS_FILE",
		   [Define to the name of the environment variable which can specify the path for the request defaults file.])
AC_DEFINE_UNQUOTED(CM_STORE_CAS_DIRECTORY,"$mylocalstatedir/cas",
		   [Define to the default path for CA tracking files.])
UPCASE_PACKAGE_NAME=`echo "${PACKAGE_NAME}" | tr '[a-z]' '[A-Z]'`
AC_DEFINE_UNQUOTED(CM_STORE_CAS_DIRECTORY_ENV,"${UPCASE_PACKAGE_NAME}_CAS_DIR",
		   [Define to the name of the environment variable which can specify the directory for tracking CAs.])
mylocaledir="$localedir"
mylocaledir=`eval echo $mylocaledir | sed "s,NONE,$prefix,g"`
mylocaledir=`eval echo $mylocaledir | sed "s,NONE,$ac_default_prefix,g"`
mylocaledir=`eval echo $mylocaledir | sed "s,NONE,,g"`
AC_DEFINE_UNQUOTED(MYLOCALEDIR,"$mylocaledir",
		   [Define to the name of the directory under which locale data will be installed.])

CM_DBUS_NAME=org.fedorahosted.certmonger
AC_DEFINE_UNQUOTED(CM_DBUS_NAME,"$CM_DBUS_NAME",
		   [Define to the name of the certmonger service.])
AC_SUBST(CM_DBUS_NAME)
CM_DBUS_BASE_PATH=/org/fedorahosted/certmonger
AC_DEFINE_UNQUOTED(CM_DBUS_BASE_PATH,"$CM_DBUS_BASE_PATH",
		   [Define to the path of the certmonger main node.])
AC_DEFINE_UNQUOTED(CM_DBUS_RECONNECT_TIMEOUT,30,
		   [Define to the amount of time to wait between attempts to reconnect to the message bus if we get disconnected.])

PKG_CHECK_MODULES(TALLOC,talloc)
PKG_CHECK_MODULES(TEVENT,tevent)
PKG_CHECK_MODULES(DBUS,dbus-1)
PKG_CHECK_MODULES(CERTMONGER,dbus-1 talloc tevent nss)
PKG_CHECK_MODULES(GETCERT,dbus-1 talloc)

have_libxml=true
if pkg-config libxml-2.0 ; then
	PKG_CHECK_MODULES(XML,libxml-2.0)
	have_libxml=true
fi

have_libcurl=false
if pkg-config libcurl ; then
	PKG_CHECK_MODULES(CURL,libcurl)
	have_libcurl=true
fi

if $have_libcurl ; then
	if $have_libxml ; then
		AM_CONDITIONAL(WITH_CURL_AND_XML,true)
	fi
fi

dnl PKG_CHECK_MODULES(XMLRPC,xmlrpc_client) # Not provided in upstream versions.
savedCFLAGS="$CFLAGS"
CFLAGS=
AC_ARG_VAR(XMLRPC_C_CONFIG,[the full path of the xmlrpc-c-config command])
AC_PATH_PROG(XMLRPC_C_CONFIG,[xmlrpc-c-config],,[$PATH$PATH_SEPARATOR/usr/xmlrpc/bin$PATH_SEPARATOR/usr/xmlrpc-c/bin])
if test -z "$XMLRPC_C_CONFIG" ; then
	AC_MSG_ERROR(xmlrpc-c-config not found)
fi
AC_MSG_CHECKING(for XMLRPC CFLAGS)
XMLRPC_CFLAGS=`${XMLRPC_C_CONFIG} client --cflags`
AC_MSG_RESULT([$XMLRPC_CFLAGS])
AC_SUBST(XMLRPC_CFLAGS)
AC_MSG_CHECKING(for XMLRPC LIBS)
XMLRPC_LIBS=`${XMLRPC_C_CONFIG} client --libs`
AC_MSG_RESULT([$XMLRPC_LIBS])
AC_SUBST(XMLRPC_LIBS)
CFLAGS="$savedCFLAGS"

savedCFLAGS="$CFLAGS"
CFLAGS=
AC_ARG_VAR(KRB5_CONFIG,[the full path of the krb5-config command])
AC_PATH_PROG(KRB5_CONFIG,[krb5-config],,[$PATH$PATH_SEPARATOR/usr/kerberos/bin$PATH_SEPARATOR/usr/krb5/bin])
if test -z "$KRB5_CONFIG" ; then
	AC_MSG_ERROR(krb5-config not found)
fi
AC_MSG_CHECKING(for krb5 CFLAGS)
KRB5_CFLAGS=`${KRB5_CONFIG} --cflags`
AC_MSG_RESULT([$KRB5_CFLAGS])
AC_SUBST(KRB5_CFLAGS)
AC_MSG_CHECKING(for krb5 LIBS)
KRB5_LIBS=`${KRB5_CONFIG} --libs`
AC_MSG_RESULT([$KRB5_LIBS])
AC_SUBST(KRB5_LIBS)
CFLAGS="$savedCFLAGS"

AC_ARG_WITH(openssl,
	    AS_HELP_STRING(--without-openssl,
	    		   [build without support for storing keys and certificates in files]),
	    withopenssl=$withval,
	    withopenssl=yes)

AM_CONDITIONAL(HAVE_OPENSSL,test x$withopenssl != xno)
if test x$withopenssl != xno ; then
	PKG_CHECK_MODULES(OPENSSL,openssl)
	AC_DEFINE(HAVE_OPENSSL,1,[Define if you have OpenSSL.])
	CFLAGSsave="$CFLAGS"
	LIBSsave="$LIBS"
	CFLAGS="$OPENSSL_CFLAGS $LIBS"
	LIBS="$OPENSSL_LIBS $LIBS"
	AC_CHECK_DECLS([OpenSSL_add_all_algorithms,OpenSSL_add_ssl_algorithms],,,[#include <openssl/ssl.h>])
	CFLAGS="$CFLAGSsave"
	LIBS="$LIBSsave"
fi

AM_CONDITIONAL(HAVE_NSS,test x$withnss != xno)
if test x$withnss != xno ; then
	if pkg-config mozilla-nss 2> /dev/null ; then
		PKG_CHECK_MODULES(NSS,mozilla-nss)
	else
		PKG_CHECK_MODULES(NSS,nss)
	fi
	AC_DEFINE(HAVE_NSS,1,[Define if you have NSS.])
fi

AC_DEFINE_UNQUOTED(CM_DEFAULT_KEY_STORAGE_TYPE,cm_key_storage_nssdb,[Define to the default type of storage used for keys.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_KEY_STORAGE_LOCATION,"/etc/pki/nssdb",[Define to the default location of storage used for keys.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_KEY_TOKEN,NULL,[Define to the default token used for holding keys.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_KEY_NICKNAME,"Server-Cert",[Define to the default nickname given to keys.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_STORAGE_TYPE,cm_cert_storage_nssdb,[Define to the default type of storage used for certificates.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_STORAGE_LOCATION,"/etc/pki/nssdb",[Define to the default location of storage used for certificates.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_TOKEN,NULL,[Define to the default token used to store certificates.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_NICKNAME,"Server-Cert",[Define to the default nickname given to certificates.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_PUBKEY_TYPE,cm_key_rsa,[Define to the default public key type.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_RSA_MODULUS,0x10001,[Define to the default RSA key modulus.])
CM_DEFAULT_PUBKEY_SIZE=2048
AC_DEFINE_UNQUOTED(CM_DEFAULT_PUBKEY_SIZE,$CM_DEFAULT_PUBKEY_SIZE,[Define to the default public key size.])
AC_SUBST(CM_DEFAULT_PUBKEY_SIZE)
CM_DEFAULT_TTL_LIST="2419200, 604800, 259200, 172800, 86400"
AC_DEFINE_UNQUOTED(CM_DEFAULT_TTL_LIST,[$CM_DEFAULT_TTL_LIST],[Define to the list of default time-left thresholds at which we need to warn the user.])
AC_SUBST(CM_DEFAULT_TTL_LIST)
AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_SUBJECT_CN,"localhost",[Define to the last-ditch default CN value for a signing request.])
CM_DEFAULT_CERT_LIFETIME=1y
AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_LIFETIME,"$CM_DEFAULT_CERT_LIFETIME",[Define to the default certificate lifetime for self-signed certificates.])
AC_SUBST(CM_DEFAULT_CERT_LIFETIME)
AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_SERIAL,"01",[Define to the default starting serial number for self-signed certificates.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_NOTIFICATION_METHOD,cm_notification_syslog,[Define to the default method of notification.])
AC_DEFINE_UNQUOTED(CM_DEFAULT_NOTIFICATION_MAIL,"root",[Define to the address where notification mail should be sent by default.])
CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY=daemon.notice
AC_SUBST(CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY)
AC_DEFINE_UNQUOTED(CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY,"$CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY",[Define to the syslog facility from which notification messages should be sent by default.])
AC_DEFINE(CM_DELAY_SOON,5,[Define to the time to wait for something that will happen soon.])
AC_DEFINE(CM_DELAY_SOONISH,30,[Define to the time to wait for something that will happen soon, but not that soon.])
AC_DEFINE(CM_DELAY_CA_POLL,(7 * 24 * 60 * 60),[Define to the time to wait between attempts to see if the CA issued a certificate.])
AC_DEFINE(CM_DELAY_NETLINK,(60),[Define to the time to wait after a netlink routing notification to retry submissions.])

CM_SELF_SIGN_CA_NAME=SelfSign
AC_SUBST(CM_SELF_SIGN_CA_NAME)
AC_DEFINE_UNQUOTED(CM_SELF_SIGN_CA_NAME,"$CM_SELF_SIGN_CA_NAME",[Define to the name that the internal self-signing not-really-a-CA will be known by.])

AC_DEFINE(WITH_IPA,1,[Define to ensure that there's always an IPA CA defined.])
CM_IPA_CA_NAME=IPA
AC_SUBST(CM_IPA_CA_NAME)
AC_DEFINE_UNQUOTED(CM_IPA_CA_NAME,"$CM_IPA_CA_NAME",[Define to the name that the default IPA CA will be known by.])
AC_DEFINE_UNQUOTED(CM_IPA_HELPER_PATH,"$mylibexecdir/ipa-submit",[Define to the path of the IPA submission helper.])
AM_CONDITIONAL(WITH_IPA,true)

AC_DEFINE(WITH_CERTMASTER,1,[Define to ensure that there's always a CERTMASTER CA defined.])
CM_CERTMASTER_CA_NAME=certmaster
AC_SUBST(CM_CERTMASTER_CA_NAME)
AC_DEFINE_UNQUOTED(CM_CERTMASTER_CA_NAME,"$CM_CERTMASTER_CA_NAME",[Define to the name that the default certmaster CA will be known by.])
AC_DEFINE_UNQUOTED(CM_CERTMASTER_HELPER_PATH,"$mylibexecdir/certmaster-submit",[Define to the path of the CERTMASTER submission helper.])
AM_CONDITIONAL(WITH_CERTMASTER,true)

AC_CONFIG_COMMANDS(src_introspect_sh,[chmod +x src/introspect.sh])
AC_OUTPUT(Makefile src/Makefile dbus/Makefile tests/Makefile tests/tools/Makefile dbus/certmonger.conf src/certmonger.init src/introspect.sh src/certmonger.8 src/getcert.1 src/getcert-request.1 src/getcert-list.1 src/getcert-list-cas.1 src/getcert-start-tracking.1 src/getcert-stop-tracking.1 src/selfsign-getcert.1 src/ipa-getcert.1 src/getcert-resubmit.1 src/certmonger-certmaster-submit.8 src/certmonger-ipa-submit.8 src/certmaster-getcert.1 src/certmonger.conf.5 po/Makefile.in src/certmonger.conf)
