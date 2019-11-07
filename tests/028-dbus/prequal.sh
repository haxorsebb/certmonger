#!/bin/bash
DBUSSEND=`which dbus-send 2> /dev/null`
if test -z "$DBUSSEND" ; then
	echo dbus-send not found
	exit 1
fi
DBUSDAEMON=`which dbus-daemon 2> /dev/null`
if test -z "$DBUSDAEMON" ; then
	echo dbus-daemon not found
	exit 1
fi

PYTHON=${PYTHON:-python3}

if ! $PYTHON -c 'import os' 2> /dev/null ; then
	echo $PYTHON not found
	exit 1
fi
if ! $PYTHON -c 'import dbus' 2> /dev/null ; then
	echo $PYTHON-dbus not found
	exit 1
fi
if ! $PYTHON -c 'import xml' 2> /dev/null ; then
	echo $PYTHON-xml not found
	exit 1
fi
if ! $PYTHON -c 'import xml.etree.ElementTree' 2> /dev/null ; then
	echo $PYTHON-xml does not include etree.ElementTree
	exit 1
fi
