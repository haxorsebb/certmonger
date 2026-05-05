#!/bin/sh
if test `id -u` -eq 0 ; then
	echo "This test won't work right if run as root."
	exit 1
fi
