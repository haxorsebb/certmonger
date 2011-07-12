#!/bin/sh

tmpfile=`mktemp ${TMPDIR:-/tmp}/runtestsXXXXXX`
if test -z "$tmpfile" ; then
	echo Error creating temporary file.
	exit 1
else
	trap 'rm -f "$tmpfile"' EXIT
fi
tmpdir=`mktemp -d ${TMPDIR:-/tmp}/runtestsXXXXXX`
if test -z "$tmpdir" ; then
	echo Error creating temporary directory.
	exit 1
else
	trap 'rm -f "$tmpfile"; rm -fr "$tmpdir"' EXIT
fi
unset DBUS_SESSION_BUS_ADDRESS
eval `dbus-launch --sh-syntax`
if test -z "$DBUS_SESSION_BUS_ADDRESS" ; then
	echo Error launching session bus.
	exit 1
else
	trap 'rm -f "$tmpfile"; rm -fr "$tmpdir"; kill "$DBUS_SESSION_BUS_PID"' EXIT
fi

srcdir=${srcdir:-`pwd`}
pushd "$srcdir" > /dev/null
srcdir=`pwd`
popd > /dev/null

builddir=${builddir:-`pwd`}
pushd "$builddir" > /dev/null
builddir=`pwd`
popd > /dev/null

toolsdir=${toolsdir:-${builddir}/tools}
export builddir
export srcdir
export toolsdir
export tmpdir
cd "$builddir"

CERTMONGER_CONFIG_DIR=${srcdir}
export CERTMONGER_CONFIG_DIR

stat=0
subdirs=
if test $# -eq 0 ; then
	subdirs=`cd "$srcdir"; ls -1 | grep '^[0-9]'`
fi
for testid in "$@" $subdirs ; do
	if test -x "$srcdir"/"$testid"/run.sh ; then
		mkdir -p "$builddir"/"$testid"
		pushd "$srcdir"/"$testid" > /dev/null
		rm -fr "$tmpdir"/*
		if test -r ./expected.out ; then
			echo -n "Running test "$testid"... "
			./run.sh "$tmpdir" > "$tmpfile" 2> "$tmpdir"/errors
			if cmp "$tmpfile" expected.out ; then
				stat=0
				echo "OK"
				cp $tmpfile "$builddir"/"$testid"/actual.out
				cp "$tmpdir"/errors "$builddir"/"$testid"/actual.err
			else
				stat=1
				echo "FAIL"
				diff -u expected.out "$tmpfile" | sed s,"^\+\+\+ $tmpfile","+++ actual",g
				cp $tmpfile "$builddir"/"$testid"/actual.out
				cp "$tmpdir"/errors "$builddir"/"$testid"/actual.err
			fi
		else
			echo "Running test "$testid"."
			./run.sh "$tmpdir"
			stat=$?
		fi
		popd > /dev/null
		if test $stat -ne 0 ; then
			break
		fi
	else
		echo "No test defined in "$testid", skipping."
	fi
done
exit $stat
