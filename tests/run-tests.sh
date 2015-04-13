#!/bin/bash

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
mkdir -m 500 "$tmpdir"/rosubdir
mkdir -m 700 "$tmpdir"/rwsubdir
trap 'rm -f "$tmpfile"; chmod u+w "$tmpdir"/* ; rm -fr "$tmpdir"' EXIT
unset DBUS_SESSION_BUS_ADDRESS
eval `dbus-launch --sh-syntax`
if test -z "$DBUS_SESSION_BUS_ADDRESS" ; then
	echo Error launching session bus.
	exit 1
else
	trap 'rm -f "$tmpfile"; chmod u+w "$tmpdir"/* ; rm -fr "$tmpdir"; kill "$DBUS_SESSION_BUS_PID"' EXIT
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
	if test -x "$srcdir"/"$testid"/prequal.sh ; then
		if ! "$srcdir"/"$testid"/prequal.sh ; then
			echo "Skipping test "$testid"."
			continue
		fi
	fi
	RUNVALGRIND=${VALGRIND:+valgrind --log-file="$builddir"/"$testid"/valgrind/%p.log --trace-children=yes --track-origins=yes}
	if test -n "$RUNVALGRIND" ; then
		rm -fr "$builddir"/"$testid"/valgrind
		mkdir -p "$builddir"/"$testid"/valgrind
	fi
	if test -x "$srcdir"/"$testid"/run.sh ; then
		pushd "$srcdir"/"$testid" > /dev/null
		rm -fr "$tmpdir"/*
		mkdir -m 500 "$tmpdir"/rosubdir
		mkdir -m 700 "$tmpdir"/rwsubdir
		if test -r ./expected.out ; then
			echo -n "Running test "$testid"... "
			$RUNVALGRIND ./run.sh "$tmpdir" > "$tmpfile" 2> "$tmpdir"/errors
			sed -i "s|${TMPDIR:-/tmp}/runtests....../|\${tmpdir}/|g" "$tmpfile" "$tmpdir/errors"
			stat=1
			for i in expected.out* ; do
				if ! test -s "$i" ; then
					break
				fi
				if cmp -s "$tmpfile" "$i" 2> /dev/null ; then
					stat=0
					echo "OK"
					cp $tmpfile "$builddir"/"$testid"/actual.out
					cp "$tmpdir"/errors "$builddir"/"$testid"/actual.err
					break
				fi
			done
			if test $stat -eq 1 ; then
				echo "FAIL"
				diff -u expected.out "$tmpfile" | sed s,"^\+\+\+ $tmpfile","+++ actual",g
				cp $tmpfile "$builddir"/"$testid"/actual.out
				cp "$tmpdir"/errors "$builddir"/"$testid"/actual.err
			fi
		else
			echo "Running test "$testid"."
			$RUNVALGRIND ./run.sh "$tmpdir"
			stat=$?
		fi
		if test -n "$RUNVALGRIND" ; then
			echo > $tmpfile
			if grep "ERROR SUMMARY" "$builddir"/"$testid"/valgrind/*.log | grep -v '0 errors' | cut -f1 -d: | xargs grep Command: $tmpfile | grep -qv "Command: /usr" ; then
				echo valgrind detected errors
			fi
		fi
		for i in "$tmpdir"/core* ; do
			if test -s "$i"; then
				cp "$i" .
			fi
		done
		popd > /dev/null
		if test $stat -ne 0 ; then
			break
		fi
	else
		echo "No test defined in "$testid", skipping."
	fi
done
exit $stat
