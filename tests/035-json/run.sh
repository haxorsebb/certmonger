#!/bin/bash -e

cd "$tmpdir"

echo "[utf8]"
"$toolsdir"/json-utf8
for good in "$srcdir"/035-json/good.* ; do
	if ! "$toolsdir"/json "$good" ; then
		exit 1
	fi
done
for bad in "$srcdir"/035-json/bad.* ; do
	if "$toolsdir"/json "$bad" ; then
		echo unexpected success with `basename "$bad"`
		exit 1
	else
		echo got expected error with `basename "$bad"`
	fi
done
echo OK
