#!/bin/bash -e

cd "$tmpdir"

for good in "$srcdir"/040-pem/good.* ; do
	if ! "$toolsdir"/pem "$good" ; then
		exit 1
	fi
done
for bad in "$srcdir"/040-pem/bad.* bad.notfound; do
	if "$toolsdir"/pem "$bad" > /dev/null; then
		echo unexpected success with `basename "$bad"`
		exit 1
	else
		echo got expected error with `basename "$bad"`
	fi
done
echo OK
