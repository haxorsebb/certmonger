#!/bin/bash -e

cd "$tmpdir"
cp -p "$srcdir"/040-pem/bad.* $tmpdir
base64 -d < "$tmpdir"/bad.isrg-root-x1-cross-signed.der.b64 > "$tmpdir"/bad.isrg-root-x1-cross-signed.der
rm -f "$tmpdir"/bad.isrg-root-x1-cross-signed.der.b64

for good in "$srcdir"/040-pem/good.* ; do
	if ! "$toolsdir"/pem "$good" ; then
		exit 1
	fi
done
for bad in "$tmpdir"/bad.* bad.notfound; do
	if "$toolsdir"/pem "$bad" > /dev/null; then
		echo unexpected success with `basename "$bad"`
		exit 1
	else
		echo got expected error with `basename "$bad"`
	fi
done
echo OK
