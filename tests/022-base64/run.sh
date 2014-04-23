#!/bin/bash -e

cd "$tmpdir"
middle=40
top=200
for length in `seq $top` ; do
	dd if=/dev/urandom bs=1 count=$length of=raw.$length
	base64    < raw.$length > encoded1.$length
	base64 -d -i < encoded1.$length > decoded1.$length
	$toolsdir/base64 -e < raw.$length > encoded2.$length
	$toolsdir/base64 -d < encoded2.$length > decoded2.$length
	$toolsdir/base64 -d < encoded1.$length > decoded3.$length
	if test $length -le $middle ; then
		if ! cmp -s $tmpdir/encoded1.$length $tmpdir/encoded2.$length ; then
			echo Encodings differ:
			od -Ad -t x1c $tmpdir/raw.$length
			diff -u $tmpdir/encoded1.$length $tmpdir/encoded2.$length
			exit 1
		fi
	fi
	if ! cmp -s $tmpdir/decoded1.$length $tmpdir/decoded2.$length ; then
		echo Decodings differ:
		diff -u $tmpdir/decoded1.$length $tmpdir/decoded2.$length
		exit 1
	fi
	if ! cmp -s $tmpdir/decoded1.$length $tmpdir/decoded3.$length ; then
		echo Decodings differ:
		diff -u $tmpdir/decoded1.$length $tmpdir/decoded3.$length
		exit 1
	fi
done
echo OK.
