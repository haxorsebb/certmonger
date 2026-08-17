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

# bad.16 contains a raw (non-escaped) UTF-8 encoding of a surrogate code
# point (U+D800, as bytes ED A0 80).  cm_json_decode() accepts these bytes
# as-is (it only rejects surrogates reached via \u escapes), so the file
# above is correctly rejected -- but only because cm_json_encode() must
# also refuse to re-serialize a surrogate code point.  Check that it fails
# for that reason specifically: a regression that makes cm_json_utf8_to_point()
# or cm_json_escape() accept surrogates again would still get caught by the
# round-trip check above, but with a different (misleading) error, so pin
# down the exact message here.
echo '[bad.16 detail]'
"$toolsdir"/json "$srcdir"/035-json/bad.16 > /dev/null 2> "$tmpdir"/bad.16.err || true
cat "$tmpdir"/bad.16.err

echo OK
