#!/bin/sh
source "$srcdir"/functions
rm -f "$tmpdir"/*.db
certutil -N -d "$tmpdir" --empty-password 2>/dev/null
initnssdb "$tmpdir"

run_certutil -d "$tmpdir" -S -n test \
	-s "cn=Test" -c "cn=Test" \
	-x -t u -k mldsa -q ML-DSA-87

if [ $? -ne 0 ]; then
	echo "ML-DSA is not available or not allowed in NSS crypto policy."
	exit 1
fi
