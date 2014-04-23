#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in nistp256 nistp384 nistp521 ; do
	# Generate a self-signed cert.
	run_certutil -d "$tmpdir" -S -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u -k ec -q $size
	# Check the size of the key.
	cat > entry.nss.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	$toolsdir/keyiread entry.nss.$size
	# Export the key.
	if ! pk12util -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size" > /dev/null 2>&1 ; then
		echo Error exporting key for $size, continuing.
		continue
	fi
	if ! openssl pkcs12 -in $size.p12 -out key.$size -passin pass: -nodes -nocerts > /dev/null 2>&1 ; then
		echo Error parsing exported key for $size, continuing.
		continue
	fi
	cat > entry.openssl.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	key_nickname=keyi$size
	EOF
	$toolsdir/keyiread entry.openssl.$size
done
echo Test complete.
