#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 512 1024 1536 2048 3072 4096 ; do
	# Generate a self-signed cert.
	run_certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u -k dsa
	# Correct the expected size of the key.
	if test $size -gt 1024 ; then
		size=1024
	fi
	# Export the key.
	pk12util -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size" > /dev/null 2>&1
	openssl pkcs12 -in $size.p12 -out key.$size -passin pass: -nodes -nocerts > /dev/null 2>&1
	cat > entry.openssl.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	key_nickname=keyi$size
	EOF
	$toolsdir/keyiread -m $size -s entry.openssl.$size
	# Check the size of the key (with cache).
	cat > entry.nss.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	grep ^key_pubkey_info= entry.openssl.$size >> entry.nss.$size
	grep ^key_pubkey= entry.openssl.$size >> entry.nss.$size
	$toolsdir/keyiread -m $size -s entry.nss.$size
	# Check the size of the key (without cache).
	cat > entry.nss.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	$toolsdir/keyiread -m $size -s entry.nss.$size
done
echo Test complete.
