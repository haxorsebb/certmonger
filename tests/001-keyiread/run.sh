#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 512 1024 1536 2048 3072 4096 ; do
	# Generate a self-signed cert.
	certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u < /dev/urandom > /dev/null 2> /dev/null
	# Check the size of the key.
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	$toolsdir/keyiread entry.$size
done

for size in 512 1024 1536 2048 3072 4096 ; do
	# Generate a key.
	openssl genrsa $size > sample.$size 2> /dev/null
	# Check the size of the key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/sample.$size
	EOF
	$toolsdir/keyiread entry.$size
done
