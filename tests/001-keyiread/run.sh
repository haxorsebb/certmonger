#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"
for size in 512 1024 1536 2048 3072 4096 ; do
	certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=Test $size-Bits" -c "cn=Test $size-Bits" \
		-m $size \
		-x -t u < /dev/urandom > /dev/null 2> /dev/null
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_storage_nickname=keyi$size
	EOF
	$toolsdir/keyiread entry.$size
done

for size in 512 1024 1536 2048 3072 4096 ; do
	openssl genrsa $size > sample.$size 2> /dev/null
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/sample.$size
	EOF
	$toolsdir/keyiread entry.$size
done
