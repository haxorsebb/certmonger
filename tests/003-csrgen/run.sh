#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 512 1024 1536 2048 3072 4096 ; do
	# Build a self-signed certificate.
	certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u < /dev/urandom > /dev/null 2> /dev/null
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	# Generate a new CSR for that certificate's key.
	$toolsdir/csrgen entry.$size > csr.nss.$size
	# Export the certificate and key.
	pk12util -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size"
	openssl pkcs12 -in $size.p12 -passin pass: -out key.$size -nodes 2>&1
	# Generate a new CSR using the key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	EOF
	$toolsdir/csrgen entry.$size > csr.openssl.$size
	# They'd better be the same!
	cmp csr.nss.$size csr.openssl.$size
	echo $size OK.
done
