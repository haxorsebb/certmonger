#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

size=2048
# Build a self-signed certificate.
run_certutil -d "$tmpdir" -S -g $size -n keyi$size \
	-s "cn=T$size" -c "cn=T$size" \
	-x -t u -k dsa
# Export the key.
pk12util -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size" > /dev/null 2>&1
openssl pkcs12 -in $size.p12 -out key.$size -passin pass: -nodes -nocerts > /dev/null 2>&1
# Read the public key and cache it.
cat > entry.openssl.$size <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/key.$size
key_nickname=keyi$size
id=keyi$size
EOF
$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
# Add the cached value to the prepping for the NSS copy.
cat > entry.nss.$size <<- EOF
key_storage_type=NSSDB
key_storage_location=$tmpdir
key_nickname=keyi$size
id=keyi$size
EOF
# Generate a new CSR for that certificate's key.
$toolsdir/csrgen entry.nss.$size > csr.nss.$size
grep ^spkac= entry.nss.$size | sed s,spkac,SPKAC, > spkac.nss.$size
# Generate a new CSR using the extracted key.
$toolsdir/csrgen entry.openssl.$size > csr.openssl.$size
grep ^spkac= entry.openssl.$size | sed s,spkac,SPKAC, > spkac.openssl.$size
# The RSA tests already verify the contents of the requests, so we really only
# need to care about the signatures passing verification.
openssl req   -verify -noout < csr.nss.$size 2>&1
openssl req   -verify -noout < csr.openssl.$size 2>&1
openssl spkac -verify -noout < spkac.nss.$size 2>&1
openssl spkac -verify -noout < spkac.openssl.$size 2>&1

echo Test complete.
