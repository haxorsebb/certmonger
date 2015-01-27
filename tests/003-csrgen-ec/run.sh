#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

size=secp256r1

# Build a self-signed certificate.
run_certutil -d "$tmpdir" -S -n keyi$size \
	-s "cn=T$size" -c "cn=T$size" \
	-x -t u -k ec -q $size
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
# Pull out the mini-cert.
grep ^minicert= entry.openssl.$size | sed s,^minicert=,, | base64 -d > minicert.openssl.$size
openssl x509 -out minicert.openssl.$size.pem -in minicert.openssl.$size -inform der
grep ^minicert= entry.nss.$size | sed s,^minicert=,, | base64 -d > minicert.nss.$size
openssl x509 -out minicert.nss.$size.pem -in minicert.nss.$size -inform der
# The RSA tests already verify the contents of the requests, so we really only
# need to care about the signatures passing verification.
openssl req   -verify -noout < csr.nss.$size 2>&1
openssl req   -verify -noout < csr.openssl.$size 2>&1
openssl spkac -verify -noout < spkac.nss.$size 2>&1
openssl spkac -verify -noout < spkac.openssl.$size 2>&1
openssl verify -CAfile minicert.openssl.$size.pem minicert.openssl.$size.pem 2>&1
openssl verify -CAfile minicert.nss.$size.pem minicert.nss.$size.pem 2>&1

echo Test complete.
