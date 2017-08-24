#!/bin/bash -e

srcdir=$PWD
cd $tmpdir

mkconfig() {
	cat > request <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key
	cert_storage_type=FILE
	cert_storage_location=$tmpdir/cert
	template_subject=CN=MS V2 Certificate Template test
	EOF
}

echo "[key]"
mkconfig
$toolsdir/keygen request

echo "[csr : bogus oid]"
mkconfig
echo "template_certificate_template=NotAnOid:42" >> request
$toolsdir/csrgen request | openssl asn1parse \
	| $srcdir/extract-extdata.py || echo "extension not present"

echo "[csr : bogus major version]"
mkconfig
echo "template_certificate_template=1.2.3.4:wat" >> request
$toolsdir/csrgen request | openssl asn1parse \
	| $srcdir/extract-extdata.py || echo "extension not present"

echo "[csr : missing major version]"
mkconfig
echo "template_certificate_template=1.2.3.4" >> request
$toolsdir/csrgen request | openssl asn1parse \
	| $srcdir/extract-extdata.py || echo "extension not present"

echo "[csr : too many parts]"
mkconfig
echo "template_certificate_template=1.2.3.4:1:1:1" >> request
$toolsdir/csrgen request | openssl asn1parse \
	| $srcdir/extract-extdata.py || echo "extension not present"

echo "[csr : oid, major version]"
mkconfig
echo "template_certificate_template=1.2.3.4:42" >> request
$toolsdir/csrgen request | openssl asn1parse \
	| $srcdir/extract-extdata.py | openssl asn1parse -inform DER

echo "[csr : oid, major version, minor version]"
mkconfig
echo "template_certificate_template=1.2.3.4:42:17" >> request
$toolsdir/csrgen request | openssl asn1parse \
	| $srcdir/extract-extdata.py | openssl asn1parse -inform DER
