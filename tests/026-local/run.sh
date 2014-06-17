#!/bin/bash -e

cd $tmpdir

cat > request <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/key
cert_storage_type=FILE
cert_storage_location=$tmpdir/cert
template_subject=CN=Babs Jensen's Signer
template_email=root@localhost,root@localhost.localdomain
template_ku=1000011
template_is_ca=1
template_certfname=Babs Jensen's Signer
template_ocsp=http://ocsp-1.example.com:12345,http://ocsp-2.example.com:12345
template_nscomment=certmonger generated this request
template_no_ocsp_check=1
EOF
filter() {
	sed -re 's,CN=[[:xdigit:]]{8}-[[:xdigit:]]{8}-[[:xdigit:]]{8}-[[:xdigit:]]{8},CN=$UUID,g' |\
	sed -re 's,[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2},(160 bits),g' |\
	sed s,'^        Signature Algorithm,    Signature Algorithm,g'
}
dumpreq() {
	openssl req -in "$@" -text -noout -reqopt no_serial,no_pubkey,no_sigdump,no_validity | filter
}
dumpcert() {
	openssl x509 -in "$@" -text -noout -certopt no_serial,no_pubkey,no_sigdump,no_validity | filter
}
echo "[key]"
$toolsdir/keygen request
echo "[csr]"
$toolsdir/csrgen request > csr
dumpreq csr
echo "[issue]"
$builddir/../src/local-submit -d $tmpdir csr > cert
echo "[issuer]"
openssl pkcs12 -in creds -passin pass: -nodes | openssl x509 > ca-cert
dumpcert ca-cert
echo "[subject]"
dumpcert cert
echo "[verify]"
openssl verify -CAfile $tmpdir/ca-cert cert
echo OK.
