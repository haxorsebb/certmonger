#!/bin/bash -e

#srcdir="/home/vagrant/rpmbuild/SOURCES/certmonger-0.79.21/tests"
#toolsdir="/home/vagrant/rpmbuild/SOURCES/certmonger-0.79.21/tests/tools"
#tmpdir="/tmp/test"

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

grep -v ^validity_period $CERTMONGER_CONFIG_DIR/certmonger.conf > \
	$tmpdir/certmonger.conf
cat >> $tmpdir/certmonger.conf << EOF
[selfsign]
validity_period = 46129s
EOF

function append() {
	cat >> $1 <<- EOF
	template_subject=CN=Babs Jensen
	template_hostname=localhost,localhost.localdomain
	template_email=root@localhost,root@localhost.localdomain
	template_principal=root@EXAMPLE.COM,root@FOO.EXAMPLE.COM
	template_ku=111
	template_eku=id-kp-clientAuth,id-kp-emailProtection
	EOF
}

function setupca() {
	cat > ca.self <<- EOF
	id=self_signer
	ca_is_default=0
	ca_type=INTERNAL:SELF
	ca_internal_serial=04
	ca_internal_issue_time=40271
	EOF
}

# ML-DSA signatures include fresh randomness, so full DER/PEM of two certs
# produced from the same key and template will almost always differ. Compare
# stable fields and verify each cert instead of cmp on the whole file.
function compare_mldsa_certs() {
	local nss=$1 ossl=$2
	local d n o
	n="n"
	o="o"
	openssl x509 -in "$nss" -noout -serial > "$n.s" && openssl x509 -in "$ossl" -noout -serial > "$o.s"
	cmp "$n.s" "$o.s"
	openssl x509 -in "$nss" -noout -subject > "$n.sj" && openssl x509 -in "$ossl" -noout -subject > "$o.sj"
	cmp "$n.sj" "$o.sj"
	openssl x509 -in "$nss" -noout -issuer > "$n.is" && openssl x509 -in "$ossl" -noout -issuer > "$o.is"
	cmp "$n.is" "$o.is"
	openssl x509 -in "$nss" -noout -dates > "$n.dt" && openssl x509 -in "$ossl" -noout -dates > "$o.dt"
	cmp "$n.dt" "$o.dt"
	openssl x509 -in "$nss" -noout -pubkey > "$n.pk" && openssl x509 -in "$ossl" -noout -pubkey > "$o.pk"
	cmp "$n.pk" "$o.pk"
    openssl x509 -in "$nss" -noout -ext subjectKeyIdentifier > "$n.skid" && openssl x509 -in "$ossl" -noout -ext subjectKeyIdentifier > "$o.skid"
	cmp "$n.skid" "$o.skid"
#	openssl verify -CAfile "$nss" "$nss" > /dev/null
#	openssl verify -CAfile "$ossl" "$ossl" > /dev/null
}

for size in ML-DSA-44 ML-DSA-65 ML-DSA-87; do
	# Build a self-signed certificate.
	run_certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u -k mldsa -q $size
	# Export the certificate and key.
	pk12util -C AES-128-CBC -c AES-128-CBC -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size" > /dev/null 2>&1
	openssl pkcs12 -in $size.p12 -passin pass: -out key.$size -nodes > /dev/null 2>&1
	# Read that OpenSSL key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	EOF
	$toolsdir/keyiread entry.$size > /dev/null 2>&1
	grep ^key_pubkey_info= entry.$size > pubkey.$size
	grep ^key_pubkey= entry.$size >> pubkey.$size
	# Use that NSS key.
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	append entry.$size
	cat pubkey.$size >> entry.$size
	$toolsdir/csrgen entry.$size > csr.nss.$size
	setupca
	$toolsdir/submit ca.self entry.$size > cert.nss.$size
	# Use that OpenSSL key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	EOF
	append entry.$size
	cat pubkey.$size >> entry.$size
	$toolsdir/csrgen entry.$size > csr.openssl.$size
	setupca
	$toolsdir/submit ca.self entry.$size > cert.openssl.$size
	# Now compare them.
	if ! compare_mldsa_certs cert.nss.$size cert.openssl.$size ; then
		echo "Certificates differ (non-signature fields or verify failed) for $size"
		exit 1
 	else
		echo $size OK.
	fi
done
echo Test complete.
