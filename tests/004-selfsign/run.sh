#!/bin/bash -e

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
	template_challengepassword=ChallengePasswordIsEncodedInPlainText
	template_certfname=CertificateFriendlyName
	template_crldp=http://crl-1.example.com:12345/get,http://crl-2.example.com:12345/get
	template_ocsp=http://ocsp-1.example.com:12345,http://ocsp-2.example.com:12345
	template_nscomment=certmonger generated this request
	template_ipaddress=127.0.0.1,::1
	template_freshest_crl=http://dcrl-1.example.com:12345/get,http://dcrl-2.example.com:12345/get
	template_no_ocsp_check=1
	template_profile=caAwesomeCert
	template_ns_certtype=client,email
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

for size in 512 1024 1536 2048 3072 4096 ; do
	# Build a self-signed certificate.
	run_certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u
	# Export the certificate and key.
	pk12util -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size" > /dev/null 2>&1
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
	if ! cmp cert.nss.$size cert.openssl.$size ; then
		echo Certificates differ:
		cat cert.nss.$size cert.openssl.$size
		exit 1
	else
		echo $size OK.
	fi
done
cat cert.nss.$size 1>&2
echo Test complete.
