#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

function setupca() {
	cat > ca.self <<- EOF
	id=self_signer
	ca_is_default=0
	ca_type=INTERNAL:SELF
	ca_internal_serial=1235
	ca_internal_issue_time=`date +%s`
	EOF
}

for preserve in 1 0 ; do
	size=2048
	rm -f "$tmpdir"/*.db
	touch "$tmpdir"/keyi "$tmpdir"/certi
	rm -f "$tmpdir"/keyi* "$tmpdir"/certi*
	initnssdb "$tmpdir"
	# Build a self-signed certificate.
	run_certutil -d "$tmpdir" -S -g $size -n "i$size" \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u -m 4660
	# Export the certificate and key.
	pk12util -d "$tmpdir" -o $size.p12 -W "" -n "i$size" > /dev/null 2>&1
	openssl pkcs12 -in $size.p12 -passin pass: -nocerts -nodes | awk '/^-----BEGIN/,/^-----END/{print}' > keyi$size
	openssl pkcs12 -in $size.p12 -passin pass: -nokeys  -nodes | awk '/^-----BEGIN/,/^-----END/{print}' > certi$size
	# Read that NSS key.
	cat > entry.nss.$size <<- EOF
	ca_name=self_signer
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=i$size
	key_preserve=$preserve
	cert_storage_type=NSSDB
	cert_storage_location=$tmpdir
	cert_nickname=i$size
	template_subject=CN=T$size
	EOF
	$toolsdir/keyiread entry.nss.$size > /dev/null 2>&1
	# Read that OpenSSL key.
	cat > entry.openssl.$size <<- EOF
	ca_name=self_signer
	key_storage_type=FILE
	key_storage_location=$tmpdir/keyi$size
	key_preserve=$preserve
	cert_storage_type=FILE
	cert_storage_location=$tmpdir/certi$size
	EOF
	$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
	# Use that NSS key.
	cat > entry.nss.$size <<- EOF
	ca_name=self_signer
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=i$size
	key_preserve=$preserve
	cert_storage_type=NSSDB
	cert_storage_location=$tmpdir
	cert_nickname=i$size
	template_subject=CN=T$size
	EOF
	$toolsdir/keyiread entry.nss.$size > /dev/null 2>&1
	$toolsdir/csrgen entry.nss.$size > csr.nss.$size
	setupca
	$toolsdir/submit ca.self entry.nss.$size > cert.nss.$size
	# Use that OpenSSL key.
	cat > entry.openssl.$size <<- EOF
	ca_name=self_signer
	key_storage_type=FILE
	key_storage_location=$tmpdir/keyi$size
	key_preserve=$preserve
	cert_storage_type=FILE
	cert_storage_location=$tmpdir/certi$size
	template_subject=CN=T$size
	EOF
	$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
	$toolsdir/csrgen entry.openssl.$size > csr.openssl.$size
	setupca
	$toolsdir/submit ca.self entry.openssl.$size > cert.openssl.$size
	# Now compare them.
	if ! cmp cert.nss.$size cert.openssl.$size ; then
		echo Certificates differ:
		cat cert.nss.$size cert.openssl.$size
		exit 1
	else
		echo $size OK.
	fi
	# Now generate new keys, CSRs, and certificates.
	echo "NSS keys before keygen (preserve=$preserve)"
	marker=`grep ^key_next_marker= entry.nss.$size | cut -f2- -d=`
	run_certutil -K -d $tmpdir | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort
	$toolsdir/keygen entry.nss.$size
	echo "NSS keys after keygen (preserve=$preserve)"
	marker=`grep ^key_next_marker= entry.nss.$size | cut -f2- -d=`
	run_certutil -K -d $tmpdir | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort
	$toolsdir/keyiread entry.nss.$size > /dev/null 2>&1
	$toolsdir/csrgen entry.nss.$size > csr.nss.$size
	setupca
	$toolsdir/submit ca.self entry.nss.$size > cert.nss.$size

	echo "NSS certs before saving (preserve=$preserve)"
	run_certutil -L -d $tmpdir | grep -v SSL,S/MIME | grep -v '^$' | grep -v 'Trust'
	echo "NSS keys before saving (preserve=$preserve)"
	marker=`grep ^key_next_marker= entry.nss.$size | cut -f2- -d=`
	run_certutil -K -d $tmpdir | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	echo "NSS Signing"
	certutil -M -d $tmpdir -n i$size -t P,P,P
	cmsutil -S -d $tmpdir -N i$size -i plain.txt -o signed
	echo "NSS Verify"
	cmsutil -D -d $tmpdir -i signed
	certutil -M -d $tmpdir -n i$size -t ,,
	echo "OpenSSL Signing"
	openssl smime -sign -signer certi$size -binary -nodetach -inkey keyi$size -in plain.txt -outform PEM -out signed
	echo "OpenSSL Verify"
	openssl smime -verify -CAfile certi$size -inform PEM -in signed
	certutil -M -d $tmpdir -n i$size -t ,,

	$toolsdir/certsave entry.nss.$size

	echo "NSS certs after saving (preserve=$preserve)"
	run_certutil -L -d $tmpdir | grep -v SSL,S/MIME | grep -v '^$' | grep -v 'Trust'
	echo "NSS keys after saving (preserve=$preserve)"
	marker=`grep ^key_next_marker= entry.nss.$size | cut -f2- -d=`
	run_certutil -K -d $tmpdir | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort

	echo "PEM keys before keygen (preserve=$preserve)"
	marker=`grep ^key_next_marker= entry.openssl.$size | cut -f2- -d=`
	find $tmpdir -name "keyi${size}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort
	$toolsdir/keygen entry.openssl.$size
	echo "PEM keys after keygen (preserve=$preserve)"
	marker=`grep ^key_next_marker= entry.openssl.$size | cut -f2- -d=`
	find $tmpdir -name "keyi${size}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort
	$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
	$toolsdir/csrgen entry.openssl.$size > csr.openssl.$size
	setupca
	$toolsdir/submit ca.self entry.openssl.$size > cert.openssl.$size

	echo "PEM certs before saving (preserve=$preserve)"
	find $tmpdir -name "certi${size}*" -print | env LANG=C sort
	find $tmpdir -name "certi${size}*" -print | xargs -n 1 openssl x509 -noout -serial -in
	echo "PEM keys before saving (preserve=$preserve)"
	marker=`grep ^key_next_marker= entry.openssl.$size | cut -f2- -d=`
	find $tmpdir -name "keyi${size}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	echo "NSS Signing"
	certutil -M -d $tmpdir -n i$size -t P,P,P
	cmsutil -S -d $tmpdir -N i$size -i plain.txt -o signed
	echo "NSS Verify"
	cmsutil -D -d $tmpdir -i signed
	certutil -M -d $tmpdir -n i$size -t ,,
	echo "OpenSSL Signing"
	openssl smime -sign -signer certi$size -binary -nodetach -inkey keyi$size -in plain.txt -outform PEM -out signed
	echo "OpenSSL Verify"
	openssl smime -verify -CAfile certi$size -inform PEM -in signed

	$toolsdir/certsave entry.openssl.$size

	echo "PEM certs after saving (preserve=$preserve)"
	find $tmpdir -name "certi${size}*" -print | env LANG=C sort
	find $tmpdir -name "certi${size}*" -print | xargs -n 1 openssl x509 -noout -serial -in
	echo "PEM keys after saving (preserve=$preserve)"
	find $tmpdir -name "keyi${size}*" -print | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	echo "NSS Signing"
	certutil -M -d $tmpdir -n i$size -t P,P,P
	cmsutil -S -d $tmpdir -N i$size -i plain.txt -o signed
	echo "NSS Verify"
	cmsutil -D -d $tmpdir -i signed
	certutil -M -d $tmpdir -n i$size -t ,,
	echo "OpenSSL Signing"
	openssl smime -sign -signer certi$size -binary -nodetach -inkey keyi$size -in plain.txt -outform PEM -out signed
	echo "OpenSSL Verify"
	openssl smime -verify -CAfile certi$size -inform PEM -in signed
done
cat cert.nss.$size 1>&2
echo Test complete.
