#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"
issuetime=`date +%s`

function setupca() {
	cat > ca.self <<- EOF
	id=self_signer
	ca_is_default=0
	ca_type=INTERNAL:SELF
	ca_internal_serial=1235
	ca_internal_issue_time=$issuetime
	EOF
}

for preserve in 1 0 ; do
	for pin in "" password ; do
	echo "[ Begin pass (preserve=$preserve,pin=\"$pin\"). ]"

	size=2048
	rm -f "$tmpdir"/*.db
	touch "$tmpdir"/keyi "$tmpdir"/certi
	rm -f "$tmpdir"/keyi* "$tmpdir"/certi* "$tmpdir"/pubkey*
	initnssdb "$tmpdir" $pin
	echo "$pin" > pinfile
	# Build a self-signed certificate.
	run_certutil -d "$tmpdir" -S -g $size -n "i$size" \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u -m 4660 -f pinfile
	# Export the certificate and key.
	pk12util -d "$tmpdir" -k pinfile -o $size.p12 -W "" -n "i$size" > /dev/null 2>&1
	openssl pkcs12 -in $size.p12 -passin pass: -nocerts -passout pass:${pin:- -nodes} | awk '/^-----BEGIN/,/^-----END/{print}' > keyi$size
	openssl pkcs12 -in $size.p12 -passin pass: -nokeys  -nodes | awk '/^-----BEGIN/,/^-----END/{print}' > certi$size
	# Grab a copy of the public key.
	openssl x509 -pubkey -noout -in "$tmpdir"/certi$size > "$tmpdir"/pubkey.old
	# Read info about that key using NSS
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
	echo key_pin_file=`pwd`/pinfile >> entry.nss.$size
	$toolsdir/keyiread entry.nss.$size > /dev/null 2>&1
	# Read info about that key using OpenSSL
	cat > entry.openssl.$size <<- EOF
	ca_name=self_signer
	key_storage_type=FILE
	key_storage_location=$tmpdir/keyi$size
	key_preserve=$preserve
	cert_storage_type=FILE
	cert_storage_location=$tmpdir/certi$size
	EOF
	echo key_pin_file=`pwd`/pinfile >> entry.openssl.$size
	$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
	# Use that NSS key to generate a self-signed certificate.
	echo '(prep NSS)'
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
	echo key_pin_file=`pwd`/pinfile >> entry.nss.$size
	$toolsdir/keyiread entry.nss.$size > /dev/null 2>&1
	$toolsdir/csrgen entry.nss.$size > csr.nss.$size
	setupca
	grep ^key.\*count= entry.nss.$size | LANG=C sort
	echo '(submit NSS)'
	$toolsdir/submit ca.self entry.nss.$size > cert.nss.$size
	grep ^key.\*count= entry.nss.$size | LANG=C sort
	# Use that OpenSSL key to generate a self-signed certificate.
	echo '(prep OpenSSL)'
	cat > entry.openssl.$size <<- EOF
	ca_name=self_signer
	key_storage_type=FILE
	key_storage_location=$tmpdir/keyi$size
	key_preserve=$preserve
	cert_storage_type=FILE
	cert_storage_location=$tmpdir/certi$size
	template_subject=CN=T$size
	EOF
	echo key_pin_file=`pwd`/pinfile >> entry.openssl.$size
	$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
	$toolsdir/csrgen entry.openssl.$size > csr.openssl.$size
	setupca
	grep ^key.\*count= entry.openssl.$size | LANG=C sort
	echo '(submit OpenSSL)'
	$toolsdir/submit ca.self entry.openssl.$size > cert.openssl.$size
	grep ^key.\*count= entry.openssl.$size | LANG=C sort
	# Now compare the self-signed certificates built from the keys.
	if ! cmp cert.nss.$size cert.openssl.$size ; then
		echo First round certificates differ:
		cat cert.nss.$size cert.openssl.$size
		exit 1
	else
		echo First round certificates OK.
	fi

	# Now generate new keys, CSRs, and certificates (NSS).
	echo "NSS keys before re-keygen (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.nss.$size | cut -f2- -d=`
	firstid=`run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -r 's,< *0>,<->,g' | awk '{print $3}' | env LANG=C sort`
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | env LANG=C sort 1>&2
	echo firstid="$firstid" 1>&2
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", -e "s,$firstid,originalhex,g" | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort
	grep ^key.\*count= entry.nss.$size | LANG=C sort
	$toolsdir/keygen entry.nss.$size
	echo "NSS keys after re-keygen (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.nss.$size | cut -f2- -d=`
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", -e "s,$firstid,originalhex,g" | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort
	$toolsdir/keyiread entry.nss.$size > /dev/null 2>&1
	$toolsdir/csrgen entry.nss.$size > csr.nss.$size
	setupca
	grep ^key.\*count= entry.nss.$size | LANG=C sort
	echo '(submit NSS)'
	$toolsdir/submit ca.self entry.nss.$size > cert.nss.$size
	grep ^key.\*count= entry.nss.$size | LANG=C sort

	# Verify that we can still sign using the old key and cert using the right name (NSS).
	echo "NSS certs before saving (preserve=$preserve,pin=\"$pin\"):"
	run_certutil -L -d $tmpdir | grep -v SSL,S/MIME | grep -v '^$' | grep -v 'Trust'
	run_certutil -L -d $tmpdir -n i$size -a | openssl x509 -noout -serial
	echo "NSS keys before saving (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.nss.$size | cut -f2- -d=`
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", -e "s,$firstid,originalhex,g" | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	echo "NSS Signing:"
	certutil -M -d $tmpdir -n i$size -t P,P,P
	cmsutil -S -d $tmpdir -f pinfile -N i$size -i plain.txt -o signed
	echo "NSS Verify:"
	cmsutil -D -d $tmpdir -f pinfile -i signed
	certutil -M -d $tmpdir -n i$size -t ,,

	# Go and save the new certs and keys (NSS).
	echo '(saving)'
	$toolsdir/certsave entry.nss.$size
	grep ^key.\*count= entry.nss.$size | LANG=C sort
	# Grab a copy of the public key (NSS).
	certutil -L -d $tmpdir -n i$size -a | openssl x509 -pubkey -noout > "$tmpdir"/pubkey.nss

	# Verify that we can sign using the new key and cert using the right name (NSS).
	echo "NSS certs after saving (preserve=$preserve,pin=\"$pin\"):"
	run_certutil -L -d $tmpdir | grep -v SSL,S/MIME | grep -v '^$' | grep -v 'Trust'
	run_certutil -L -d $tmpdir -n i$size -a | openssl x509 -noout -serial
	echo "NSS keys after saving (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.nss.$size | cut -f2- -d=`
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", -e "s,$firstid,originalhex,g" | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	echo "NSS Signing:"
	certutil -M -d $tmpdir -n i$size -t P,P,P
	cmsutil -S -d $tmpdir -f pinfile -N i$size -i plain.txt -o signed
	echo "NSS Verify:"
	cmsutil -D -d $tmpdir -f pinfile -i signed
	certutil -M -d $tmpdir -n i$size -t ,,

	# Now generate new keys, CSRs, and certificates (OpenSSL).
	echo "PEM keys before re-keygen (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.openssl.$size | cut -f2- -d=`
	find $tmpdir -name "keyi${size}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort
	grep ^key.\*count= entry.openssl.$size | LANG=C sort
	$toolsdir/keygen entry.openssl.$size
	echo "PEM keys after re-keygen (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.openssl.$size | cut -f2- -d=`
	find $tmpdir -name "keyi${size}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort
	$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
	$toolsdir/csrgen entry.openssl.$size > csr.openssl.$size
	setupca
	grep ^key.\*count= entry.openssl.$size | LANG=C sort
	echo '(submit OpenSSL)'
	$toolsdir/submit ca.self entry.openssl.$size > cert.openssl.$size
	grep ^key.\*count= entry.openssl.$size | LANG=C sort

	# Verify that we can still sign using the old key and cert (OpenSSL).
	echo "PEM certs before saving (preserve=$preserve,pin=\"$pin\"):"
	find $tmpdir -name "certi${size}*" -print | env LANG=C sort
	find $tmpdir -name "certi${size}*" -print | xargs -n 1 openssl x509 -noout -serial -in
	echo "PEM keys before saving (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.openssl.$size | cut -f2- -d=`
	find $tmpdir -name "keyi${size}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	echo "OpenSSL Signing:"
	openssl smime -sign -signer certi$size -binary -nodetach -inkey keyi$size -passin pass:$pin -in plain.txt -outform PEM -out signed
	echo "OpenSSL Verify:"
	openssl smime -verify -CAfile certi$size -inform PEM -in signed

	# Go and save the new certs and keys (OpenSSL).
	echo '(saving)'
	$toolsdir/certsave entry.openssl.$size
	grep ^key.\*count= entry.openssl.$size | LANG=C sort
	# Grab a copy of the public key (OpenSSL).
	openssl x509 -pubkey -noout -in "$tmpdir"/certi$size > "$tmpdir"/pubkey.openssl

	# Verify that we can sign using the new key and cert (OpenSSL).
	echo "PEM certs after saving (preserve=$preserve,pin=\"$pin\"):"
	find $tmpdir -name "certi${size}*" -print | env LANG=C sort
	find $tmpdir -name "certi${size}*" -print | xargs -n 1 openssl x509 -noout -serial -in
	echo "PEM keys after saving (preserve=$preserve,pin=\"$pin\"):"
	find $tmpdir -name "keyi${size}*" -print | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	echo "OpenSSL Signing:"
	openssl smime -sign -signer certi$size -binary -nodetach -inkey keyi$size -passin pass:$pin -in plain.txt -outform PEM -out signed
	echo "OpenSSL Verify:"
	openssl smime -verify -CAfile certi$size -inform PEM -in signed

	# Double-check that the keys were changed.
	if ! test -s "$tmpdir"/pubkey.old ; then
		echo Error reading old pubkey.
	fi
	if ! test -s "$tmpdir"/pubkey.nss ; then
		echo Error reading NSS pubkey.
	fi
	if ! test -s "$tmpdir"/pubkey.openssl ; then
		echo Error reading OpenSSL pubkey.
	fi
	if cmp -s "$tmpdir"/pubkey.old "$tmpdir"/pubkey.nss ; then
		echo NSS key not changed.
	fi
	if cmp -s "$tmpdir"/pubkey.old "$tmpdir"/pubkey.openssl ; then
		echo OpenSSL key not changed.
	fi
	if cmp -s "$tmpdir"/pubkey.nss "$tmpdir"/pubkey.openssl ; then
		echo Rekey produced the same keys.
	fi
	echo "[ End pass (preserve=$preserve,pin=\"$pin\"). ]"
	done
done
cat cert.nss.$size 1>&2
echo Test complete.
