# Shared rekey integration test body.
#
# Select key type with REKEY_KEY_TYPE:
#   rsa   (default) — RSA-2048 via certutil -g
#   mldsa           — ML-DSA-44 initial cert, ML-DSA-65 at rekey (see below)
#
# Invoked from tests/030-rekey/run.sh (RSA) or tests/030-rekey-mldsa/run.sh.

REKEY_KEY_TYPE=${REKEY_KEY_TYPE:-rsa}

case "$REKEY_KEY_TYPE" in
rsa)
	tag=2048
	nick=i2048
	cn=T2048
	;;
mldsa)
	initial_size=${REKEY_ML_DSA_INITIAL:-44}
	rekey_size=${REKEY_ML_DSA_REKEY:-65}
	tag=mldsa${initial_size}
	nick=imldsa${initial_size}
	cn=Tmldsa${initial_size}
	;;
*)
	echo "Unsupported REKEY_KEY_TYPE=$REKEY_KEY_TYPE" >&2
	exit 1
	;;
esac

create_initial_cert() {
	if test "$REKEY_KEY_TYPE" = rsa ; then
		run_certutil -d "$tmpdir" -S -g "$tag" -n "$nick" \
			-s "cn=$cn" -c "cn=$cn" \
			-x -t u -m 4660 -f pinfile
	else
		run_certutil -d "$tmpdir" -S -n "$nick" \
			-s "cn=$cn" -c "cn=$cn" \
			-x -t u -k mldsa -q ML-DSA-${initial_size} -m 4660 -f pinfile
	fi
}

set_mldsa_rekey_gen_params() {
	local entry=$1

	if test "$REKEY_KEY_TYPE" != mldsa ; then
		return 0
	fi
	if grep -q '^key_gen_size=' "$entry" ; then
		sed -i "s/^key_gen_size=.*/key_gen_size=${rekey_size}/" "$entry"
	else
		echo key_gen_size=${rekey_size} >> "$entry"
	fi
	if grep -q '^key_gen_type=' "$entry" ; then
		sed -i "s/^key_gen_type=.*/key_gen_type=ML-DSA-${rekey_size}/" "$entry"
	else
		echo key_gen_type=ML-DSA-${rekey_size} >> "$entry"
	fi
}

keyiread_maybe_quiet() {
	local entry=$1
	local phase=${2:-}

	if test "$REKEY_KEY_TYPE" = mldsa && test "$phase" = after-rekey ; then
		$toolsdir/keyiread "$entry"
		grep ^key_next_type= "$entry"
		grep ^key_next_size= "$entry"
	else
		$toolsdir/keyiread "$entry" > /dev/null 2>&1
	fi
}

maybe_sign_nss() {
	if test "$REKEY_KEY_TYPE" = mldsa ; then
		echo "(NSS signing skipped for ML-DSA in this test)"
		return 0
	fi
	echo "NSS Signing:"
	certutil -M -d $tmpdir -n "$nick" -t P,P,P -f pinfile
	cmsutil -S -d $tmpdir -f pinfile -N "$nick" -i plain.txt -o signed -f pinfile
	echo "NSS Verify:"
	cmsutil -D -d $tmpdir -f pinfile -i signed -f pinfile
	certutil -M -d $tmpdir -n "$nick" -t ,, -f pinfile
}

maybe_sign_openssl() {
	if test "$REKEY_KEY_TYPE" = mldsa ; then
		echo "(OpenSSL signing skipped for ML-DSA in this test)"
		return 0
	fi
	echo "OpenSSL Signing:"
	openssl smime -sign -signer certi$tag -binary -nodetach -inkey keyi$tag -passin pass:$pin -in plain.txt -outform PEM -out signed
	echo "OpenSSL Verify:"
	openssl smime -verify -CAfile certi$tag -inform PEM -in signed
}

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

	rm -f "$tmpdir"/*.db
	touch "$tmpdir"/keyi "$tmpdir"/certi
	rm -f "$tmpdir"/keyi* "$tmpdir"/certi* "$tmpdir"/pubkey*
	initnssdb "$tmpdir" $pin
	echo "$pin" > pinfile
	# Build a self-signed certificate.
	create_initial_cert
	# Export the certificate and key.
	pk12util -C AES-128-CBC -c AES-128-CBC -d "$tmpdir" -k pinfile -o $tag.p12 -W "" -n "$nick" > /dev/null 2>&1
	openssl pkcs12 -in $tag.p12 -passin pass: -nocerts -passout pass:${pin:- -nodes} | awk '/^-----BEGIN/,/^-----END/{print}' > keyi$tag
	openssl pkcs12 -in $tag.p12 -passin pass: -nokeys  -nodes | awk '/^-----BEGIN/,/^-----END/{print}' > certi$tag
	# Grab a copy of the public key.
	openssl x509 -pubkey -noout -in "$tmpdir"/certi$tag > "$tmpdir"/pubkey.old
	# Read info about that key using NSS
	cat > entry.nss.$tag <<- EOF
	ca_name=self_signer
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=$nick
	key_preserve=$preserve
	cert_storage_type=NSSDB
	cert_storage_location=$tmpdir
	cert_nickname=$nick
	template_subject=CN=$cn
	EOF
	echo key_pin_file=`pwd`/pinfile >> entry.nss.$tag
	keyiread_maybe_quiet entry.nss.$tag
	# Read info about that key using OpenSSL
	cat > entry.openssl.$tag <<- EOF
	ca_name=self_signer
	key_storage_type=FILE
	key_storage_location=$tmpdir/keyi$tag
	key_preserve=$preserve
	cert_storage_type=FILE
	cert_storage_location=$tmpdir/certi$tag
	EOF
	echo key_pin_file=`pwd`/pinfile >> entry.openssl.$tag
	keyiread_maybe_quiet entry.openssl.$tag
	# Use that NSS key to generate a self-signed certificate.
	echo '(prep NSS)'
	cat > entry.nss.$tag <<- EOF
	ca_name=self_signer
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=$nick
	key_preserve=$preserve
	cert_storage_type=NSSDB
	cert_storage_location=$tmpdir
	cert_nickname=$nick
	template_subject=CN=$cn
	EOF
	echo key_pin_file=`pwd`/pinfile >> entry.nss.$tag
	keyiread_maybe_quiet entry.nss.$tag
	$toolsdir/csrgen entry.nss.$tag > csr.nss.$tag
	setupca
	grep ^key.\*count= entry.nss.$tag | LANG=C sort
	echo '(submit NSS)'
	$toolsdir/submit ca.self entry.nss.$tag > cert.nss.$tag
	grep ^key.\*count= entry.nss.$tag | LANG=C sort
	# Use that OpenSSL key to generate a self-signed certificate.
	echo '(prep OpenSSL)'
	cat > entry.openssl.$tag <<- EOF
	ca_name=self_signer
	key_storage_type=FILE
	key_storage_location=$tmpdir/keyi$tag
	key_preserve=$preserve
	cert_storage_type=FILE
	cert_storage_location=$tmpdir/certi$tag
	template_subject=CN=$cn
	EOF
	echo key_pin_file=`pwd`/pinfile >> entry.openssl.$tag
	keyiread_maybe_quiet entry.openssl.$tag
	$toolsdir/csrgen entry.openssl.$tag > csr.openssl.$tag
	setupca
	grep ^key.\*count= entry.openssl.$tag | LANG=C sort
	echo '(submit OpenSSL)'
	$toolsdir/submit ca.self entry.openssl.$tag > cert.openssl.$tag
	grep ^key.\*count= entry.openssl.$tag | LANG=C sort

	# Now generate new keys, CSRs, and certificates (NSS).
	echo "NSS keys before re-keygen (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.nss.$tag | cut -f2- -d=`
	firstid=`run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -r 's,< *0>,<->,g' | awk '{print $3}' | env LANG=C sort`
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | env LANG=C sort 1>&2
	echo firstid="$firstid" 1>&2
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", -e "s,$firstid,originalhex,g" | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort
	grep ^key.\*count= entry.nss.$tag | LANG=C sort
	set_mldsa_rekey_gen_params entry.nss.$tag
	$toolsdir/keygen entry.nss.$tag
	echo "NSS keys after re-keygen (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.nss.$tag | cut -f2- -d=`
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", -e "s,$firstid,originalhex,g" | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort
	keyiread_maybe_quiet entry.nss.$tag after-rekey
	$toolsdir/csrgen entry.nss.$tag > csr.nss.$tag
	setupca
	grep ^key.\*count= entry.nss.$tag | LANG=C sort
	echo '(submit NSS)'
	$toolsdir/submit ca.self entry.nss.$tag > cert.nss.$tag
	grep ^key.\*count= entry.nss.$tag | LANG=C sort

	# Verify that we can still sign using the old key and cert using the right name (NSS).
	echo "NSS certs before saving (preserve=$preserve,pin=\"$pin\"):"
	run_certutil -L -d $tmpdir | grep -v SSL,S/MIME | grep -v '^$' | grep -v 'Trust'
	run_certutil -L -d $tmpdir -n "$nick" -a | openssl x509 -noout -serial
	echo "NSS keys before saving (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.nss.$tag | cut -f2- -d=`
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", -e "s,$firstid,originalhex,g" | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	maybe_sign_nss

	# Go and save the new certs and keys (NSS).
	echo '(saving)'
	$toolsdir/certsave entry.nss.$tag
	grep ^key.\*count= entry.nss.$tag | LANG=C sort
	# Grab a copy of the public key (NSS).
	certutil -L -d $tmpdir -n "$nick" -a | openssl x509 -pubkey -noout > "$tmpdir"/pubkey.nss

	# Verify that we can sign using the new key and cert using the right name (NSS).
	echo "NSS certs after saving (preserve=$preserve,pin=\"$pin\"):"
	run_certutil -L -d $tmpdir | grep -v SSL,S/MIME | grep -v '^$' | grep -v 'Trust'
	run_certutil -L -d $tmpdir -n "$nick" -a | openssl x509 -noout -serial
	echo "NSS keys after saving (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.nss.$tag | cut -f2- -d=`
	run_certutil -K -d $tmpdir -f pinfile | grep -v 'Checking token' | sed -e s,"${marker:-////////}","(next)", -e "s,$firstid,originalhex,g" | sed -r -e 's,[0123456789abcdef]{8},hex,g' -e 's,< 0>,<->,g' -e 's,< 1>,<->,g' | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	maybe_sign_nss

	# Now generate new keys, CSRs, and certificates (OpenSSL).
	echo "PEM keys before re-keygen (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.openssl.$tag | cut -f2- -d=`
	find $tmpdir -name "keyi${tag}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort
	grep ^key.\*count= entry.openssl.$tag | LANG=C sort
	set_mldsa_rekey_gen_params entry.openssl.$tag
	$toolsdir/keygen entry.openssl.$tag
	echo "PEM keys after re-keygen (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.openssl.$tag | cut -f2- -d=`
	find $tmpdir -name "keyi${tag}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort
	keyiread_maybe_quiet entry.openssl.$tag after-rekey
	$toolsdir/csrgen entry.openssl.$tag > csr.openssl.$tag
	setupca
	grep ^key.\*count= entry.openssl.$tag | LANG=C sort
	echo '(submit OpenSSL)'
	$toolsdir/submit ca.self entry.openssl.$tag > cert.openssl.$tag
	grep ^key.\*count= entry.openssl.$tag | LANG=C sort

	# Verify that we can still sign using the old key and cert (OpenSSL).
	echo "PEM certs before saving (preserve=$preserve,pin=\"$pin\"):"
	find $tmpdir -name "certi${tag}*" -print | env LANG=C sort
	find $tmpdir -name "certi${tag}*" -print | xargs -n 1 openssl x509 -noout -serial -in
	echo "PEM keys before saving (preserve=$preserve,pin=\"$pin\"):"
	marker=`grep ^key_next_marker= entry.openssl.$tag | cut -f2- -d=`
	find $tmpdir -name "keyi${tag}*" -print | sed -e s,"${marker:-////////}","(next)", | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	maybe_sign_openssl

	# Go and save the new certs and keys (OpenSSL).
	echo '(saving)'
	$toolsdir/certsave entry.openssl.$tag
	grep ^key.\*count= entry.openssl.$tag | LANG=C sort
	# Grab a copy of the public key (OpenSSL).
	openssl x509 -pubkey -noout -in "$tmpdir"/certi$tag > "$tmpdir"/pubkey.openssl

	# Verify that we can sign using the new key and cert (OpenSSL).
	echo "PEM certs after saving (preserve=$preserve,pin=\"$pin\"):"
	find $tmpdir -name "certi${tag}*" -print | env LANG=C sort
	find $tmpdir -name "certi${tag}*" -print | xargs -n 1 openssl x509 -noout -serial -in
	echo "PEM keys after saving (preserve=$preserve,pin=\"$pin\"):"
	find $tmpdir -name "keyi${tag}*" -print | env LANG=C sort

	echo "This is the plaintext." > plain.txt
	maybe_sign_openssl

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
cat cert.nss.$tag 1>&2
echo Test complete.
