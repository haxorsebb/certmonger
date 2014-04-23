#!/bin/bash

cd "$tmpdir"

source "$srcdir"/functions

size=2048
pin=blahblah
echo $pin > pin.txt
echo ""   > empty.txt

clean() {
	sed -r -e 's|'"$tmpdir"'|$tmpdir|g' -e 's,: SEC_ERROR_[^:]+: ,: ,g' |\
	grep -vF 'certutil: Checking token "NSS Certificate DB" in slot "NSS User Private Key and Certificate Services"'
}

echo '['Generate Key Without PIN.']'
cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
key_gen_size=$size
EOF
rm -f $tmpdir/keyfile
$toolsdir/keygen entry | clean
egrep '(: |PRIVATE)' $tmpdir/keyfile

echo '['Try To Read Key Without PIN.']'
cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
key_gen_size=$size
EOF
$toolsdir/keyiread entry | clean

echo '['Retry With Unnecessary PIN File.']'
echo key_pin_file=$tmpdir/pin.txt >> entry
$toolsdir/keyiread entry | clean

echo '['Replacing key with an encrypted one.']'
cat > keyfile <<- EOF
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,6D45AA0F810E9C67

4PkG3RcN8x3s5B1QlpCnfRouU5cR1Ws6lUTClbxqJwLtnJQb5gfvJmOCVft3guKE
UYfYbwsE1xiz1SOPyQiMCQFN6kHTQQOXeoDa0FI2EJOKMaYDG8eyt9lIBVb3nAVo
YsWh6lvgZVAcyf9EwqaXm/5Ay3rdoyT1yktN4TpC8AvCjAHy3y1Vb/e2TDmz8faQ
FS5T/L7oCaNcbfK/PSBG9jAQdlLJoL53L9eKzMK6WP2LTtVFI2i7vDuQnQPw5GN7
Q+HGpLSICBZbw6n1MmTmmdOtowDnXmr6FSyECB5ibdCqb+2itNQ+J1HNOtKzpbKC
3q6YSAMDw/D8e45auh3FRt6SAYvZ8Tw4jNqd16P6/aa5rno3qMWBcv0G0fmb0N6R
Hka4FKLjBQo5g0WxKvpRwxHrrQW6JeT9I5+NgNN4sJc=
-----END RSA PRIVATE KEY-----
EOF

echo '['Read Key Info With Bogus PIN Location.']'
cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
key_pin_file=$tmpdir/bogus-pin.txt
EOF
$toolsdir/keyiread entry | clean

echo '['Read Key Info Without PIN.']'
cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
EOF
$toolsdir/keyiread entry | clean

echo '['Retrying With PIN.']'
echo key_pin=$pin >> entry
$toolsdir/keyiread entry | clean

echo '['Read Key Info Without PIN File.']'
cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
EOF
$toolsdir/keyiread entry | clean

echo '['Retry With PIN File.']'
echo key_pin_file=$tmpdir/pin.txt >> entry
$toolsdir/keyiread entry | clean

echo '['Generate Key With PIN.']'
cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
key_gen_size=2048
key_pin_file=$tmpdir/pin.txt
EOF
rm -f $tmpdir/keyfile
$toolsdir/keygen entry | clean
egrep '(: |PRIVATE)' $tmpdir/keyfile

echo '['Try To Read Key Without PIN.']'
cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
key_gen_size=2048
EOF
$toolsdir/keyiread entry | clean

echo '['Retry With PIN File.']'
echo key_pin_file=$tmpdir/pin.txt >> entry
$toolsdir/keyiread entry | clean

echo '['Generate CSR With PIN.']'
rm -f csr.pem
echo key_pin_file=$tmpdir/pin.txt >> entry
$toolsdir/csrgen entry > csr.pem | clean
egrep '(: |REQUEST)' $tmpdir/csr.pem

for precreate in false true ; do

	rm -fr $tmpdir/${scheme}db
	mkdir -p $tmpdir/${scheme}db
	if $precreate ; then
		echo '['Creating database, without PIN.']'
		initnssdb "${scheme:+${scheme}:}$tmpdir/${scheme}db"
	else
		echo '['Not pre-creating database.']'
	fi

	cat > entry <<- EOF
	key_storage_type=NSSDB
	key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	key_nickname=Test
	EOF

	echo '['Generating key${scheme:+ \($scheme\)} without PIN.']'
	$toolsdir/keygen entry | clean
	run_certutil -K -d ${scheme:+${scheme}:}$tmpdir/${scheme}db 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g' | clean

	echo '['Providing Unnecessary PIN.']'
	echo key_pin_file=$tmpdir/pin.txt >> entry

	echo '['Reading Key Info With Unnecessary PIN.']'
	$toolsdir/keyiread entry | clean
	run_certutil -K -d ${scheme:+${scheme}:}$tmpdir/${scheme}db -f $tmpdir/pin.txt 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g' | clean

	echo '['Generating CSR With Unnecessary PIN.']'
	rm -f csr.pem
	$toolsdir/csrgen entry > csr.pem | clean
	egrep '(: |REQUEST)' $tmpdir/csr.pem
	run_certutil -K -d ${scheme:+${scheme}:}$tmpdir/${scheme}db -f $tmpdir/pin.txt 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g' | clean

done

for precreate in false true ; do

	rm -fr $tmpdir/${scheme}db
	mkdir -p $tmpdir/${scheme}db
	if $precreate ; then
		echo '['Creating database with PIN.']'
		initnssdb "${scheme:+${scheme}:}$tmpdir/${scheme}db" $pin
	else
		echo '['Not pre-creating database, with PIN.']'
	fi

	cat > entry <<- EOF
	key_storage_type=NSSDB
	key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	key_nickname=Test
	key_pin_file=$tmpdir/pin.txt
	EOF

	echo '['Generating key${scheme:+ \($scheme\)} with PIN.']'
	$toolsdir/keygen entry | clean
	run_certutil -K -f $tmpdir/pin.txt -d ${scheme:+${scheme}:}$tmpdir/${scheme}db 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g' | clean

	echo '['Reading Key Info Without PIN.']'
	cat > entry <<- EOF
	key_storage_type=NSSDB
	key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	key_nickname=Test
	EOF
	$toolsdir/keyiread entry | clean
	run_certutil -K -f $tmpdir/empty.txt -d ${scheme:+${scheme}:}$tmpdir/${scheme}db 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g' | clean

	echo '['Reading Key Info With Bogus PIN Location.']'
	echo key_pin_file=$tmpdir/bogus-pin.txt >> entry
	$toolsdir/keyiread entry | clean

	echo '['Reading Key Info With PIN.']'
	cat > entry <<- EOF
	key_storage_type=NSSDB
	key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	key_nickname=Test
	key_pin_file=$tmpdir/pin.txt
	EOF
	$toolsdir/keyiread entry | clean

	echo '['Generating CSR Without PIN.']'
	cat > entry <<- EOF
	key_storage_type=NSSDB
	key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	key_nickname=Test
	EOF
	rm -f csr.pem
	$toolsdir/csrgen entry > csr.pem | clean
	egrep '(: |REQUEST)' $tmpdir/csr.pem

	echo '['Generating CSR With Bogus PIN Location.']'
	echo key_pin_file=$tmpdir/bogus-pin.txt >> entry
	rm -f csr.pem
	$toolsdir/csrgen entry > csr.pem | clean
	egrep '(: |REQUEST)' $tmpdir/csr.pem

	echo '['Generating CSR With PIN.']'
	cat > entry <<- EOF
	key_storage_type=NSSDB
	key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	key_nickname=Test
	key_pin_file=$tmpdir/pin.txt
	EOF
	rm -f csr.pem
	$toolsdir/csrgen entry > csr.pem | clean
	egrep '(: |REQUEST)' $tmpdir/csr.pem

done

echo '['Test complete.']'
