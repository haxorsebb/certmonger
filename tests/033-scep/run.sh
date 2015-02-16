#!/bin/bash
cd "$tmpdir"

SCEP_MSGTYPE_PKCSREQ="19"
SCEP_MSGTYPE_CERTREP="3"
SCEP_MSGTYPE_GETCERTINITIAL="20"
SCEP_MSGTYPE_GETCERT="21"
SCEP_MSGTYPE_GETCRL="22"

$toolsdir/cachain.sh 0 2> /dev/null

cat > ca << EOF
id=SCEP
ca_type=EXTERNAL
EOF
var="ca_encryption_cert="
cat ca0.crt | while read line ; do
	echo "$var""$line" >> ca
	var=" "
done

cat > entry << EOF
id=Test
ca_name=SelfSign
state=NEED_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/ee.key
cert_storage_type=FILE
cert_storage_location=$tmpdir/ee.crt
notification_method=STDOUT
EOF

$toolsdir/certread entry > /dev/null
$toolsdir/csrgen entry > /dev/null
$toolsdir/scepgen ca entry > scepdata

echo -----BEGIN CERTIFICATE----- > mini.crt
minicert=`grep ^minicert: scepdata | cut -f2- -d:`
while test -n "$minicert" ; do
	line=`echo "$minicert" | cut -c-60`
	minicert=`echo "$minicert" | cut -c61-`
	echo $line >> mini.crt
done
echo -----END CERTIFICATE----- >> mini.crt

check_failed() {
	if ! grep -q "^verify failed$" results ; then
		echo expected signature verification to fail, but it did not
		exit 1
	fi
}
check_verified() {
	if ! grep -q "^verify passed$" results ; then
		echo expected signature verification to fail, but it did not
		exit 1
	fi
}
check_msgtype() {
	msgtype=`grep ^msgtype: results | cut -f2 -d:`
	if test $msgtype -ne $1 ; then
		expected message type $1, got $msgtype
	fi
}
check_txid() {
	original=`grep ^tx: scepdata | cut -f2 -d:`
	parsed=`grep ^tx: results | cut -f2 -d:`
	if test "$original" != "$parsed" ; then
		expected tx id "$original", got "$parsed"
	fi
}
check_nonce() {
	original=`grep ^nonce: scepdata | cut -f2 -d:`
	parsed=`grep ^snonce: results | cut -f2 -d:`
	if test "$original" != "$parsed" ; then
		expected nonce "$original", got "$parsed"
	fi
}

echo "[req, no trust root]"
grep ^req: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify ee.crt 2>&1 > results 2>&1
check_failed
echo OK
echo "[gic, no trust root]"
grep ^gic: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify ee.crt 2>&1 > results 2>&1
check_failed
echo OK
echo "[req, self root]"
grep ^req: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r mini.crt ee.crt 2>&1 > results 2>&1
check_failed
echo OK
echo "[gic, self root]"
grep ^gic: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r mini.crt ee.crt 2>&1 > results 2>&1
check_failed
echo OK
echo "[req, old root]"
grep ^req: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r ca0.crt ee.crt 2>&1 > results 2>&1
check_verified
check_msgtype $SCEP_MSGTYPE_PKCSREQ
check_txid
check_nonce
echo OK
echo "[gic, old trust root]"
grep ^gic: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r ca0.crt ee.crt 2>&1 > results 2>&1
check_verified
check_msgtype $SCEP_MSGTYPE_GETCERTINITIAL
check_txid
check_nonce
echo OK
echo "[req next, no trust root]"
grep ^req.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify ee.crt > results 2>&1
check_failed
echo OK
echo "[gic next, no trust root]"
grep ^gic.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify ee.crt > results 2>&1
check_failed
echo OK
echo "[req next, self root]"
grep ^req.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r mini.crt ee.crt > results 2>&1
check_verified
check_msgtype $SCEP_MSGTYPE_PKCSREQ
check_txid
check_nonce
echo OK
echo "[gic next, self root]"
grep ^gic.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r mini.crt ee.crt > results 2>&1
check_verified
check_msgtype $SCEP_MSGTYPE_GETCERTINITIAL
check_txid
check_nonce
echo OK
echo "[req next, old root]"
grep ^req.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r ca0.crt ee.crt > results 2>&1
check_failed
echo OK
echo "[gic next, old trust root]"
grep ^gic.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r ca0.crt ee.crt > results 2>&1
check_failed
echo OK
