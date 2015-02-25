#!/bin/bash
cd "$tmpdir"

SCEP_MSGTYPE_PKCSREQ="19"
SCEP_MSGTYPE_CERTREP="3"
SCEP_MSGTYPE_GETCERTINITIAL="20"
SCEP_MSGTYPE_GETCERT="21"
SCEP_MSGTYPE_GETCRL="22"

CERTMONGER_CONFIG_DIR="$tmpdir"
export CERTMONGER_CONFIG_DIR

$toolsdir/cachain.sh 0 2> /dev/null

cat > ca << EOF
id=SCEP
ca_type=EXTERNAL
ca_capabilities=Renewal,SHA-512,SHA-256,SHA-1,DES3
EOF
var="ca_encryption_cert="
cat ca0.crt | while read line ; do
	echo "$var""$line" >> ca
	var=" "
done

openssl genrsa -out ee.key.next.key 2> /dev/null
cat > entry << EOF
id=Test
ca_name=SelfSign
state=NEED_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/ee.key
key_next_marker=next
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
		echo expected signature verification to fail, but it did not:
		cat results
		exit 1
	fi
}
check_verified() {
	if ! grep -q "^verify passed$" results ; then
		echo expected signature verification to succeed, but it did not:
		cat results
		exit 1
	fi
}
set_digest() {
	cat > $CERTMONGER_CONFIG_DIR/certmonger.conf <<- EOF
	[defaults]
	digest = $1
	notification_method = stdout
	[selfsign]
	validity_period = 1d
	EOF
}
check_digest() {
	digest=`grep ^digest: results | cut -f2 -d:`
	if test $digest != $1 ; then
		echo expected digest $1, got "$digest":
		cat results
	fi
}
check_msgtype() {
	msgtype=`grep ^msgtype: results | cut -f2 -d:`
	if test $msgtype -ne $1 ; then
		echo expected message type $1, got "$msgtype":
		cat results
	fi
}
check_txid() {
	original=`grep ^tx: scepdata | cut -f2 -d:`
	parsed=`grep ^tx: results | cut -f2 -d:`
	if test "$original" != "$parsed" ; then
		echo expected tx id "$original", got "$parsed":
		cat results
	fi
}
check_nonce() {
	original=`grep ^nonce: scepdata | cut -f2 -d:`
	parsed=`grep ^snonce: results | cut -f2 -d:`
	if test "$original" != "$parsed" ; then
		echo expected nonce "$original", got "$parsed":
		cat results
	fi
}

set_digest md5
$toolsdir/scepgen ca entry > scepdata

echo "[req, no trust root]"
if test x`grep ^req: scepdata | cut -f2- -d:` = x ; then
	echo missing req
fi
grep ^req: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify ee.crt 2>&1 > results 2>&1
check_failed
echo OK
echo "[gic, no trust root]"
if test x`grep ^gic: scepdata | cut -f2- -d:` = x ; then
	echo missing gic
fi
grep ^gic: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify ee.crt 2>&1 > results 2>&1
check_failed
echo OK
echo "[req, self root]"
if test x`grep ^req: scepdata | cut -f2- -d:` = x ; then
	echo missing req
fi
grep ^req: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r mini.crt ee.crt 2>&1 > results 2>&1
check_failed
echo OK
echo "[gic, self root]"
if test x`grep ^gic: scepdata | cut -f2- -d:` = x ; then
	echo missing gic
fi
grep ^gic: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r mini.crt ee.crt 2>&1 > results 2>&1
check_failed
echo OK
echo "[req, old root]"
set_digest md5
$toolsdir/scepgen ca entry > scepdata
if test x`grep ^req: scepdata | cut -f2- -d:` = x ; then
	echo missing req
fi
grep ^req: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r ca0.crt ee.crt 2>&1 > results 2>&1
check_verified
check_msgtype $SCEP_MSGTYPE_PKCSREQ
check_txid
check_nonce
check_digest md5
echo OK
echo "[gic, old trust root]"
set_digest sha1
$toolsdir/scepgen ca entry > scepdata
if test x`grep ^gic: scepdata | cut -f2- -d:` = x ; then
	echo missing gic
fi
grep ^gic: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r ca0.crt ee.crt 2>&1 > results 2>&1
check_verified
check_msgtype $SCEP_MSGTYPE_GETCERTINITIAL
check_txid
check_nonce
check_digest sha1
echo OK
echo "[req next, no trust root]"
if test x`grep ^req.next.: scepdata | cut -f2- -d:` = x ; then
	echo missing req.next
fi
grep ^req.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify ee.crt > results 2>&1
check_failed
echo OK
echo "[gic next, no trust root]"
if test x`grep ^gic.next.: scepdata | cut -f2- -d:` = x ; then
	echo missing gic.next
fi
grep ^gic.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify ee.crt > results 2>&1
check_failed
echo OK
echo "[req next, self root]"
set_digest sha256
$toolsdir/scepgen ca entry > scepdata
if test x`grep ^req.next.: scepdata | cut -f2- -d:` = x ; then
	echo missing req.next
fi
grep ^req.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r mini.crt ee.crt > results 2>&1
check_verified
check_msgtype $SCEP_MSGTYPE_PKCSREQ
check_txid
check_nonce
check_digest sha256
echo OK
echo "[gic next, self root]"
if test x`grep ^gic.next.: scepdata | cut -f2- -d:` = x ; then
	echo missing gic.next
fi
grep ^gic.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r mini.crt ee.crt > results 2>&1
check_verified
check_msgtype $SCEP_MSGTYPE_GETCERTINITIAL
check_txid
check_nonce
echo OK
echo "[req next, old root]"
if test x`grep ^req.next.: scepdata | cut -f2- -d:` = x ; then
	echo missing req.next
fi
grep ^req.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r ca0.crt ee.crt > results 2>&1
check_failed
echo OK
echo "[gic next, old trust root]"
if test x`grep ^gic.next.: scepdata | cut -f2- -d:` = x ; then
	echo missing gic.next
fi
grep ^gic.next.: scepdata | cut -f2- -d: | base64 -i -d | $toolsdir/pk7verify -r ca0.crt ee.crt > results 2>&1
check_failed
echo OK
