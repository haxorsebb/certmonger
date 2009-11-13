#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions

names='
id-kp
id-kp.1
id-kp.2
id-kp.3
id-kp.4
id-kp.5
id-kp.8
id-kp.9
id-kp-clientAuth
id-kp-codeSigning
id-kp-emailProtection
id-kp-OCSPSigning
id-kp-serverAuth
id-kp-timeStamping
id-ms-kp-sc-logon
id-pkinit
id-pkinit.4
id-pkinit.5
id-pkinit-KPClientAuth
id-pkinit-KPKdc
id-pkix
id-pkix.1
id-pkix.3
'
oids='
1.3.6.1.5
1.3.6.1.5.5
1.3.6.1.5.5.7
1.3.6.1.5.2
1.3.6.1.5.2.3
1.3.6.1.4.1.311.20.2.2
'
for name in $names ; do
	oid=`$toolsdir/name2oid "$name"`
	echo $name '->' $oid
done
for oid in $oids ; do
	name=`$toolsdir/oid2name "$oid"`
	echo $oid '->' $name
done

echo Test complete.
