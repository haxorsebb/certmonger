#!/bin/bash -e

cd $tmpdir

cat > $tmpdir/ca <<- EOF
id=Lostie
ca_type=EXTERNAL
ca_external_helper=$tmpdir/no-such-helper.sh
EOF
echo '['missing']'
$toolsdir/cadata -c $tmpdir/ca || echo Error $?

cat > $tmpdir/helper.sh << EOF
#!/bin/bash
case "\$CERTMONGER_OPERATION" in
IDENTIFY)
	echo Best. CA. Ever.
	exit 0
	;;
GET-DEFAULT-TEMPLATE)
	echo DefaultTemplate
	exit 0
	;;
GET-SUPPORTED-TEMPLATES)
	echo DefaultTemplate,OtherTemplate
	echo ThirdTemplate
	exit 0
	;;
GET-RENEW-REQUEST-REQUIREMENTS)
	echo CERTMONGER_REQ_PRINCIPAL
	exit 0
	;;
GET-NEW-REQUEST-REQUIREMENTS)
	echo CERTMONGER_CA_PROFILE
	echo CERTMONGER_REQ_PRINCIPAL,CERTMONGER_SPKI
	exit 0
	;;
FETCH-ROOTS)
	echo Root 1
	echo -----BEGIN CERTIFICATE-----
	echo This is a certificate.  Not a real one.
	echo -----END CERTIFICATE-----
	echo Root 2
	echo -----BEGIN CERTIFICATE-----
	echo This is a second certificate.  Not a real one.
	echo -----END CERTIFICATE-----
	echo
	echo Other Root 1
	echo -----BEGIN CERTIFICATE-----
	echo This is a third certificate.  Not a real one.
	echo -----END CERTIFICATE-----
	echo Other Root 2
	echo -----BEGIN CERTIFICATE-----
	echo This is a fourth certificate.  Not a real one.
	echo -----END CERTIFICATE-----
	echo
	echo Other Random Certificate 1
	echo -----BEGIN CERTIFICATE-----
	echo This is a fifth certificate.  Not a real one.
	echo -----END CERTIFICATE-----
	echo Other Random Certificate 2
	echo -----BEGIN CERTIFICATE-----
	echo This is a sixth certificate.  Not a real one.
	echo -----END CERTIFICATE-----
	exit 0
	;;
esac
exit 6
EOF
chmod +x $tmpdir/helper.sh

for flag in i r e d p c ; do
	cat > $tmpdir/ca <<- EOF
	id=CADataRetrievalTest
	ca_type=EXTERNAL
	ca_external_helper=$tmpdir/helper.sh
	EOF
	echo '['"$flag"']'
	$toolsdir/cadata -$flag $tmpdir/ca
	cat $tmpdir/ca
done
echo '['all']'
cat > $tmpdir/ca <<- EOF
id=CADataRetrievalTest
ca_type=EXTERNAL
ca_external_helper=$tmpdir/helper.sh
EOF
for flag in i r e d p c ; do
	$toolsdir/cadata -$flag $tmpdir/ca
done
cat $tmpdir/ca

echo OK.
