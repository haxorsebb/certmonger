#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions

cat > ca << EOF
id=SelfSign
ca_type=INTERNAL:SELF
EOF

cat > entry << EOF
id=Test
state=NEED_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile
EOF
# These cover parts of the process, forcing it to stop if any phase needs
# to be tried again, so that we don't hit infinite loops.
echo '[Generating key pair.]'
$toolsdir/iterate ca entry GENERATING_KEY_PAIR,HAVE_KEY_PAIR
if test "`grep ^state entry`" != state=NEED_CSR ; then
	echo Key generation failed or did not move to CSR generation.
	grep ^state entry
	exit 1
fi

echo
echo '[Generating CSR.]'
$toolsdir/iterate ca entry NEED_CSR,GENERATING_CSR
if test "`grep ^state entry`" != state=HAVE_CSR ; then
	echo CSR generation failed or did not move to submission.
	grep ^state entry
	exit 1
fi

echo
echo '[Getting CSR signed.]'
$toolsdir/iterate ca entry HAVE_CSR,NEED_TO_SUBMIT,SUBMITTING
if test "`grep ^state entry`" != state=NEED_TO_SAVE_CERT ; then
	echo Signing failed or did not move to saving.
	grep ^state entry
	exit 1
fi

echo
echo '[Saving certificate.]'
$toolsdir/iterate ca entry SAVING_CERT,NEED_TO_READ_CERT,READING_CERT,SAVED_CERT
if test "`grep ^state entry`" != state=MONITORING ; then
	echo Saving failed or did not move to monitoring.
	grep ^state entry
	exit 1
fi

echo
echo '[From-scratch enrollment scenario OK.]'

echo
echo '[Picking up mid-life without a key or a certificate.]'
cat > entry << EOF
id=Test
state=NEWLY_ADDED
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile2
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile2
EOF
$toolsdir/iterate ca entry NEWLY_ADDED,NEWLY_ADDED_READING_KEYI,NEWLY_ADDED_START_READING_CERT,NEWLY_ADDED_READING_CERT,NEWLY_ADDED_DECIDING
if test "`grep ^state entry`" != state=NEED_KEY_PAIR ; then
	echo Figuring stuff out failed or did not move to generating a key.
	grep ^state entry
	exit 1
fi

echo
echo '[Picking up mid-life without a certificate.]'
cat > entry << EOF
id=Test
state=NEWLY_ADDED
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile2
EOF
$toolsdir/iterate ca entry NEWLY_ADDED,NEWLY_ADDED_READING_KEYI,NEWLY_ADDED_START_READING_CERT,NEWLY_ADDED_READING_CERT,NEWLY_ADDED_DECIDING
if test "`grep ^state entry`" != state=NEED_CSR; then
	echo Figuring stuff out failed or did not move to generating a CSR.
	grep ^state entry
	exit 1
fi

echo
echo '[Picking up mid-life.]'
cat > entry << EOF
id=Test
state=NEWLY_ADDED
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile
EOF
$toolsdir/iterate ca entry NEWLY_ADDED,NEWLY_ADDED_READING_KEYI,NEWLY_ADDED_START_READING_CERT,NEWLY_ADDED_READING_CERT,NEWLY_ADDED_DECIDING
if test "`grep ^state entry`" != state=MONITORING ; then
	echo Figuring stuff out failed or did not move to monitoring.
	grep ^state entry
	exit 1
fi

echo
echo '[Retroactive issuing.]'
cat > entry2 << EOF
id=Test
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile2
monitor=1
notification_method=STDOUT
EOF
cat > ca2 << EOF
id=SelfSign
ca_type=INTERNAL:SELF
ca_internal_lifetime=1d
ca_internal_issue_time=0
EOF
$toolsdir/iterate ca2 entry2 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca2 entry2 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca2 entry2 SAVING_CERT,NEED_TO_READ_CERT,READING_CERT,SAVED_CERT
openssl x509 -noout -startdate -enddate -in $tmpdir/certfile2
echo
echo '[Noticing expiration.]'
openssl x509 -noout -startdate -enddate -in $tmpdir/certfile2
$toolsdir/iterate ca  entry2 NEED_TO_NOTIFY,NOTIFYING | sed 's@'"$tmpdir"'@$tmpdir@g'
echo
echo '[Kicking off autorenew.]'
cat > entry2 << EOF
id=Test
state=MONITORING
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile2
monitor=1
autorenew=1
notification_method=STDOUT
EOF
openssl x509 -noout -startdate -enddate -in $tmpdir/certfile2
$toolsdir/iterate ca  entry2 NEED_TO_NOTIFY,NOTIFYING | sed 's@'"$tmpdir"'@$tmpdir@g'
exit 0
