#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions

cert="-----BEGIN CERTIFICATE-----
MIIEDjCCAvagAwIBAgIOAQAAAAABPWT1Paf0wU4wDQYJKoZIhvcNAQEFBQAwRjEX
MBUGA1UEChMOQ3liZXJ0cnVzdCBJbmMxKzApBgNVBAMTIkN5YmVydHJ1c3QgUHVi
bGljIFN1cmVTZXJ2ZXIgU1YgQ0EwHhcNMTMwMzEzMTc0ODQ3WhcNMTQwMzEzMTc0
ODQ3WjBuMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTk9SVEggQ0FST0xJTkExEDAO
BgNVBAcTB1JhbGVpZ2gxEDAOBgNVBAoTB1JlZCBIYXQxCzAJBgNVBAsTAklUMRUw
EwYDVQQDFAwqLnJlZGhhdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC8NmWLQuAdaMTQ2Ae8AVPUKDEdCNtGBE4It5hb4xL9cHSzQeBaMDm9UR5X
w5DLR93TQFL+Rc9mLbrBhIz9eacrs5qpUp4i5XhgnvEN7vBsUyFjZqQ+W5Zqs5Cv
yMVv+rkRRa22hYPqFNM0R0lBPLltZO6+58VA53ttr87JOdPZsdomJtzruXz9ceLg
ZnDULmIfZFhw7bz0Y9qAURSsULpIjLwWsGjOlNpPSTisCNwNWrmT4KerD8RnCXy+
keWZPSw9RgMBbyYD6am0nj2/JPmkv390F6HYi6f/0OyefKqZEaPgwDmhEiW6K2Ps
qodUKMcfBFJNgPs6ZuqOLnGILVyrAgMBAAGjgdEwgc4wHwYDVR0jBBgwFoAUBJhg
34AblkldZVYtpSwJJArs3LkwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5v
bW5pcm9vdC5jb20vUHVibGljU3VyZVNlcnZlclNWLmNybDAdBgNVHQ4EFgQUC5p5
rlungiFqeTNw0HOISTrudr8wCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBEGCWCGSAGG+EIBAQQEAwIGwDAN
BgkqhkiG9w0BAQUFAAOCAQEAJC1PfXXjM3Y2ifPlzauQgLHiizx3XeIB86AXJHL2
N77UMfkSYmUJraWZX3Ye7icDbRwNHLIDJMfpjgcwnC+ZB+byyvmtjGjcTuqVZpXS
2JU8kgGxNlEjCd4NsumpzollG1W1iDorBCt9bHp8b4isLD+jSnqbWKnvuEUle0ad
Pi7xjf9BidMvYUEBpJsd9rA1LQtp/ZfxxA6RtgCeXjQPexjsvf6SLKyrmacHZcMJ
b6JbhXMTzB7QZjR3IooqzXS8T/2zBxDUSH4fJ4o0KSkY8cjNCCxdnkXL96PC9KQ5
kV1Ad3iHw/TnJjzrJJs3o92pRR/JtF0Jw6dszNP1Sn68uA==
-----END CERTIFICATE-----"

cat > ca-issued << EOF
#!/bin/sh
echo "$cert"
exit 0
EOF
chmod u+x ca-issued
cat > ca-issued-with-no-newline << EOF
#!/bin/sh
echo -n "$cert"
exit 0
EOF
chmod u+x ca-issued-with-no-newline
cat > ca-issued-with-noise-before << EOF
#!/bin/sh
echo iLoveCookies
echo "$cert"
exit 0
EOF
chmod u+x ca-issued-with-noise-before
cat > ca-issued-with-noise-after << EOF
#!/bin/sh
echo "$cert"
echo iLoveCookies
exit 0
EOF
chmod u+x ca-issued-with-noise-after
cat > ca-issued-with-noise-both << EOF
#!/bin/sh
echo iLoveCookies
echo "$cert"
echo Also Monkeys
exit 0
EOF
chmod u+x ca-issued-with-noise-both
cat > ca-ask-again << EOF
#!/bin/sh
echo iLoveCookiesSome
exit 1
EOF
chmod u+x ca-ask-again
cat > ca-issued-binary-x509 << EOF
#!/bin/sh
echo "$cert" | openssl x509 -outform der
exit 0
EOF
chmod u+x ca-issued-binary-x509
cat > ca-reject << EOF
#!/bin/sh
echo CA rejected us, must have been having a bad day.
exit 2
EOF
chmod u+x ca-reject
cat > ca-reject-second-time << EOF
#!/bin/sh
if test -z "\$CERTMONGER_CA_COOKIE" ; then
	echo 1
	echo Try again.
	echo
	echo Maybe later.
	exit 5
else
	echo CA rejected us, must have been having a bad day.
	echo cookie was "\$CERTMONGER_CA_COOKIE"
	exit 2
fi
EOF
chmod u+x ca-reject-second-time
cat > ca-unreachable << EOF
#!/bin/sh
echo Could not contact CA.
exit 3
EOF
chmod u+x ca-unreachable
cat > ca-unconfigured << EOF
#!/bin/sh
echo Something is wrong with my brain.
exit 4
EOF
chmod u+x ca-unconfigured
cat > ca-ask-again-5 << EOF
#!/bin/sh
echo 13
echo iLoveCookiesMore
exit 5
EOF
chmod u+x ca-ask-again-5
cat > ca-ask-again-broken-5 << EOF
#!/bin/sh
echo "?1034h13"
echo iLoveCookiesMore
exit 5
EOF
chmod u+x ca-ask-again-broken-5
cat > ca-what-what-6 << EOF
#!/bin/sh
echo What do you want?
exit 6
EOF
chmod u+x ca-what-what-6
cat > ca-needs-scep-16 << EOF
#!/bin/sh
echo Nope, need SCEP data.
exit 16
EOF
chmod u+x ca-needs-scep-16

cat > ca << EOF
id=SelfSign
ca_type=INTERNAL:SELF
EOF

cat > entry << EOF
id=Test
ca_name=SelfSign
state=NEED_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile
notification_method=STDOUT
post_certsave_command=echo POSTHOOK
post_certsave_uid=`id -u`
pre_certsave_command=echo PREHOOK
pre_certsave_uid=`id -u`
EOF
# These cover parts of the process, forcing it to stop if any phase needs
# to be tried again, so that we don't hit infinite loops.
echo '[Generating key pair.]'
$toolsdir/iterate ca entry GENERATING_KEY_PAIR,HAVE_KEY_PAIR
if test "`grep ^state entry`" != state=NEED_KEYINFO ; then
	echo Key generation failed or did not move to key info reading.
	grep ^state entry
	exit 1
fi
grep ^key.\*count= entry | LANG=C sort

echo
echo '[Reading back key info.]'
$toolsdir/iterate ca entry NEED_KEYINFO,START_READING_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
if test "`grep ^state entry`" != state=NEED_CSR ; then
	echo Key info read failed or did not move to CSR generation.
	grep ^state entry
	exit 1
fi
grep ^key_size entry
grep ^key.\*count= entry | LANG=C sort

echo
echo '[Generating CSR.]'
$toolsdir/iterate ca entry HAVE_KEYINFO,NEED_CSR,GENERATING_CSR
if test "`grep ^state entry`" != state=HAVE_CSR ; then
	echo CSR generation failed or did not move to submission.
	grep ^state entry
	exit 1
fi
grep ^key.\*count= entry | LANG=C sort

echo
echo '[Getting CSR signed.]'
$toolsdir/iterate ca entry HAVE_CSR,NEED_TO_SUBMIT,SUBMITTING
if test "`grep ^state entry`" != state=NEED_TO_SAVE_CERT ; then
	echo Signing failed or did not move to saving.
	grep ^state entry
	exit 1
fi
grep ^key.\*count= entry | LANG=C sort

echo
echo '[Saving certificate.]'
$toolsdir/iterate ca entry START_SAVING_CERT,PRE_SAVE_CERT,SAVING_CERT,NEED_TO_READ_CERT,READING_CERT,POST_SAVED_CERT,NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS,NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED,SAVED_CERT | sed 's@'"$tmpdir"'@$tmpdir@g'
if test "`grep ^state entry`" != state=MONITORING ; then
	echo Saving failed or did not move to monitoring.
	grep ^state entry
	exit 1
fi
grep ^key.\*count= entry | LANG=C sort

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
notification_method=STDOUT
EOF
$toolsdir/iterate ca entry NEWLY_ADDED,NEWLY_ADDED_START_READING_KEYINFO,NEWLY_ADDED_READING_KEYINFO,NEWLY_ADDED_START_READING_CERT,NEWLY_ADDED_READING_CERT,NEWLY_ADDED_DECIDING
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
notification_method=STDOUT
EOF
$toolsdir/iterate ca entry NEWLY_ADDED,NEWLY_ADDED_START_READING_KEYINFO,NEWLY_ADDED_READING_KEYINFO,NEWLY_ADDED_START_READING_CERT,NEWLY_ADDED_READING_CERT,NEWLY_ADDED_DECIDING
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
notification_method=STDOUT
EOF
$toolsdir/iterate ca entry NEWLY_ADDED,NEWLY_ADDED_START_READING_KEYINFO,NEWLY_ADDED_READING_KEYINFO,NEWLY_ADDED_START_READING_CERT,NEWLY_ADDED_READING_CERT,NEWLY_ADDED_DECIDING
if test "`grep ^state entry`" != state=MONITORING ; then
	echo Figuring stuff out failed or did not move to monitoring.
	grep ^state entry
	exit 1
fi


echo
echo '[Retroactive issuing.]'
cat > entry2 << EOF
id=Test
ca_name=SelfSign
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
ca_internal_issue_time=0
EOF
$toolsdir/iterate ca2 entry2 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca2 entry2 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca2 entry2 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca2 entry2 START_SAVING_CERT,SAVING_CERT,NEED_TO_READ_CERT,READING_CERT,NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS,NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED,SAVED_CERT | sed 's@'"$tmpdir"'@$tmpdir@g'
openssl x509 -noout -startdate -enddate -in $tmpdir/certfile2
echo
echo '[Noticing expiration.]'
openssl x509 -noout -startdate -enddate -in $tmpdir/certfile2
$toolsdir/iterate ca  entry2 NEED_TO_NOTIFY_VALIDITY,NOTIFYING_VALIDITY | sed 's@'"$tmpdir"'@$tmpdir@g'

echo
echo '[Kicking off autorenew.]'
cat > entry2 << EOF
id=Test
ca_name=SelfSign
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
$toolsdir/iterate ca  entry2 MONITORING,NEED_TO_NOTIFY_VALIDITY,NOTIFYING_VALIDITY | sed 's@'"$tmpdir"'@$tmpdir@g'

echo
echo '[Enroll.]'
cat > entry3 << EOF
id=Test
ca_name=Friendly
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile4
notification_method=STDOUT
EOF
cat > ca3 << EOF
id=Friendly
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-issued
EOF
: > $tmpdir/certfile4
$toolsdir/iterate ca3 entry3 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
grep ^key.\*count= entry3 | LANG=C sort
$toolsdir/iterate ca3 entry3 NEED_CSR,GENERATING_CSR
grep ^key.\*count= entry3 | LANG=C sort
$toolsdir/iterate ca3 entry3 NEED_TO_SUBMIT,SUBMITTING
grep ^key.\*count= entry3 | LANG=C sort
$toolsdir/iterate ca3 entry3 NEED_TO_SAVE_CERT,SAVING_CERT,START_SAVING_CERT
grep ^key.\*count= entry3 | LANG=C sort

echo
echo '[Enroll, helper produces noise before.]'
cat > entry3 << EOF
id=Test
ca_name=Friendly
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile4
notification_method=STDOUT
EOF
cat > ca3 << EOF
id=Friendly
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-issued-with-noise-before
EOF
: > $tmpdir/certfile4
$toolsdir/iterate ca3 entry3 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca3 entry3 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca3 entry3 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca3 entry3 NEED_TO_SAVE_CERT,SAVING_CERT,START_SAVING_CERT

echo
echo '[Enroll, helper produces noise after]'
cat > entry3 << EOF
id=Test
ca_name=Friendly
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile4
notification_method=STDOUT
EOF
cat > ca3 << EOF
id=Friendly
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-issued-with-noise-after
EOF
: > $tmpdir/certfile4
$toolsdir/iterate ca3 entry3 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca3 entry3 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca3 entry3 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca3 entry3 NEED_TO_SAVE_CERT,SAVING_CERT,START_SAVING_CERT

echo
echo '[Enroll, helper produces noise before and after.]'
cat > entry3 << EOF
id=Test
ca_name=Friendly
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile4
notification_method=STDOUT
EOF
cat > ca3 << EOF
id=Friendly
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-issued-with-noise-both
EOF
: > $tmpdir/certfile4
$toolsdir/iterate ca3 entry3 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca3 entry3 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca3 entry3 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca3 entry3 NEED_TO_SAVE_CERT,SAVING_CERT,START_SAVING_CERT

echo
echo '[Enroll, helper omits newline at end of certificate.]'
cat > entry3 << EOF
id=Test
ca_name=Friendly
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile4
notification_method=STDOUT
EOF
cat > ca3 << EOF
id=Friendly
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-issued-with-no-newline
EOF
: > $tmpdir/certfile4
$toolsdir/iterate ca3 entry3 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca3 entry3 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca3 entry3 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca3 entry3 NEED_TO_SAVE_CERT,SAVING_CERT,START_SAVING_CERT

echo
echo '[Enroll, helper produces binary certificate output.]'
cat > entry3 << EOF
id=Test
ca_name=Friendly
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile4
notification_method=STDOUT
EOF
cat > ca3 << EOF
id=Friendly
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-issued-binary-x509
EOF
: > $tmpdir/certfile4
$toolsdir/iterate ca3 entry3 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca3 entry3 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca3 entry3 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca3 entry3 NEED_TO_SAVE_CERT,SAVING_CERT,START_SAVING_CERT

echo
echo '[Enroll until we notice we have no specified CA.]'
cat > entry3 << EOF
id=Test
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
notification_method=STDOUT
EOF
cat > ca3 << EOF
id=Meanie
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-reject
EOF
$toolsdir/iterate ca3 entry3 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca3 entry3 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca3 entry3 NEED_TO_SUBMIT,SUBMITTING

echo
echo '[Enroll until the CA tells us to come back later.]'
cat > entry4 << EOF
id=Test
ca_name=Busy
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
notification_method=STDOUT
EOF
cat > ca4 << EOF
id=Busy
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-ask-again
EOF
$toolsdir/iterate ca4 entry4 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca4 entry4 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca4 entry4 NEED_TO_SUBMIT,SUBMITTING
grep ca_cookie entry4
$toolsdir/iterate ca4 entry4 ""

echo
echo '[Enroll until the CA rejects us.]'
cat > entry5 << EOF
id=Test
ca_name=Meanie
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile3
notification_method=STDOUT
EOF
cat > ca5 << EOF
id=Meanie
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-reject
EOF
$toolsdir/iterate ca5 entry5 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
grep ^key.\*count= entry5 | LANG=C sort
$toolsdir/iterate ca5 entry5 NEED_CSR,GENERATING_CSR
grep ^key.\*count= entry5 | LANG=C sort
$toolsdir/iterate ca5 entry5 NEED_TO_SUBMIT,SUBMITTING
grep ^key.\*count= entry5 | LANG=C sort
$toolsdir/iterate ca5 entry5 NEED_TO_NOTIFY_REJECTION,NOTIFYING_REJECTION | sed 's@'"$tmpdir"'@$tmpdir@g'
grep ^key.\*count= entry5 | LANG=C sort
$toolsdir/iterate ca5 entry5 "" | sed 's@'"$tmpdir"'@$tmpdir@g'
grep ^key.\*count= entry5 | LANG=C sort

echo
echo '[Enroll until the CA rejects us after poll.]'
cat > entry5 << EOF
id=Test
ca_name=Meanie
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile3
notification_method=STDOUT
EOF
cat > ca5 << EOF
id=Meanie
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-reject-second-time
EOF
$toolsdir/iterate ca5 entry5 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca5 entry5 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca5 entry5 NEED_TO_SUBMIT,SUBMITTING,CA_WORKING
$toolsdir/iterate ca5 entry5 NEED_TO_NOTIFY_REJECTION,NOTIFYING_REJECTION | sed 's@'"$tmpdir"'@$tmpdir@g'
$toolsdir/iterate ca5 entry5 "" | sed 's@'"$tmpdir"'@$tmpdir@g'

echo
echo '[Enroll until the CA turns out to be unreachable.]'
cat > entry6 << EOF
id=Test
ca_name=Lostie
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
notification_method=STDOUT
EOF
cat > ca6 << EOF
id=Lostie
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-unreachable
EOF
$toolsdir/iterate ca6 entry6 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca6 entry6 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca6 entry6 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca6 entry6 ""

echo
echo '[Enroll until the CA client turns out to be unconfigured.]'
cat > entry7 << EOF
id=Test
ca_name=Lostie
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
notification_method=STDOUT
EOF
cat > ca7 << EOF
id=Lostie
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-unconfigured
EOF
$toolsdir/iterate ca7 entry7 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca7 entry7 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca7 entry7 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca7 entry7 ""

echo
echo '[Enroll until the CA tells us to come back later.]'
cat > entry8 << EOF
id=Test
ca_name=Busy
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
notification_method=STDOUT
EOF
cat > ca8 << EOF
id=Busy
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-ask-again-5
EOF
$toolsdir/iterate ca8 entry8 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca8 entry8 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca8 entry8 NEED_TO_SUBMIT,SUBMITTING
grep ca_cookie entry8
$toolsdir/iterate ca8 entry8 ""

echo
echo '[Enroll until the CA tells us to come back later, but with a broken date.]'
cat > entry8 << EOF
id=Test
ca_name=Busy
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
notification_method=STDOUT
EOF
cat > ca8 << EOF
id=Busy
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-ask-again-broken-5
EOF
$toolsdir/iterate ca8 entry8 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca8 entry8 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca8 entry8 NEED_TO_SUBMIT,SUBMITTING
grep ca_cookie entry8 || echo NO COOKIE FOR YOU
$toolsdir/iterate ca8 entry8 ""

echo
echo "[Enroll until we realize our enrollment helper doesn't support enrollment.]"
cat > entry9 << EOF
id=Test
ca_name=Confused
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
notification_method=STDOUT
EOF
cat > ca9 << EOF
id=Confused
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-what-what-6
EOF
$toolsdir/iterate ca9 entry9 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca9 entry9 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca9 entry9 NEED_TO_SUBMIT,SUBMITTING

echo
echo "[Enroll until we have SCEP data to go with it.]"
cat > entry9 << EOF
id=Test
ca_name=SCEP
state=HAVE_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
notification_method=STDOUT
EOF
cat > ca9 << EOF
id=SCEP
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-needs-scep-16
ca_encryption_cert=-----BEGIN CERTIFICATE-----
 MIICBDCCAW2gAwIBAgIEEjRWgTANBgkqhkiG9w0BAQUFADAaMRgwFgYDVQQDDA9U
 ZXN0IExldmVsIDggQ0EwHhcNMTUwMjA0MTk0NjU4WhcNMTYwMjA0MTk0NjU4WjAX
 MRUwEwYDVQQDDAxUZXN0IEVFIENlcnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
 AoGBALjcinKYW+KHmciWmdXK5ZNRpKXcc6DqKykg0dUYgUsKTr6GYBeyA64Jmq8S
 IOYqP2gWnSnw+LWQpbzKvCW0gCO6/skqwNdDZfcxXQmWVEE2oJPmu0a5I02DD46y
 vVeugjriz2RHVNNjORXmf2xm6bZtcWtzzXew+H5lJIpRzj4LAgMBAAGjWjBYMAkG
 A1UdEwQCMAAwCwYDVR0PBAQDAgTwMB0GA1UdDgQWBBRd3x1DMcHyzexXrenW0TRw
 3ANRyjAfBgNVHSMEGDAWgBQz4V1OzMt4ObAn9koy3aLP2bzFTjANBgkqhkiG9w0B
 AQUFAAOBgQBozEcRs625HJ6YMZ2TLJKST1Z38ouIfwtl2Gv4WzGgVcRKVpoMgWjl
 DbC+yjEDPm5+GwzEwVuR0E4g/nThfff/Ld8wVLfqdvClIUcgM8XEpPSRGrWLri+t
 9KqCx+t7heiWQcRD4OT1EfsHmXUz2+tAat6XvRcJ3AI1gtks0vJ6mA==
 -----END CERTIFICATE-----
EOF
$toolsdir/iterate ca9 entry9 NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
grep ^key.\*count= entry9 | LANG=C sort
$toolsdir/iterate ca9 entry9 NEED_CSR,GENERATING_CSR
grep ^key.\*count= entry9 | LANG=C sort
$toolsdir/iterate ca9 entry9 NEED_TO_SUBMIT,SUBMITTING
grep ^key.\*count= entry9 | LANG=C sort
$toolsdir/iterate ca9 entry9 NEED_SCEP_DATA,GENERATING_SCEP_DATA,HAVE_SCEP_DATA
grep ^key.\*count= entry9 | LANG=C sort

# Note! The "iterate" harness rounds delay times up to the next multiple of 50.
for interval in 0 30 1800 3600 7200 86000 86500 604800 1000000 2000000; do
	now=`date +%s`
	CM_FORCE_TIME=$now ; export CM_FORCE_TIME
	when=`expr $now + $interval`
	later=`env TZ=UTC date -d @$when +%Y%m%d%H%M%S`
	for ca in ca-unreachable ca-ask-again ca-unconfigured ; do
		echo
		echo '[CA poll timeout remaining='$interval'.]'
		cat > entry9 <<- EOF
		id=Test
		ca_name=Lostie
		state=HAVE_CSR
		cert_not_after=$later
		csr=AAAA
		notification_method=STDOUT
		EOF
		cat > ca9 <<- EOF
		id=Lostie
		ca_type=EXTERNAL
		ca_external_helper=$tmpdir/$ca
		EOF
		$toolsdir/iterate ca9 entry9 NEED_TO_SUBMIT,SUBMITTING
	done
	echo
	echo '[Monitor poll timeout remaining='$interval'.]'
	cat > entry9 <<- EOF
	id=Test
	ca_name=Lostie
	state=MONITORING
	cert_not_after=$later
	csr=AAAA
	notification_method=STDOUT
	EOF
	cat > ca9 <<- EOF
	id=Lostie
	ca_type=EXTERNAL
	ca_external_helper=$tmpdir/$ca
	EOF
	$toolsdir/iterate ca9 entry9 ""
done

SAVED_CONFIG_DIR="$CERTMONGER_CONFIG_DIR"
CERTMONGER_CONFIG_DIR=`pwd`
echo
echo '[Kicking off split monitor/enroll TTL tests.]'
cat > entry10 << EOF
id=Test
ca_name=SelfSign
state=NEWLY_ADDED
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile10
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile10
monitor=1
autorenew=1
notification_method=STDOUT
EOF
cat > ca10 << EOF
id=SelfSign
ca_type=INTERNAL:SELF
ca_internal_issue_time=0
EOF
$toolsdir/iterate ca10 entry10 NEWLY_ADDED_START_READING_KEYINFO,NEWLY_ADDED_READING_KEYINFO,NEWLY_ADDED_START_READING_CERT,NEWLY_ADDED_READING_CERT,NEWLY_ADDED_DECIDING
$toolsdir/iterate ca10 entry10 NEED_KEY_PAIR,GENERATING_KEY_PAIR,HAVE_KEY_PAIR,NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO
$toolsdir/iterate ca10 entry10 NEED_CSR,GENERATING_CSR
$toolsdir/iterate ca10 entry10 NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca10 entry10 START_SAVING_CERT,SAVING_CERT,NEED_TO_READ_CERT,READING_CERT,NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS,NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED,SAVED_CERT | sed 's@'"$tmpdir"'@$tmpdir@g'
cp $tmpdir/certfile10 $tmpdir/certfile10.bak

echo
echo '[Kicking off enroll only.]'
cp $tmpdir/certfile10.bak $tmpdir/certfile10
cat > entry10 << EOF
id=Test
ca_name=SelfSign
state=MONITORING
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile10
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile10
monitor=1
autorenew=1
notification_method=STDOUT
EOF
cat > ca10 << EOF
id=SelfSign
ca_type=INTERNAL:SELF
ca_internal_issue_time=0
EOF
openssl x509 -noout -startdate -enddate -in $tmpdir/certfile10
cat > certmonger.conf << EOF
[defaults]
enroll_ttls = 30s
notify_ttls = N
EOF
$toolsdir/iterate ca10 entry10 NEED_CSR,GENERATING_CSR,HAVE_CSR,NEED_TO_SUBMIT,SUBMITTING,NEED_TO_SAVE_CERT,START_SAVING_CERT,SAVING_CERT,NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS,NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED,SAVED_CERT,NEED_TO_READ_CERT,READING_CERT | sed 's@'"$tmpdir"'@$tmpdir@g'

echo
echo '[Kicking off notify only.]'
cp $tmpdir/certfile10.bak $tmpdir/certfile10
cat > entry10 << EOF
id=Test
ca_name=SelfSign
state=MONITORING
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile10
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile10
monitor=1
autorenew=1
notification_method=STDOUT
EOF
cat > ca10 << EOF
id=SelfSign
ca_type=INTERNAL:SELF
ca_internal_issue_time=0
EOF
openssl x509 -noout -startdate -enddate -in $tmpdir/certfile10
cat > certmonger.conf << EOF
[defaults]
notify_ttls = 30s
enroll_ttls = N
EOF
$toolsdir/iterate ca10 entry10 NEED_TO_NOTIFY_VALIDITY,NOTIFYING_VALIDITY | sed 's@'"$tmpdir"'@$tmpdir@g'

echo
echo '[Kicking off notify-then-submit.]'
: > $tmpdir/notification.txt
cat > $tmpdir/notify.sh << EOF
#!/bin/sh
touch $tmpdir/notification.txt
echo The sky is falling: \$CERTMONGER_NOTIFICATION >> $tmpdir/notification.txt
EOF
chmod u+x $tmpdir/notify.sh
cp $tmpdir/certfile10.bak $tmpdir/certfile10
cat > entry10 << EOF
id=Test
ca_name=SelfSign
state=MONITORING
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile10
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile10
monitor=1
autorenew=1
notification_method=STDOUT
EOF
cat > ca10 << EOF
id=SelfSign
ca_type=INTERNAL:SELF
ca_internal_issue_time=0
EOF
openssl x509 -noout -startdate -enddate -in $tmpdir/certfile10
cat > certmonger.conf << EOF
[defaults]
notify_ttls = 30s
enroll_ttls = 30s
notification_method=command
notification_destination=$tmpdir/notify.sh
EOF
$toolsdir/iterate ca10 entry10 NEED_TO_NOTIFY_VALIDITY,NOTIFYING_VALIDITY,NEED_CSR,GENERATING_CSR,HAVE_CSR,NEED_TO_SUBMIT,SUBMITTING,NEED_TO_SAVE_CERT,START_SAVING_CERT,SAVING_CERT,NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS,NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED,SAVED_CERT,NEED_TO_READ_CERT,READING_CERT | sed 's@'"$tmpdir"'@$tmpdir@g'
cat $tmpdir/notification.txt | sed 's@'"$tmpdir"'@$tmpdir@g'
CERTMONGER_CONFIG_DIR="$SAVED_CONFIG_DIR"

echo
echo Test complete.
