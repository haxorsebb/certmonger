#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions

cat > ca-data << EOF
#!/bin/sh
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
case "\$CERTMONGER_OPERATION" in
IDENTIFY)
	echo Test
	;;
FETCH-ROOTS)
	echo Root
	echo "\$cert"
	;;
GET-SUPPORTED-TEMPLATES)
	echo None
	;;
GET-DEFAULT-TEMPLATE)
	echo None
	;;
GET-NEW-REQUEST-REQUIREMENTS)
	echo None
	;;
GET-RENEW-REQUEST-REQUIREMENTS)
	echo None
	;;
esac
exit 0
EOF
chmod +x $tmpdir/ca-data

for phase in identify certs profiles default_profile enrollment_reqs renewal_reqs ; do
# These cover parts of the process, forcing it to stop if any phase needs
# to be tried again, so that we don't hit infinite loops.
for state in IDLE NEED_TO_REFRESH,REFRESHING UNREACHABLE NEED_TO_SAVE_DATA,PRE_SAVE_DATA,START_SAVING_DATA,SAVING_DATA,NEED_POST_SAVE_DATA,POST_SAVE_DATA,SAVED_DATA NEED_TO_ANALYZE,ANALYZING DISABLED NEED_TO_REFRESH,REFRESHING,NEED_TO_SAVE_DATA,PRE_SAVE_DATA,START_SAVING_DATA,SAVING_DATA,NEED_POST_SAVE_DATA,POST_SAVE_DATA,SAVED_DATA ; do
init=`echo $state | cut -f1 -d,`

cat > ca << EOF
id=Test CA
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-data
EOF

cat > entry << EOF
id=Test
ca_name=Test CA
state=NEED_KEY_PAIR
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile
notification_method=STDOUT
EOF

echo '['"$phase":"$init"']'
$toolsdir/citerate ca entry $phase $init $state
cat ca
echo

done
done

echo Test complete.
