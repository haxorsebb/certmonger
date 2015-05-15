#!/bin/bash -e

cd "$tmpdir"
mkdir "$tmpdir"/cas "$tmpdir"/requests "$tmpdir"/local "$tmpdir"/files "$tmpdir"/db "$tmpdir"/backup
timeout=900

cat > $tmpdir/cas/local << EOF
id=local
ca_type=EXTERNAL
ca_external_helper="$builddir"/../src/local-submit -d "$tmpdir"/local
EOF
cat > $tmpdir/cas/jerkca << EOF
id=jerkca
ca_type=EXTERNAL
ca_external_helper="$toolsdir"/printenv CERTMONGER_CERTIFICATE
EOF

run() {
	env CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*"
}

listfiles() {
	echo -n certs:
	echo -n certs: 1>&2
	ls -1 files/*cert* | wc -l
	ls -1 files/*cert* 1>&2
	for cert in "$tmpdir"/files/*cert* ; do
		head -n 1 "$cert"
	done
	echo -n keys:
	echo -n keys: 1>&2
	ls -1 files/*key* | wc -l
	ls -1 files/*key* 1>&2
	for key in "$tmpdir"/files/*key* ; do
		head -n 1 "$key"
	done
}
listdb() {
	: > "$tmpdir"/db/pinfile
	echo -n certs:
	echo -n certs: 1>&2
	certutil -L -d "$tmpdir"/db | grep -v Nickname | grep -v '^$' | grep -v ,S/MIME, | wc -l
	certutil -L -d "$tmpdir"/db | wc -l 1>&2
	echo -n keys:
	echo -n keys: 1>&2
	certutil -K -d "$tmpdir"/db -f "$tmpdir"/db/pinfile | grep -v Checking | grep -v '^$' | wc -l
	certutil -K -d "$tmpdir"/db -f "$tmpdir"/db/pinfile 1>&2
}

extract() {
	pk12util -d "$tmpdir"/db -n first -o "$tmpdir"/files/p12 -W "" -K ""
	openssl pkcs12 -nokeys -nomacver -in "$tmpdir"/files/p12 -passin pass: -nodes | awk '/BEGIN/,/END/{print}' > "$1"/cert
	openssl pkcs12 -nocerts -nomacver -in "$tmpdir"/files/p12 -passin pass: -nodes | awk '/BEGIN/,/END/{print}' > "$1"/key
	echo -n cert:
	head -n 1 "$1"/cert | wc -l
	echo -n key:
	head -n 1 "$1"/key | wc -l
}

REQOPTS="-N cn=First"

# First round.
echo '[Files, initial.]'
run "$builddir"/../src/getcert request -c local -I first -w --wait-timeout=$timeout $REQOPTS -f "$tmpdir"/files/cert -k "$tmpdir"/files/key
listfiles

# Save the key and cert we just generated, and generate a new certificate.
cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
echo '[Files, resubmit.]'
run "$builddir"/../src/getcert resubmit -c local -w --wait-timeout=$timeout -f "$tmpdir"/files/cert
listfiles
# Make sure we have a new certificate and the key is unchanged.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key || echo ERROR: keys were changed on resubmit
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on resubmit

# Save the key and cert we just generated, and generate a new key and
# certificate.  Force its serial number, since it'll be used as part of the
# name when it's renamed out of the way later.
cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
echo 1235 > "$tmpdir"/local/serial
echo '[Files, rekey]'
run "$builddir"/../src/getcert rekey -c local -w --wait-timeout=$timeout -f "$tmpdir"/files/cert
listfiles
# Make sure we have a new certificate and key.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key && echo ERROR: keys were not changed on rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on rekey

# Save the key and cert we just generated, and generate a new key and certificate.
echo key_preserve=1 >> "$tmpdir"/requests/*
cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
echo '[Files, rekey with preserve=1]'
run "$builddir"/../src/getcert rekey -c local -w --wait-timeout=$timeout -f "$tmpdir"/files/cert
listfiles
# Make sure we have a new certificate and key, and that the old key still
# exists where we expect it to be.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key && echo ERROR: keys were not changed on rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on rekey
cmp -s "$tmpdir"/backup/key "$tmpdir"/files/key.1235.key || echo ERROR: old keys were not saved on rekey

# Save the key and cert we just generated, and try to generate a new key and certificate.
rm -f "$tmpdir"/files/key.*
cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
echo '[Files, rekey with jerk CA]'
run "$builddir"/../src/getcert rekey -c jerkca -w --wait-timeout=$timeout -f "$tmpdir"/files/cert
listfiles
# Make sure we didn't nuke the old key, but we should have been able to get rid of the candidate key.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key || echo ERROR: keys were changed on failed rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert || echo ERROR: cert was not changed on failed rekey

rm -f "$tmpdir"/requests/* "$tmpdir"/local/* "$tmpdir"/files/* "$tmpdir"/db/* "$tmpdir"/backup/*

# First round.
echo '[Database, initial.]'
run "$builddir"/../src/getcert request -c local -I first -w --wait-timeout=$timeout $REQOPTS -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/backup

# Save the key and cert we just generated, and generate a new certificate.
echo '[Database, resubmit]'
run "$builddir"/../src/getcert resubmit -c local -w --wait-timeout=$timeout -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/files
# Make sure we have a new certificate and the key is unchanged.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key || echo ERROR: keys were changed on resubmit
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on resubmit

# Save the key and cert we just generated, and generate a new key and
# certificate.  Force its serial number, since it'll be used as part of the
# name when it's renamed out of the way later.
cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
echo 1235 > "$tmpdir"/local/serial
echo '[Database, rekey]'
run "$builddir"/../src/getcert rekey -c local -w --wait-timeout=$timeout -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/files
# Make sure we have a new certificate and key.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key && echo ERROR: keys were not changed on rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on rekey

# Save the key and cert we just generated.
echo key_preserve=1 >> "$tmpdir"/requests/*
cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
# ID is based on a hash of the public key, so use that for comparison, since
# pk12util can't export a key that doesn't have a certificate to go with it.
certutil -K -d "$tmpdir"/db -f "$tmpdir"/db/pinfile | grep -v Checking | grep -v '^$' | awk '{print $3}' > "$tmpdir"/backup/id
# Generate a new key and certificate.
echo '[Database, rekey with preserve=1]'
run "$builddir"/../src/getcert rekey -c local -w --wait-timeout=$timeout -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/files
# Make sure we have a new certificate and key, and that the old key still
# exists where we expect it to be.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key && echo ERROR: keys were not changed on rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on rekey
certutil -K -d "$tmpdir"/db -f "$tmpdir"/db/pinfile | grep -v Checking | grep -v first | grep -v '^$' | awk '{print $3}' > "$tmpdir"/files/id.old
cmp -s "$tmpdir"/backup/id "$tmpdir"/files/id.old || echo ERROR: old keys were not saved on rekey

# Save the key and cert we just generated.
cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
# ID is based on a hash of the public key, so use that for comparison, since
# pk12util can't export a key that doesn't have a certificate to go with it.
certutil -K -d "$tmpdir"/db -f "$tmpdir"/db/pinfile | grep -v Checking | grep -v '^$' | awk '{print $3}' > "$tmpdir"/backup/id
# Try to generate a new key and certificate.
echo '[Database, rekey with jerk CA]'
run "$builddir"/../src/getcert rekey -c jerkca -w --wait-timeout=$timeout -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/files
# Make sure we didn't nuke the old key.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key || echo ERROR: keys were changed on failed rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert || echo ERROR: cert was not changed on failed rekey

echo key_preserve=0 >> "$tmpdir"/requests/*
# Save the key and cert we just generated.
cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
# ID is based on a hash of the public key, so use that for comparison, since
# pk12util can't export a key that doesn't have a certificate to go with it.
certutil -K -d "$tmpdir"/db -f "$tmpdir"/db/pinfile | grep -v Checking | grep -v '^$' | awk '{print $3}' > "$tmpdir"/backup/id
# Try to generate a new key and certificate.
echo '[Database, rekey with jerk CA, nonpreserving]'
run "$builddir"/../src/getcert rekey -c jerkca -w --wait-timeout=$timeout -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/files
# Make sure we didn't nuke the old key.
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key || echo ERROR: keys were changed on failed rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert || echo ERROR: cert was not changed on failed rekey

echo OK
