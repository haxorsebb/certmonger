#!/bin/bash -e

cd "$tmpdir"
mkdir "$tmpdir"/cas "$tmpdir"/requests "$tmpdir"/local "$tmpdir"/files "$tmpdir"/db "$tmpdir"/backup
timeout=900

cat > $tmpdir/cas/local << EOF
id=local
ca_type=EXTERNAL
ca_external_helper="$builddir"/../src/local-submit -d "$tmpdir"/local
EOF

run() {
	env CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*"
}

listfiles() {
	ls -1 files/*cert* | wc -l
	head -n 1 "$tmpdir"/files/cert
	ls -1 files/*key* | wc -l
	head -n 1 "$tmpdir"/files/key
}
listdb() {
	: > "$tmpdir"/db/pinfile
	certutil -L -d "$tmpdir"/db | grep -v Nickname | grep -v '^$' | grep -v ,S/MIME, | wc -l
	certutil -K -d "$tmpdir"/db -f "$tmpdir"/db/pinfile | grep -v Checking | grep -v '^$' | wc -l
}

extract() {
	pk12util -d "$tmpdir"/db -n first -o "$tmpdir"/files/p12 -W "" -K ""
	openssl pkcs12 -nokeys -nomacver -in "$tmpdir"/files/p12 -passin pass: -nodes | awk '/BEGIN/,/END/{print}' > "$1"/cert
	openssl pkcs12 -nocerts -nomacver -in "$tmpdir"/files/p12 -passin pass: -nodes | awk '/BEGIN/,/END/{print}' > "$1"/key
	head -n 1 "$1"/cert | wc -l
	head -n 1 "$1"/key | wc -l
}

REQOPTS="-N cn=First"

echo '[Files, initial.]'
run "$builddir"/../src/getcert request -c local -I first -w --wait-timeout=$timeout $REQOPTS -f "$tmpdir"/files/cert -k "$tmpdir"/files/key
listfiles

cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
echo '[Files, resubmit.]'
run "$builddir"/../src/getcert resubmit -c local -w --wait-timeout=$timeout -f "$tmpdir"/files/cert
listfiles
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key || echo ERROR: keys were changed on resubmit
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on resubmit

cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
echo '[Files, rekey]'
run "$builddir"/../src/getcert rekey -c local -w --wait-timeout=$timeout -f "$tmpdir"/files/cert
listfiles
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key && echo ERROR: keys were not changed on rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on rekey

rm -f "$tmpdir"/requests/* "$tmpdir"/local/* "$tmpdir"/files/* "$tmpdir"/db/* "$tmpdir"/backup/*

echo '[Database, initial.]'
run "$builddir"/../src/getcert request -c local -I first -w --wait-timeout=$timeout $REQOPTS -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/backup

echo '[Database, resubmit]'
run "$builddir"/../src/getcert resubmit -c local -w --wait-timeout=$timeout -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/files
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key || echo ERROR: keys were changed on resubmit
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on resubmit

cp "$tmpdir"/files/cert "$tmpdir"/files/key "$tmpdir"/backup
echo '[Database, rekey]'
run "$builddir"/../src/getcert rekey -c local -w --wait-timeout=$timeout -d "$tmpdir"/db -n first
listdb
extract "$tmpdir"/files
cmp -s "$tmpdir"/files/key "$tmpdir"/backup/key && echo ERROR: keys were not changed on rekey
cmp -s "$tmpdir"/files/cert "$tmpdir"/backup/cert && echo ERROR: cert was not changed on rekey

echo OK
