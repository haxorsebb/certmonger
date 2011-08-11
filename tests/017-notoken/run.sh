#!/bin/sh

cd "$tmpdir"

source "$srcdir"/functions

size=2048

cat > $tmpdir/ca << EOF
id=Lostie
ca_type=EXTERNAL
ca_external_helper=$tmpdir/ca-unconfigured
EOF


rm -fr $tmpdir/${scheme}db
mkdir -p $tmpdir/${scheme}db
echo '['Creating database.']'
initnssdb "${scheme:+${scheme}:}$tmpdir/${scheme}db" BlahBlah

cat > entry <<- EOF
id=Test
key_storage_type=NSSDB
key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
key_token=No Such Token
key_nickname=Test
state=NEED_KEY_PAIR
EOF

echo '['Generating key${scheme:+ \($scheme\)} with no token.']'
$toolsdir/iterate $tmpdir/ca $tmpdir/entry NEED_KEY_PAIR,GENERATING_KEY_PAIR
grep ^state= $tmpdir/entry

rm -fr $tmpdir/${scheme}db
mkdir -p $tmpdir/${scheme}db
echo '['Creating database.']'
initnssdb "${scheme:+${scheme}:}$tmpdir/${scheme}db" BlahBlah

cat > entry <<- EOF
id=Test
key_storage_type=NSSDB
key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
key_token=No Such Token
key_nickname=Test
state=NEED_KEYINFO
EOF

echo '['Reading Key Info${scheme:+ \($scheme\)} with no token.']'
$toolsdir/iterate $tmpdir/ca $tmpdir/entry NEED_KEYINFO,READING_KEYINFO
grep ^state= $tmpdir/entry

rm -fr $tmpdir/${scheme}db
mkdir -p $tmpdir/${scheme}db
echo '['Creating database.']'
initnssdb "${scheme:+${scheme}:}$tmpdir/${scheme}db" BlahBlah

cat > entry <<- EOF
id=Test
key_storage_type=NSSDB
key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
key_token=No Such Token
key_nickname=Test
state=NEED_CSR
EOF

echo '['Generating CSR${scheme:+ \($scheme\)} with no token.']'
$toolsdir/iterate $tmpdir/ca $tmpdir/entry NEED_CSR,GENERATING_CSR
grep ^state= $tmpdir/entry

echo '['Test complete.']'
