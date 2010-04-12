#!/bin/sh -e

cd "$tmpdir"
CERTMONGER_CONFIG_DIR=$tmpdir; export CERTMONGER_CONFIG_DIR

source "$srcdir"/functions

echo '['Empty file.']'
cat > certmonger.conf << EOF
EOF
$toolsdir/prefs

echo '['Empty defaults.']'
cat > certmonger.conf << EOF
[defaults]
EOF
$toolsdir/prefs

echo '['Other settings.']'
cat > certmonger.conf << EOF
[defaults]
cipher = aes256
digest = sha-1
ttls = 30 60 90
notification_method = mail
notification_destination = root
EOF
$toolsdir/prefs

echo '['Other settings.']'
cat > certmonger.conf << EOF
[defaults]
cipher = aes128
digest = sha512
ttls = 1d 14d 7d 28d 1y
notification_method = mail
notification_destination = root
EOF
$toolsdir/prefs

echo '['Test complete.']'
