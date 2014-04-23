#!/bin/bash -e

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
# Accept 366*24*60*60 as a valid substitute for 365*24*60*60 when computing
# seconds-until-it's-one-year-from-now
$toolsdir/prefs | sed -e 's,31622400$,31536000,g'

echo '['TTL settings compatibility and notification commands.']'
cat > certmonger.conf << EOF
[defaults]
enroll_ttls = 1d 14d 7d 28d
notify_ttls = 1d 14d 7d
notification_method = command
notification_destination = logger "The sky is falling!"
EOF
$toolsdir/prefs

echo '['Test complete.']'
