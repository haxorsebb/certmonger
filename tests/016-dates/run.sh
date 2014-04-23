#!/bin/bash -e

cd "$tmpdir"
CERTMONGER_CONFIG_DIR=$tmpdir; export CERTMONGER_CONFIG_DIR

source "$srcdir"/functions

echo '['Tests begin.']'
$toolsdir/dates 1999 1s 30 1m 1h 24h 1d 2w 28d 1M 6M 1y 5y "3y 2M 3d"
$toolsdir/dates 2000 1s 1m 60m 24h 1d 2w 28d 1M 6M 1y 5y "3y 2M 3d"
$toolsdir/dates 2001 1s 1m 60m 1h 1d 2w 28d 1M 6M 1y 5y "3y 2M 3d"
$toolsdir/dates 2008 36h 48h "2w3600" 336h 1080h 14M 1y14M
echo '['Test complete.']'
