#!/bin/bash -e
. prequal.sh
mkdir -p $tmpdir/requests $tmpdir/cas "$tmpdir/local" $tmpdir/config
export CERTMONGER_TMPDIR="$tmpdir"
export CERTMONGER_REQUESTS_DIR="$tmpdir/requests"
export CERTMONGER_CAS_DIR="$tmpdir/cas"
export CERTMONGER_CONFIG_DIR="$tmpdir/config"
export CERTMONGER_LOCAL_CA_DIR="$tmpdir/local"
libexecdir=`$toolsdir/libexecdir`
cp ../certmonger.conf "$tmpdir"/config/
cp prequal.sh runsub.sh *.py "$tmpdir"/
for entry in entry bogus-entry ; do
	sed "s|@tmpdir@|$tmpdir|g" $entry > "$tmpdir"/requests/$entry
done
$DBUSDAEMON --session --print-address=3 --print-pid=4 --fork 3> $tmpdir/address 4> $tmpdir/pid
if test -s $tmpdir/pid ; then
	env DBUS_SESSION_BUS_ADDRESS=`cat $tmpdir/address` \
	$toolsdir/../../src/certmonger-session -n -c $tmpdir/runsub.sh
fi
kill `cat $tmpdir/pid`

cat $tmpdir/runsub.err > /dev/stderr

now=`date +%s`
for i in `seq 240` ; do
	recently=$(($now-$i))
	tomorrow=$(($now-$i+24*60*60))
	sed -i -e s/^$recently'$/recently/g' -e s/"("$recently"L)"/'(recently)'/g \
	       -e s/^$tomorrow'$/tomorrow/g' -e s/"("$tomorrow"L)"/'(tomorrow)'/g $tmpdir/runsub.out
done

cat $tmpdir/runsub.out | \
sed -r -e 's,CN=........-........-........-........,CN=$UUID,g' \
       -e '/^-----BEGIN/,/^-----END/d' \
       -e "s|$libexecdir|\$libexecdir|g" \
       -e "s|$tmpdir|\$tmpdir|g" \
       -e "s|expires:.*|expires: sometime|g" \
       -e "s|u'(00)?[0-9a-fA-F]{32}|u'"'$UUID|g'
sed
