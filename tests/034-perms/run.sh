#!/bin/bash
cd "$tmpdir"

function list() {
	$toolsdir/ls *.* | sed -e "s~^$owner:$group|~\$owner:\$group|~g"
}
function resetperms() {
	chown $owner:$group *.*
	chmod 0755 *.*
}

cat > ca << EOF
id=Local
ca_type=EXTERNAL
ca_external_helper=$builddir/../src/local-submit -d $tmpdir
EOF

owner=`id -un`
group=`id -gn`
cat > entry << EOF
id=Test
ca_name=Local
key_storage_type=FILE
key_storage_location=$tmpdir/ee.key
key_owner=$owner:$group
key_perms=0620
cert_storage_type=FILE
cert_storage_location=$tmpdir/ee.crt
cert_owner=$owner:$group
cert_perms=0662
notification_method=STDOUT
EOF

echo '[start]'
list

echo '[keygen]'
$toolsdir/keygen entry > /dev/stderr
list

echo '[reset]'
resetperms
list

echo '[csrgen]'
$toolsdir/csrgen entry > /dev/stderr
list

echo '[reset]'
resetperms
list

echo '[submit]'
$toolsdir/submit ca entry > /dev/stderr
list

echo '[reset]'
resetperms
list

echo '[save]'
$toolsdir/certsave entry
list

rm *.*

echo '[rekey:start]'
list

echo '[rekey:keygen]'
$toolsdir/keygen entry > /dev/stderr
list

echo '[rekey:reset]'
resetperms
list

echo '[rekey:rekey]'
$toolsdir/keygen entry > /dev/stderr
marker=`grep ^key_next_marker= entry | cut -f2- -d=`
list | sed "s~^$owner:$group|~\$owner:\$group|~g" | sed "s,$marker,MARKER,g"

echo '[rekey:reset]'
resetperms
list | sed "s~^$owner:$group|~\$owner:\$group|~g" | sed "s,$marker,MARKER,g"

echo '[rekey:csrgen]'
$toolsdir/csrgen entry > /dev/stderr
list | sed "s~^$owner:$group|~\$owner:\$group|~g" | sed "s,$marker,MARKER,g"

echo '[rekey:reset]'
resetperms
list | sed "s~^$owner:$group|~\$owner:\$group|~g" | sed "s,$marker,MARKER,g"

echo '[rekey:submit]'
$toolsdir/submit ca entry > /dev/stderr
list | sed "s~^$owner:$group|~\$owner:\$group|~g" | sed "s,$marker,MARKER,g"

echo '[rekey:reset]'
resetperms
list | sed "s~^$owner:$group|~\$owner:\$group|~g" | sed "s,$marker,MARKER,g"

echo '[rekey:save]'
$toolsdir/certsave entry
list | sed "s~^$owner:$group|~\$owner:\$group|~g" | sed "s,$marker,MARKER,g"

rm *.*

cat > entry <<- EOF
id=Test
ca_name=Local
key_storage_type=NSSDB
key_storage_location=$scheme$tmpdir
key_nickname=EE
key_owner=$owner:$group
key_perms=0620
cert_storage_type=NSSDB
cert_storage_location=$scheme$tmpdir
cert_nickname=EE
cert_owner=$owner:$group
cert_perms=0662
notification_method=STDOUT
EOF
echo

echo '['$scheme'start]'
list

echo '['$scheme'keygen]'
$toolsdir/keygen entry > /dev/stderr
list

echo '['$scheme'reset]'
resetperms
list

echo '['$scheme'csrgen]'
$toolsdir/csrgen entry > /dev/stderr
list

echo '['$scheme'reset]'
resetperms
list

echo '['$scheme'submit]'
$toolsdir/submit ca entry > /dev/stderr
list

echo '['$scheme'reset]'
resetperms
list

echo '['$scheme'save]'
$toolsdir/certsave entry
list

rm *.*

echo '[rekey:'$scheme'start]'
list

echo '[rekey:'$scheme'keygen]'
$toolsdir/keygen entry > /dev/stderr
list

echo '[rekey:'$scheme'reset]'
resetperms
list

echo '[rekey:'$scheme'keygen]'
$toolsdir/keygen entry > /dev/stderr
list

echo '[rekey:'$scheme'reset]'
resetperms
list

echo '[rekey:'$scheme'csrgen]'
$toolsdir/csrgen entry > /dev/stderr
list

echo '[rekey:'$scheme'reset]'
resetperms
list

echo '[rekey:'$scheme'submit]'
$toolsdir/submit ca entry > /dev/stderr
list

echo '[rekey:'$scheme'reset]'
resetperms
list

echo '[rekey:'$scheme'save]'
$toolsdir/certsave entry
list

rm *.*
echo OK
