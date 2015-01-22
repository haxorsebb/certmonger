#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 512 1024 1536 2048 3072 4096 ; do
	echo "[nss:$size]"
	# Generate a key.
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	key_gen_size=$size
	EOF
	$toolsdir/keygen entry.$size
	# Read the type and size.
	sed -i 's,^key_gen_size.*,,g' entry.$size
	$toolsdir/keyiread entry.$size
	# Generate a new key and read it.
	echo key_gen_size=$size >> entry.$size
	$toolsdir/keygen entry.$size
	$toolsdir/keyiread entry.$size
	# One more time.
	$toolsdir/keygen entry.$size
	$toolsdir/keyiread entry.$size
	# Extract the marker.
	marker=`grep ^key_next_marker= entry.$size | cut -f2- -d=`
	# Make sure we're clean.
	run_certutil -K -d "$tmpdir" | grep keyi$size | sed -e 's,.*keyi,keyi,' -e s,"${marker:-////////}","(next)",g | env LANG=C sort
done

echo "[nss:rosubdir]"
cat > entry.$size <<- EOF
key_storage_type=NSSDB
key_storage_location=$tmpdir/rosubdir
key_nickname=keyi$size
key_gen_size=$size
EOF
$toolsdir/keygen entry.$size || true

echo "[nss:rwsubdir]"
cat > entry.$size <<- EOF
key_storage_type=NSSDB
key_storage_location=$tmpdir/rwsubdir
key_nickname=keyi$size
key_gen_size=$size
EOF
$toolsdir/keygen entry.$size || true

for size in 512 1024 1536 2048 3072 4096 ; do
	echo "[openssl:$size]"
	# Generate a key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/sample.$size
	key_gen_size=$size
	EOF
	$toolsdir/keygen entry.$size
	# Read the size.
	sed -i 's,^key_gen_size.*,,g' entry.$size
	$toolsdir/keyiread entry.$size
	# Generate a new key and read it.
	echo key_gen_size=$size >> entry.$size
	$toolsdir/keygen entry.$size
	$toolsdir/keyiread entry.$size
	# One more time.
	$toolsdir/keygen entry.$size
	$toolsdir/keyiread entry.$size
	# Extract the marker.
	marker=`grep ^key_next_marker= entry.$size | cut -f2- -d=`
	# Make sure we're clean.
	find $tmpdir -name "sample.$size"'*' -print | sed s,"${marker:-////////}","(next)",g | env LANG=C sort
done

echo "[openssl:rosubdir]"
cat > entry.$size <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/rosubdir/sample.$size
key_gen_size=$size
EOF
$toolsdir/keygen entry.$size || true

echo "[openssl:rwsubdir]"
cat > entry.$size <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/rwsubdir/sample.$size
key_gen_size=$size
EOF
touch $tmpdir/rwsubdir/sample.$size
chmod u-w $tmpdir/rwsubdir/sample.$size
$toolsdir/keygen entry.$size || true

echo Test complete.
