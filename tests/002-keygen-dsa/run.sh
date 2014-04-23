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
	key_gen_type=DSA
	EOF
	$toolsdir/keygen entry.$size
	# Read the type and size.
	sed -i 's,^key_gen_size.*,,g' entry.$size
	$toolsdir/keyiread entry.$size
done

echo "[nss:rosubdir]"
cat > entry.$size <<- EOF
key_storage_type=NSSDB
key_storage_location=$tmpdir/rosubdir
key_nickname=keyi$size
key_gen_size=$size
key_gen_type=DSA
EOF
$toolsdir/keygen entry.$size || true

echo "[nss:rwsubdir]"
cat > entry.$size <<- EOF
key_storage_type=NSSDB
key_storage_location=$tmpdir/rwsubdir
key_nickname=keyi$size
key_gen_size=$size
key_gen_type=DSA
EOF
$toolsdir/keygen entry.$size || true

for size in 512 1024 1536 2048 3072 4096 ; do
	echo "[openssl:$size]"
	# Generate a key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/sample.$size
	key_gen_size=$size
	key_gen_type=DSA
	EOF
	$toolsdir/keygen entry.$size
	# Read the size.
	sed -i 's,^key_gen_size.*,,g' entry.$size
	$toolsdir/keyiread entry.$size
done

echo "[openssl:rosubdir]"
cat > entry.$size <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/rosubdir/sample.$size
key_gen_size=$size
key_gen_type=DSA
EOF
$toolsdir/keygen entry.$size || true

echo "[openssl:rwsubdir]"
cat > entry.$size <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/rwsubdir/sample.$size
key_gen_size=$size
key_gen_type=DSA
EOF
touch $tmpdir/rwsubdir/sample.$size
chmod u-w $tmpdir/rwsubdir/sample.$size
$toolsdir/keygen entry.$size || true

echo Test complete.
