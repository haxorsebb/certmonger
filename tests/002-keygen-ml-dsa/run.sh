#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 44 65 87 ; do
	echo "[openssl:$size]"
	# Generate a key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/sample.$size
	key_gen_size=$size
	key_gen_type=ML-DSA-$size
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
key_gen_type=ML-DSA-$size
EOF
$toolsdir/keygen entry.$size || true

echo "[openssl:rwsubdir]"
cat > entry.$size <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/rwsubdir/sample.$size
key_gen_size=$size
key_gen_type=ML-DSA-$size
EOF
touch $tmpdir/rwsubdir/sample.$size
chmod u-w $tmpdir/rwsubdir/sample.$size
$toolsdir/keygen entry.$size || true

echo Test complete.
