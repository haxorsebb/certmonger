#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 512 1024 1536 2048 3072 4096 ; do
	# Generate a key.
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	key_gen_size=$size
	EOF
	$toolsdir/keygen entry.$size
	# Read the size.
	sed -i 's,^key_gen_size.*,,g' entry.$size
	$toolsdir/keyiread entry.$size
done

for size in 512 1024 1536 2048 3072 4096 ; do
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
done
echo Test complete.
