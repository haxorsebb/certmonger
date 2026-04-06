#!/bin/bash -e
#
# ML-DSA key material: create keys in NSS, read with keyiread (NSSDB entry),
# export PKCS#12 to PEM, read with keyiread (FILE entry).  Then assert
# key_pubkey (raw) and key_pubkey_info (SPKI hex) saved on both entries match.
#

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

# Extract a multi-line store-file field: "field=value" then optional
# continuation lines " rest..." (leading space, see store-files.c).
get_store_field() {
	local fld="$1" file="$2"
	awk -v fld="$fld" '
		BEGIN { found = 0 }
		$0 ~ "^" fld "=" {
			found = 1
			v = substr($0, length(fld) + 2)
			while (getline > 0) {
				if ($0 ~ /^ /)
					v = v substr($0, 2)
				else {
					print v
					exit 0
				}
			}
			print v
			exit 0
		}
		END {
			if (!found)
				exit 1
		}
	' "$file"
}

crosscheck_pubfields() {
	local size="$1" nss_entry="$2" ossl_entry="$3" f n o

	for f in key_pubkey key_pubkey_info; do
		n=$(get_store_field "$f" "$nss_entry") || {
			echo "missing $f in $nss_entry" >&2
			return 1
		}
		o=$(get_store_field "$f" "$ossl_entry") || {
			echo "missing $f in $ossl_entry" >&2
			return 1
		}
		if test "$n" != "$o"; then
			echo "crosscheck $size: $f differs between NSS and OpenSSL entry" >&2
			return 1
		fi
		echo "crosscheck $size $f: NSS == OpenSSL (FILE)"
	done
}

for size in ML-DSA-44 ML-DSA-65 ML-DSA-87 ; do
	# Generate a self-signed cert (key in NSS).
	run_certutil -d "$tmpdir" -S -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u -k mldsa -q $size
	cat > entry.nss.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	$toolsdir/keyiread entry.nss.$size
	if ! pk12util -C AES-128-CBC -c AES-128-CBC -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size" > /dev/null 2>&1 ; then
		echo Error exporting key for $size, continuing.
		continue
	fi
	if ! openssl pkcs12 -in $size.p12 -out key.$size -passin pass: -nodes -nocerts > /dev/null 2>&1 ; then
		echo Error parsing exported key for $size, continuing.
		continue
	fi
	cat > entry.openssl.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	key_nickname=keyi$size
	EOF
	$toolsdir/keyiread entry.openssl.$size
	crosscheck_pubfields "$size" "entry.nss.$size" "entry.openssl.$size"
done
echo Test complete.
