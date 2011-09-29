#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 512 1024 1536 2048 3072 4096 ; do
	# Build a self-signed certificate.
	run_certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	# Generate a new CSR for that certificate's key.
	$toolsdir/csrgen entry.$size > csr.nss.$size
	grep ^spkac entry.$size | sed s,spkac,SPKAC, > spkac.nss.$size
	# Export the certificate and key.
	pk12util -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size"
	openssl pkcs12 -in $size.p12 -passin pass: -out key.$size -nodes 2>&1
	# Generate a new CSR using the extracted key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	EOF
	$toolsdir/csrgen entry.$size > csr.openssl.$size
	grep ^spkac entry.$size | sed s,spkac,SPKAC, > spkac.openssl.$size
	# They'd better be the same!
	if cmp csr.nss.$size csr.openssl.$size ; then
		if cmp spkac.nss.$size spkac.openssl.$size ; then
			echo $size OK.
			cat spkac.nss.$size | openssl spkac -verify -noout 2>&1
		else
			echo With basic/default settings, SPKACs differ:
			cat spkac.nss.$size spkac.openssl.$size
			exit 1
		fi
	else
		echo With basic/default settings, these differ:
		cat csr.nss.$size csr.openssl.$size
		exit 1
	fi
done

iteration=1
for size in 1024 ; do
for subject in CN=localhost CN=somehost "CN=Babs Jensen" ; do
for hostname in "" localhost localhost,localhost.localdomain; do
for email in "" root@localhost root@localhost,root@localhost.localdomain; do
for principal in "" root@EXAMPLE.COM root@EXAMPLE.COM,root@FOO.EXAMPLE.COM; do
for ku in "" 1 11 111 ; do
for eku in "" id-kp-clientAuth id-kp-clientAuth,id-kp-emailProtection ; do
for challengepassword in "" ChallengePasswordIsEncodedInPlainText ; do
for certfname in "" CertificateFriendlyName ; do
	${certnickname:+cert_nickname=$cert_nickname}
	# Generate a new CSR using the copy of the key in the NSS database.
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	${certfname:+cert_nickname=$certfname}
	${challengepassword:+challenge_password=$challengepassword}
	${subject:+template_subject=$subject}
	${hostname:+template_hostname=$hostname}
	${email:+template_email=$email}
	${principal:+template_principal=$principal}
	${ku:+template_ku=$ku}
	${eku:+template_eku=$eku}
	EOF
	$toolsdir/csrgen entry.$size > csr.nss.$size
	# Generate a new CSR using the copy of the key that's in a file.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	${certfname:+cert_nickname=$certfname}
	${challengepassword:+challenge_password=$challengepassword}
	${subject:+template_subject=$subject}
	${hostname:+template_hostname=$hostname}
	${email:+template_email=$email}
	${principal:+template_principal=$principal}
	${ku:+template_ku=$ku}
	${eku:+template_eku=$eku}
	EOF
	$toolsdir/csrgen entry.$size > csr.openssl.$size
	# Both should verify.
	if test "`openssl req -verify -key key.$size -in csr.openssl.$size -noout 2>&1`" != "verify OK" ; then
		echo Signature failed for OpenSSL:
		cat csr.openssl.$size
		echo Private key:
		awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/{print}{;}' $tmpdir/key.$size
		exit 1
	fi
	if test "`openssl req -verify -key key.$size -in csr.nss.$size -noout 2>&1`" != "verify OK" ; then
		echo Signature failed for NSS:
		cat csr.nss.$size
		echo Private key:
		awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/{print}{;}' $tmpdir/key.$size
		exit 1
	fi
	# They'd better be the same!
	if ! cmp csr.nss.$size csr.openssl.$size ; then
		echo With these settings:
		tail -n +3 entry.$size | sed 's,^$,,g'
		echo These differ:
		cat csr.nss.$size csr.openssl.$size
		echo Private key:
		awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/{print}{;}' $tmpdir/key.$size
		exit 1
	fi
	iteration=`expr $iteration + 1`
done
done
done
done
done
done
done
done
done
echo "The last CSR (the one with everything) was:"
openssl req -in csr.nss.$size -outform der | openssl asn1parse -inform der
echo Test complete.
