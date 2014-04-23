#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 512 1024 1536 2048 3072 4096 ; do
	# Build a self-signed certificate.
	run_certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u -k rsa
	# Export the key.
	pk12util -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size"
	openssl pkcs12 -in $size.p12 -out key.$size -passin pass: -nodes -nocerts 2>&1
	# Read the public key and cache it.
	cat > entry.openssl.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	key_nickname=keyi$size
	id=keyi$size
	EOF
	$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
	# Add the cached value to the prepping for the NSS copy.
	cat > entry.nss.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	id=keyi$size
	EOF
	grep ^key_pubkey_info= entry.openssl.$size >> entry.nss.$size
	grep ^key_pubkey= entry.openssl.$size >> entry.nss.$size
	# Generate a new CSR for that certificate's key.
	$toolsdir/csrgen entry.nss.$size > csr.nss.$size
	grep ^spkac entry.nss.$size | sed s,spkac,SPKAC, > spkac.nss.$size
	# Generate a new CSR using the extracted key.
	$toolsdir/csrgen entry.openssl.$size > csr.openssl.$size
	grep ^spkac entry.openssl.$size | sed s,spkac,SPKAC, > spkac.openssl.$size
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

iterate() {
	size=${1}
	subject=${2}
	hostname=${3}
	email=${4}
	principal=${5}
	ku=${6}
	eku=${7}
	challengepassword=${8}
	certfname=${9}
	ca=${10}
	capathlen=${11}
	crldp=${12}
	ocsp=${13}
	nscomment=${14}
	${certnickname:+cert_nickname=$cert_nickname}
	# Generate a new CSR using the copy of the key that's in a file.
	cat > entry.openssl.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	key_nickname=keyi$size
	key_pubkey=616263
	id=keyi$size
	${certfname:+cert_nickname=$certfname}
	${challengepassword:+challenge_password=$challengepassword}
	${subject:+template_subject=$subject}
	${hostname:+template_hostname=$hostname}
	${email:+template_email=$email}
	${principal:+template_principal=$principal}
	${ku:+template_ku=$ku}
	${eku:+template_eku=$eku}
	${ca:+template_is_ca=$ca}
	${capathlen:+template_ca_path_length=$capathlen}
	${crldp:+template_crldp=$crldp}
	${ocsp:+template_ocsp=$ocsp}
	${nscomment:+template_ns_comment=$nscomment}
	EOF
	$toolsdir/keyiread entry.openssl.$size > /dev/null 2>&1
	echo key_pubkey=616263 >> entry.openssl.$size
	$toolsdir/csrgen entry.openssl.$size > csr.openssl.$size
	# Generate a new CSR using the copy of the key in the NSS database.
	cat > entry.nss.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	key_pubkey=616263
	id=keyi$size
	${certfname:+cert_nickname=$certfname}
	${challengepassword:+challenge_password=$challengepassword}
	${subject:+template_subject=$subject}
	${hostname:+template_hostname=$hostname}
	${email:+template_email=$email}
	${principal:+template_principal=$principal}
	${ku:+template_ku=$ku}
	${eku:+template_eku=$eku}
	${ca:+template_is_ca=$ca}
	${capathlen:+template_ca_path_length=$capathlen}
	${crldp:+template_crldp=$crldp}
	${ocsp:+template_ocsp=$ocsp}
	${nscomment:+template_ns_comment=$nscomment}
	EOF
	grep ^key_pubkey_info= entry.openssl.$size >> entry.nss.$size
	echo key_pubkey=616263 >> entry.openssl.$size
	$toolsdir/csrgen entry.nss.$size > csr.nss.$size
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
		tail -n +3 entry.nss.$size | sed 's,^$,,g'
		echo These differ:
		cat csr.nss.$size csr.openssl.$size
		echo Private key:
		awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/{print}{;}' $tmpdir/key.$size
		exit 1
	fi
	iteration=`expr $iteration + 1`
}

iteration=1

for size in 1024 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done

for subject in CN=somehost "CN=Babs Jensen" ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
subject=

for hostname in "" localhost,localhost.localdomain; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
hostname=

for email in "" root@localhost,root@localhost.localdomain; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
email=

for principal in "" root@EXAMPLE.COM,root@FOO.EXAMPLE.COM; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
principal=

for ku in "" 1 10 111 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
ku=

for eku in "" id-kp-clientAuth,id-kp-emailProtection ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
eku=

for challengepassword in "" ChallengePasswordIsEncodedInPlainText ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
challengepassword=

for certfname in "" CertificateFriendlyName ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
certfname=

for ca in "" 0 1 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
ca=

for capathlen in -1 3 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
capathlen=

for crldp in "" http://crl-1.example.com:12345/get,http://crl-2.example.com:12345/get ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
crldp=

for ocsp in "" http://ocsp-1.example.com:12345,http://ocsp-2.example.com:12345 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
ocsp=

for nscomment in "" "certmonger generated this request" ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
done
nscomment=

size=512
subject="CN=Babs Jensen"
hostname=localhost,localhost.localdomain
email=root@localhost,root@localhost.localdomain
principal=root@EXAMPLE.COM,root@FOO.EXAMPLE.COM
ku=111
eku=id-kp-clientAuth,id-kp-emailProtection
challengepassword=ChallengePasswordIsEncodedInPlainText
certfname=CertificateFriendlyName
ca=1
capathlen=3
crldp=http://crl-1.example.com:12345/get,http://crl-2.example.com:12345/get
ocsp=http://ocsp-1.example.com:12345,http://ocsp-2.example.com:12345
nscomment="certmonger generated this request"
iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment"
echo "The last CSR (the one with everything) was:"
openssl req -in csr.nss.$size -outform der | openssl asn1parse -inform der
echo Test complete "($iteration combinations)".
