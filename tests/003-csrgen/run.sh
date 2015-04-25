#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

for size in 512 1024 1536 2048 3072 4096 ; do
	# Build a self-signed certificate.
	run_certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u
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
	grep ^scep_tx entry.nss.$size | sed s,^scep_tx=,, > sceptx.nss.$size
	if ! test -s sceptx.nss.$size ; then
		echo No SCEP TX ID \(NSS\)
		exit 1
	fi
	grep ^minicert entry.nss.$size | sed s,^minicert=,, > minicert.nss.$size
	if ! test -s minicert.nss.$size ; then
		echo No minicert \(NSS\)
		exit 1
	fi
	# Generate a new CSR using the extracted key.
	$toolsdir/csrgen entry.openssl.$size > csr.openssl.$size
	grep ^spkac entry.openssl.$size | sed s,spkac,SPKAC, > spkac.openssl.$size
	grep ^scep_tx entry.openssl.$size | sed s,^scep_tx=,, > sceptx.openssl.$size
	if ! test -s sceptx.openssl.$size ; then
		echo No SCEP TX ID \(OpenSSL\)
		exit 1
	fi
	grep ^minicert entry.openssl.$size | sed s,^minicert=,, > minicert.openssl.$size
	if ! test -s minicert.openssl.$size ; then
		echo No minicert \(OpenSSL\)
		exit 1
	fi
	# They'd better be the same!
	if cmp csr.nss.$size csr.openssl.$size ; then
		if cmp spkac.nss.$size spkac.openssl.$size ; then
			if cmp sceptx.nss.$size sceptx.openssl.$size ; then
				cat spkac.nss.$size | openssl spkac -verify -noout 2>&1
				if cmp minicert.nss.$size minicert.openssl.$size ; then
					base64 -d < minicert.openssl.$size | openssl x509 -out minicert.openssl.$size.pem -inform der
					openssl verify -CAfile minicert.openssl.$size.pem minicert.openssl.$size.pem
					echo $size OK.
				else
					echo With basic/default settings, minicerts differ \(NSS, OpenSSL\):
					cat minicert.nss.$size minicert.openssl.$size
					exit 1
				fi
			else
				echo With basic/default settings, SCEP TX IDs differ \(NSS, OpenSSL\):
				cat sceptx.nss.$size sceptx.openssl.$size
				exit 1
			fi
		else
			echo With basic/default settings, SPKACs differ \(NSS, OpenSSL\):
			cat spkac.nss.$size spkac.openssl.$size
			exit 1
		fi
	else
		echo With basic/default settings, these differ \(NSS, OpenSSL\):
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
	subjectder=${15}
	ipaddress=${16}
	freshestcrl=${17}
	no_ocsp_check=${18}
	profile=${19}
	ns_certtype=${20}
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
	${subjectder:+template_subject_der=$subjectder}
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
	${ipaddress:+template_ipaddress=$ipaddress}
	${freshestcrl:+template_freshest_crl=$freshestcrl}
	${no_ocsp_check:+template_no_ocsp_check=$no_ocsp_check}
	${profile:+template_profile=$profile}
	${ns_certtype:+template_ns_certtype=$ns_certtype}
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
	${subjectder:+template_subject_der=$subjectder}
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
	${ipaddress:+template_ipaddress=$ipaddress}
	${freshestcrl:+template_freshest_crl=$freshestcrl}
	${no_ocsp_check:+template_no_ocsp_check=$no_ocsp_check}
	${profile:+template_profile=$profile}
	${ns_certtype:+template_ns_certtype=$ns_certtype}
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
		echo These differ \(NSS, OpenSSL\):
		cat csr.nss.$size csr.openssl.$size
		echo Private key:
		awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/{print}{;}' $tmpdir/key.$size
		exit 1
	fi
	iteration=`expr $iteration + 1`
}

iteration=1

for size in 1024 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done

for subject in "" "Babs Jensen" CN=somehost "CN=Babs Jensen" ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
subject=

for subjectder in "" 30223120301E060355040313177361 30223120301E0603550403131773616265722E626F73746F6E2E7265646861742E636F6D ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
subjectder=

for hostname in "" "," localhost,localhost.localdomain; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
hostname=

for email in "" "," root@localhost,root@localhost.localdomain; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
email=

for principal in "" "," root@EXAMPLE.COM,root@FOO.EXAMPLE.COM; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
principal=

for ku in "" 1 10 111 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
ku=

for eku in "" "," id-kp-clientAuth,id-kp-emailProtection ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
eku=

for challengepassword in "" ChallengePasswordIsEncodedInPlainText ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
challengepassword=

for certfname in "" CertificateFriendlyName ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
certfname=

for ca in "" 0 1 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
ca=

for capathlen in -1 3 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
capathlen=

for crldp in "" "," http://crl-1.example.com:12345/get,http://crl-2.example.com:12345/get ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
crldp=

for ocsp in "" "," http://ocsp-1.example.com:12345,http://ocsp-2.example.com:12345 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
ocsp=

for nscomment in "" "certmonger generated this request" ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
nscomment=

for ipaddress in "" "," "127.0.0.1" "::1" "blargh" "this request" "1.2.3.4,fe80::" ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
ipaddress=

for freshestcrl in "" "," http://crl-1.example.com:12345/getdelta,http://crl-2.example.com:12345/getdelta ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
freshestcrl=

for no_ocsp_check in "" 0 1 ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
no_ocsp_check=

for profile in "" caLessThanAwesomeCert caAwesomeCert ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
profile=

for ns_certtype in "" client server email objsign reserved sslca emailca objca client,email ; do
	iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
done
ns_certtype=

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
subjectder=
ipaddress="127.0.0.1,::1"
freshestcrl=http://crl-1.example.com:12345/getdelta,http://crl-2.example.com:12345/getdelta
no_ocsp_check=1
profile=caAwesomeCert
ns_certtype=client,email
iterate "$size" "$subject" "$hostname" "$email" "$principal" "$ku" "$eku" "$challengepassword" "$certfname" "$ca" "$capathlen" "$crldp" "$ocsp" "$nscomment" "$subjectder" "$ipaddress" "$freshestcrl" "$no_ocsp_check" "$profile" "$ns_certtype"
echo "The last CSR (the one with everything) was:"
openssl req -in csr.nss.$size -outform der | openssl asn1parse -inform der | sed 's,2.5.29.46,X509v3 Freshest CRL,g'
cat $tmpdir/key.$size csr.nss.$size 1>&2

echo Test complete "($iteration combinations)".
