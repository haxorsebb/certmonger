#!/bin/bash -e
digest=sha1
keytype=rsa:1024
serial=12345678
cat > openssl.cnf << EOF
[req]
x509_extensions = x509
distinguished_name = name
prompt = no
[name]
CN = Test Top-Level CA
[x509]
basicConstraints = CA:true
keyUsage = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
openssl req -new -newkey $keytype -keyout ca0.key -nodes -config openssl.cnf -x509 -set_serial $serial -out ca0.crt

i=0
: > ca.txt
echo $((serial+1)) > ca.srl
while test $i -lt ${1:-8} ; do
	i=$((i+1))
	cat > openssl.cnf <<- EOF
	[req]
	distinguished_name = distinguished_name
	prompt = no
	[ca]
	default_ca = default_ca
	distinguished_name = distinguished_name
	[default_ca]
	private_key = `pwd`/ca$((i-1)).key
	certificate = `pwd`/ca$((i-1)).crt
	database = `pwd`/ca.txt
	serial = `pwd`/ca.srl
	new_certs_dir = `pwd`
	distinguished_name = distinguished_name
	default_md = $digest
	prompt = no
	policy = policy
	default_days = 365
	x509_extensions = x509_extensions
	[distinguished_name]
	CN = Test Level $i CA
	[policy]
	CN = supplied
	[x509_extensions]
	basicConstraints = CA:true
	keyUsage = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyCertSign,cRLSign
	subjectKeyIdentifier=hash
	EOF
	if test $((i%2)) == 0 ; then
		echo authorityKeyIdentifier=keyid,issuer >> openssl.cnf
	fi
	openssl req -new -newkey $keytype -keyout ca$i.key -nodes -config openssl.cnf -out ca$i.req
	openssl ca -batch -config openssl.cnf -key ca$((i-1)).key -cert ca$((i-1)).crt -in ca$i.req -out ca$i.crt -notext
done
cat > openssl.cnf <<- EOF
[req]
distinguished_name = distinguished_name
prompt = no
[ca]
default_ca = default_ca
distinguished_name = distinguished_name
[default_ca]
private_key = `pwd`/ca$i.key
certificate = `pwd`/ca$i.crt
database = `pwd`/ca.txt
serial = `pwd`/ca.srl
new_certs_dir = `pwd`
distinguished_name = distinguished_name
default_md = $digest
prompt = no
policy = policy
default_days = 365
x509_extensions = x509_extensions
[distinguished_name]
CN = Test EE Cert
[policy]
CN = supplied
[x509_extensions]
basicConstraints = CA:false
keyUsage = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
subjectKeyIdentifier=hash
EOF
if test $((i%2)) == 0 ; then
	echo authorityKeyIdentifier=keyid,issuer >> openssl.cnf
fi
openssl req -new -newkey $keytype -keyout ee.key -nodes -config openssl.cnf -out ee.req
openssl ca -batch -config openssl.cnf -key ca$i.key -cert ca$i.crt -in ee.req -out ee.crt -notext
