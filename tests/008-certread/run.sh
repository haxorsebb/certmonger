#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

cert='-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIBRzANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDEwtCYWJz
IEplbnNlbjAeFw0wOTExMTEyMTQ2NTRaFw0wOTEyMTEyMTQ2NTRaMBYxFDASBgNV
BAMTC0JhYnMgSmVuc2VuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
x4EdXC5qTDGng6w9P6iiCHPKvlKzIrKUon5A/gGdDPE1KZPc765u1GqC//VF6SPf
RnnpAxfcP1yAl91EKZJNDokum5uBfUNm2DIeriOdS2Jiw5vNDzf45eU7+RQi0ZUl
rbfTz6sBDoWSkjxLRbCJeB9khmZsiOCGSl+P5dM+2NWwHApXGvf374erTMD7VjMo
9kR76ZTQLyzvOHS3MSJdURw6fAsvblCkRUNRXF0cocF+dU6aw32O70E7jxv7MggH
mq1JKKv6NOz34mpFfTSew9dWieFcwc7E6Nz2kwlXcPzAh9fN5bXTE0DdhgKLrpeJ
lOJx+wVXxnjsyurTLK0J7QIDAQABo4GJMIGGMHYGA1UdEQEBAARsMGqBEGJhYnNA
ZXhhbXBsZS5jb22gIwYKKwYBBAGCNxQCA6AVDBNiamVuc2VuQEVYQU1QTEUuQ09N
oDEGBisGAQUCAqAnMCWgDRsLRVhBTVBMRS5DT02hFDASoAMCAQGhCzAJGwdiamVu
c2VuMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAKwbX1XJIn78vSqE
/VEnMECQG46z7JPJC0+40fqpF2chC2LwFGWTInbfrq0AVOJ3hFP4b8UY20KhjOYv
5SWQXotbOBUjqAGM69/IG9eNGoMi7yaeGCxq3O+yyyR8Nh2GfraHVeIhywtfyIft
Iy4wMPoh6qoWCSyxokNTTsFhlV/Ka7e8fDqAGKWJvABzV4Qd6MxN9MNrVoYc5UcI
/JzTBBsjXY4BF7xLgB5hAsL7PHAOYlraZkCuIP+8dEaCTdim8b9jVgPHVTp+mxmL
yxLfZh7aPfW0TcCn4tVFugebEL1bFz9Sok0F1j7uYdu5e6f3jw+QUyE24KOGFTtQ
i6k3fDQ=
-----END CERTIFICATE-----'
echo "$cert" | sed -e 's,^$,,g' -e 's,^ ,,g' > cert.original
# Import it into NSS's database and read it back.
certutil -d "$tmpdir" -A -n cert -t u,u,u < cert.original
cat > entry.nss << EOF
id=Test
cert_storage_type=NSSDB
cert_storage_location=$tmpdir
cert_nickname=cert
EOF
$toolsdir/certread entry.nss
# Read it from a PEM file.
cp cert.original cert.openssl
cat > entry.openssl << EOF
id=Test
cert_storage_type=FILE
cert_storage_location=$tmpdir/cert.openssl
EOF
$toolsdir/certread entry.openssl
# Strip out storage keywords.
egrep -v '^(cert_storage_type|cert_storage_location|cert_nickname|cert_token)' entry.nss >\
entry.nss.clean
egrep -v '^(cert_storage_type|cert_storage_location|cert_nickname|cert_token)' entry.openssl >\
entry.openssl.clean
awk '/^cert=.*BEGIN CERTIFICATE/,/END CERTIFICATE/{print}{;}' entry.nss >> entry.nss.clean
awk '/^cert=.*BEGIN CERTIFICATE/,/END CERTIFICATE/{print}{;}' entry.openssl >> entry.openssl.clean
if ! grep -q '^cert=.*BEGIN CERTIFICATE' entry.nss.clean && \
   ! grep -q '^ -----END CERTIFICATE-----' entry.nss.clean ; then
	echo Failed to pull certificate out of NSS.
	exit 1
fi
if ! grep -q '^cert=.*BEGIN CERTIFICATE' entry.openssl.clean && \
   ! grep -q '^ -----END CERTIFICATE-----' entry.openssl.clean ; then
	echo Failed to pull certificate out of OpenSSL.
	exit 1
fi
# Compare the two cleaned entry files.
if ! cmp entry.nss.clean entry.openssl.clean ; then
	echo Read certificates differently.
	diff -u entry.nss.clean entry.openssl.clean
	exit 1
fi
# Let the caller make sure it looks right.
grep ^cert_ entry.nss.clean | sort
grep ^cert_token entry.nss

echo Test complete.
