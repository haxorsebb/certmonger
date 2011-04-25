#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb ${scheme:+${scheme}:}$tmpdir

wrongcert='-----BEGIN CERTIFICATE-----
 MIIDQTCCAimgAwIBAgIBBTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdwaWxs
 Ym94MB4XDTExMDMyMzE2NTIyMFoXDTEyMDMyMzE2NTIyMFowEjEQMA4GA1UEAxMH
 cGlsbGJveDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKw+VY4P8khm
 FC8uQPkjN2xHIURUewBZMYC5r/rWMbbSXCVCes63PEBP8uxKriuBLgwY44pZbUO0
 JMezP4+kqSWZPZPKEPTvINJksNbewH51DGvMdGOh0mJhJqK/MjNTainmIWXqiwz7
 9Bhr0Py4SzdMzsmyTfJfL+CKGuS+cydSfhdc/e1XrFwyM31nGjt2Zhk3EupcraTG
 ngoEj8tPuPBjLCKprm89pjdBWtUa2ruCZrPy09uD/5bg/dRja1l1MxRvpGnwVXzy
 CAc7LJh32jwkthwxgvxR0pVp0rnqg+FjHPp/bqgomac/upHcmCDI4zPJSlnqJhgD
 FysndL2TGlECAwEAAaOBoTCBnjB2BgNVHREBAQAEbDBqggdwaWxsYm94oCcGCisG
 AQQBgjcUAgOgGQwXaG9zdC9waWxsYm94QFJFREhBVC5DT02gNgYGKwYBBQICoCww
 KqAMGwpSRURIQVQuQ09NoRowGKADAgEBoREwDxsEaG9zdBsHcGlsbGJveDAWBgNV
 HSUBAQAEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUA
 A4IBAQAK1F0TEZEJL/i+GhcNOQJpbFKK2McOCH6+PH1TRfClPk/y0nH3jS/HZI1s
 ppHAYXOl4UWaPHKPhuHFi6y/Uh11trQ5v5Gm01Y16jvcS8UJVHQphRri6FF0iIL0
 a15w3l3CcJRneDbX2hhi72ZODYzCzxdalF+ysHOyH6+ZYwWz1UR+zrz9qbqVMtLo
 YT4fxzSEEbg7VpvDOkfCBtXyAAPi307yqVoXWtJkdRwYt4fmCih9tn/GHPrRN46F
 G4IHEyvT9+WN2iqQQFpPkq8iyx4+3xyPs+/i6dIuDbZoTZ7aXjuwY+Rlz+xbbDRk
 Szk1zDVf9U0hdr0BC3cDhfbVysgx
 -----END CERTIFICATE-----'
cert='-----BEGIN CERTIFICATE-----
 MIIDBTCCAe2gAwIBAgIBRDANBgkqhkiG9w0BAQsFADAAMB4XDTA5MTExMTE3MDMw
 N1oXDTA5MTIxMTE3MDMwN1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
 ggEBAMeBHVwuakwxp4OsPT+ooghzyr5SsyKylKJ+QP4BnQzxNSmT3O+ubtRqgv/1
 Rekj30Z56QMX3D9cgJfdRCmSTQ6JLpubgX1DZtgyHq4jnUtiYsObzQ83+OXlO/kU
 ItGVJa2308+rAQ6FkpI8S0WwiXgfZIZmbIjghkpfj+XTPtjVsBwKVxr39++Hq0zA
 +1YzKPZEe+mU0C8s7zh0tzEiXVEcOnwLL25QpEVDUVxdHKHBfnVOmsN9ju9BO48b
 +zIIB5qtSSir+jTs9+JqRX00nsPXVonhXMHOxOjc9pMJV3D8wIfXzeW10xNA3YYC
 i66XiZTicfsFV8Z47Mrq0yytCe0CAwEAAaOBiTCBhjB2BgNVHREBAQAEbDBqgRBi
 YWJzQGV4YW1wbGUuY29toCMGCisGAQQBgjcUAgOgFQwTYmplbnNlbkBFWEFNUExF
 LkNPTaAxBgYrBgEFAgKgJzAloA0bC0VYQU1QTEUuQ09NoRQwEqADAgEBoQswCRsH
 YmplbnNlbjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAkHNQIKsgS
 yhowGHe8wtFD8Z+4bdRJ0NruMGltj+69AZTBt3Jo5ZvS+4UWqfRTMqZf16/uQGVJ
 BHVqYQr/LOkhB2j9vew7V4zhYPH23kAJO8P2lYZXX24nB8LlqRObVafPrQyrLVXU
 W481O+AzIFBtNIoi+sbsVm0COp8JGUo5nooBip5+as8ufQqCUu0SxhMpaokri9mB
 5V3fxIA1SquOw/6aIUEir5Mi2kKUCVYm8VP9CrdYu0vVGoBZ2GkNGsD4MZS/+a6v
 Lgdt6ebhXuOUlaTMEYwgsJS4z9EB31oHyOt/YlJjR/fp434JRxPBfXAnXEzI9apG
 /DXE+1dr1yFa
 -----END CERTIFICATE-----'
echo "$cert" | sed -e 's,^$,,g' -e 's,^ ,,g' > cert.original
echo "$wrongcert" | sed -e 's,^$,,g' -e 's,^ ,,g' > cert.wrong
# Save the right certificate to NSS's database with the wrong nickname.
cat > entry.nss << EOF
cert_storage_type=NSSDB
cert_storage_location=${scheme:+${scheme}:}$tmpdir
cert_nickname=wrongnick
cert=$cert
EOF
$toolsdir/certsave entry.nss
# Save the wrong certificate to NSS's database with the right nickname.
cat > entry.nss << EOF
cert_storage_type=NSSDB
cert_storage_location=${scheme:+${scheme}:}$tmpdir
cert_nickname=cert
cert=$wrongcert
EOF
$toolsdir/certsave entry.nss
# Save the right certificate to NSS's database and read it back.
cat > entry.nss << EOF
cert_storage_type=NSSDB
cert_storage_location=${scheme:+${scheme}:}$tmpdir
cert_nickname=cert
cert=$cert
EOF
$toolsdir/certsave entry.nss
$toolsdir/listnicks entry.nss
certutil -d ${scheme:+${scheme}:}$tmpdir -L -n cert -a > cert.nss
# Save the wrong certificate to the PEM file.
cat > entry.openssl << EOF
cert_storage_type=FILE
cert_storage_location=$tmpdir/cert.openssl
cert=$wrongcert
EOF
$toolsdir/certsave entry.nss
# Save the right certificate to the PEM file.
cat > entry.openssl << EOF
cert_storage_type=FILE
cert_storage_location=$tmpdir/cert.openssl
cert=$cert
EOF
$toolsdir/certsave entry.openssl
# Compare the three.
run_dos2unix cert.original
run_dos2unix cert.nss
run_dos2unix cert.openssl
if ! cmp cert.original cert.nss ; then
	echo Original and NSS disagree "(${scheme:+${scheme}:}$tmpdir)".
	cat cert.original cert.nss
	exit 1
fi
if ! cmp cert.original cert.openssl ; then
	echo Original and OpenSSL disagree.
	cat cert.original cert.openssl
	exit 1
fi
if ! cmp cert.nss cert.openssl ; then
	echo NSS and OpenSSL disagree.
	cat cert.nss cert.openssl
	exit 1
fi

echo Test complete.
