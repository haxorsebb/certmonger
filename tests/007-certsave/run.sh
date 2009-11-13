#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

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
# Save it to NSS's database and read it back.
cat > entry.nss << EOF
cert_storage_type=NSSDB
cert_storage_location=$tmpdir
cert_nickname=cert
cert=$cert
EOF
$toolsdir/certsave entry.nss
certutil -d "$tmpdir" -L -n cert -a > cert.nss
# Save it to a PEM file.
cat > entry.openssl << EOF
cert_storage_type=FILE
cert_storage_location=$tmpdir/cert.openssl
cert=$cert
EOF
$toolsdir/certsave entry.openssl
# Compare the three.
dos2unix cert.original 2>&1
dos2unix cert.nss 2>&1
dos2unix cert.openssl 2>&1
if ! cmp cert.original cert.nss ; then
	echo Original and NSS disagree.
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
