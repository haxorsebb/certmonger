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
egrep -v '^(cert_storage_type|cert_storage_location|cert_nickname)' entry.nss >\
entry.nss.clean
egrep -v '^(cert_storage_type|cert_storage_location|cert_nickname)' entry.openssl >\
entry.openssl.clean
# Compare the two cleaned entry files.
if ! cmp entry.nss.clean entry.openssl.clean ; then
	echo Read certificates differently.
	diff -u entry.nss.clean entry.openssl.clean
	exit 1
fi
# Let the caller make sure it looks right.
grep ^cert_ entry.nss.clean | sort
exit 0
