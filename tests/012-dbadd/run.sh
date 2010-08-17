#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions

	echo '['Generating key${scheme:+ \($scheme\)}.']'
	rm -fr $tmpdir/${scheme}db
	mkdir -p $tmpdir/${scheme}db
	initnssdb $tmpdir/${scheme}db
	cat > entry.key${scheme:+.$scheme} <<- EOF
	state=NEED_KEY_PAIR
	key_storage_type=NSSDB
	key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	key_nickname=Test
	EOF
	$toolsdir/keygen entry.key${scheme:+.$scheme}
	certutil -K -d ${scheme:+${scheme}:}$tmpdir/${scheme}db 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g'

	echo '['Saving certificate${scheme:+ \($scheme\)}.']'
	rm -fr $tmpdir/${scheme}db
	mkdir -p $tmpdir/${scheme}db
	initnssdb $tmpdir/${scheme}db
	cat > entry.cert${scheme:+.$scheme} <<- EOF
	state=NEED_TO_SAVE_CERT
	cert_storage_type=NSSDB
	cert_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	cert_nickname=Test
	cert=-----BEGIN CERTIFICATE-----
	 MIIC3jCCAcagAwIBAgIBAzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdwaWxs
	 Ym94MB4XDTEwMDIxMDIyMDMzOVoXDTEwMDMxMjIyMDMzOVowEjEQMA4GA1UEAxMH
	 cGlsbGJveDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQOQn5USR/Q
	 Gp2230fks3ZOjkF5VHxwLziS9rc+AFZ8UZrXMidnkhso9Eqp74CaJ+KhJI2F62wm
	 SerBztRAVb8T98+dXUvgYIXE6OxB0ITCMMvdJZFKs5hek2Xd6uiulCegqsNOD1qy
	 llBNLtWDoZqgXuEKfeQmUR6qUGqhVFfmL7qKmIOWN+lSswhkQrrGy3oSNVU5KWYM
	 d7bkrKWEze8ksWgNOwDFQ2pQibYljywEfBZaLegeoASygK3yl6dVjioQmkHBk8Z1
	 fRLnMs8TRT7NwgsWFkKi04SGkn/VpVKZ9piMJCpYhQWIy0U2ib0nBaYec2ReFQ6r
	 2du1UMmkwXECAwEAAaM/MD0wFQYDVR0RAQEABAswCYIHcGlsbGJveDAWBgNVHSUB
	 AQAEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IB
	 AQA9dqnzVzblb0PKdiMOzLksEqFridaRVOB/hK4WHeSJQsCk6a151Fli1uX3/QHJ
	 vRXH0P6i8eMblQ20J4IpZuO9aBLW1go8vPQM8/gD5dXUVm57sqsJlvxjKbnHplGi
	 w8KKasuYMHGOI0M//MR84LI7Nd/JIu+9In9Y+qRj91saBIgHDKeiHQtzWdehNC+2
	 e3gdWc74hx26gXRO6bNE5CZExnVULNkDOsPh/nr4Qwwx+BOn4DdU8tbRvUbvjjzQ
	 koiuvyXyTlj1E8JcT6q4P3YbCn4PTlF8xZK9+XdUzOA6HUlz2Q/ysjIQMHe6zapD
	 8Vw+Zwf78Wg6L4tcAJ6Y4W/Z
	 -----END CERTIFICATE-----
	EOF
	$toolsdir/certsave entry.cert${scheme:+.$scheme}
	echo OK
	certutil -L -d ${scheme:+${scheme}:}$tmpdir/${scheme}db 2>&1 | sed -re 's,[ \t]+, ,g' -e 's,Services ",Services",g'

echo '['Test complete.']'
