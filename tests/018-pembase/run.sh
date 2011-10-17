#!/bin/sh -e

cd "$tmpdir"

cat > 1.pem << EOF
-----BEGIN CERTIFICATE-----
MIICaDCCAdGgAwIBAgIQCgEBAQAAAnwAAAADAAAAAjANBgkqhkiG9w0BAQUFADBA
MSEwHwYDVQQKExhYY2VydCBJbnRlcm5hdGlvbmFsIEluYy4xGzAZBgNVBAsTElhj
ZXJ0IFJvb3QgQ0EgMTAyNDAeFw0wMDA4MTgxODMxMzJaFw0yNTA4MTUxOTAwNTZa
MEAxITAfBgNVBAoTGFhjZXJ0IEludGVybmF0aW9uYWwgSW5jLjEbMBkGA1UECxMS
WGNlcnQgUm9vdCBDQSAxMDI0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDW
vjeJEami90csKs9qACZlKESkiuTeoENVmURrvG64x87GY7bT6G/FmCskkbieorpx
SN40ICF61tLFiTKlicbchYRU8p5I7cxEtgb/jsTOWa2fbOkiWME/FApDgIcZUlDj
KAfIrBjisRqqo+Jgt3ZRByk5XkjpZnCBLjiavRl96wIDAQABo2MwYTAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBSEecdPB1mxa8E6
Nbq49NWZJ8i6DjAdBgNVHQ4EFgQUhHnHTwdZsWvBOjW6uPTVmSfIug4wDQYJKoZI
hvcNAQEFBQADgYEAc7DhAO2uaNJgA0br+RzxpaZ8XDJ87AJh0xwdczEsuo69SU3I
3dl3dUHnkiGabCnbp2xwhqBcw+TzMswBhFnXiDk486ji4hqwl80rF9xkBA+qanOU
1usIxoBpTd561cU38ZIXPG3TiiHMZBCq3mKHH4+4+Kp1SvQILPXcZs/DOH4=
-----END CERTIFICATE-----
EOF
cat > 1.b << EOF
MIICaDCCAdGgAwIBAgIQCgEBAQAAAnwAAAADAAAAAjANBgkqhkiG9w0BAQUFADBAMSEwHwYDVQQKExhYY2VydCBJbnRlcm5hdGlvbmFsIEluYy4xGzAZBgNVBAsTElhjZXJ0IFJvb3QgQ0EgMTAyNDAeFw0wMDA4MTgxODMxMzJaFw0yNTA4MTUxOTAwNTZaMEAxITAfBgNVBAoTGFhjZXJ0IEludGVybmF0aW9uYWwgSW5jLjEbMBkGA1UECxMSWGNlcnQgUm9vdCBDQSAxMDI0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWvjeJEami90csKs9qACZlKESkiuTeoENVmURrvG64x87GY7bT6G/FmCskkbieorpxSN40ICF61tLFiTKlicbchYRU8p5I7cxEtgb/jsTOWa2fbOkiWME/FApDgIcZUlDjKAfIrBjisRqqo+Jgt3ZRByk5XkjpZnCBLjiavRl96wIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBSEecdPB1mxa8E6Nbq49NWZJ8i6DjAdBgNVHQ4EFgQUhHnHTwdZsWvBOjW6uPTVmSfIug4wDQYJKoZIhvcNAQEFBQADgYEAc7DhAO2uaNJgA0br+RzxpaZ8XDJ87AJh0xwdczEsuo69SU3I3dl3dUHnkiGabCnbp2xwhqBcw+TzMswBhFnXiDk486ji4hqwl80rF9xkBA+qanOU1usIxoBpTd561cU38ZIXPG3TiiHMZBCq3mKHH4+4+Kp1SvQILPXcZs/DOH4=
EOF

echo '['Tests begin.']'
$toolsdir/pem2base < 1.pem > 2.b
$toolsdir/base2pem < 1.b > 2.pem
$toolsdir/pem2base < 2.pem > 3.b
$toolsdir/base2pem < 2.b > 3.pem
$toolsdir/pem2base < 3.pem > 4.b
$toolsdir/pem2base < 4.b > 5.b
unix2dos 1.pem > /dev/null 2> /dev/null
unix2dos 2.pem > /dev/null 2> /dev/null
unix2dos 3.pem > /dev/null 2> /dev/null
unix2dos 1.b > /dev/null 2> /dev/null
unix2dos 2.b > /dev/null 2> /dev/null
unix2dos 3.b > /dev/null 2> /dev/null
unix2dos 4.b > /dev/null 2> /dev/null
unix2dos 5.b > /dev/null 2> /dev/null
$toolsdir/base2pem -u < 4.b > 6.pem
cp 6.pem 6a.pem
unix2dos 6a.pem
$toolsdir/base2pem -d < 4.b > 7.pem
cp 7.pem 7a.pem
dos2unix 7.pem
diff -u 1.pem 2.pem
diff -u 1.pem 3.pem
diff -u 1.b 2.b
diff -u 1.b 3.b
diff -u 1.b 4.b
diff -u 1.b 5.b
diff -u  6.pem  7.pem
diff -u 6a.pem 7a.pem
echo '['Test complete.']'
