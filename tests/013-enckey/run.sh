#!/bin/bash -e

cd "$tmpdir"

source "$srcdir"/functions

size=2048

echo BlahBlah > pin.txt

cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
key_pin=BlahBlah
EOF

cat > keyfile <<- EOF
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6D3E363E83BA9625DBD7F9A72916A6C5

rwAsW2aMYZBbnPMK9ceei/xVq4OP7ecYKUcVYED6Vt+Z1j2mD2RJM1/WRtfhzkFB
vVKzalWgsnqB8VzUbTe38s9HP5ldGbv9IYFW4KDIMDP603Cce3IrAhgSwUqoE+6I
5NwdzsqH/m8tCT9ZJk20nY/9G/2/OdAuu3C+DQziWVyhs44L5K3hlU4j1ox0/NaU
cHTUORWB1yPLY2dEeeJoB/MgKN+RYQVaAXOfofDZOMsHlu71ZfWJIpEdHrSi1C1Q
pKZK4sVXpwbT20WVAj710IyVu6i4ybCfNKsPCfpicvqpwqzAs+hap03D0BoTsZ0u
GZ6mh8w6QLsqReXVsHK4KksJnpprBTCbtiA4KfmZ4LAoKjKBH//8UJhZHeuB3xao
NACmweBANowsCdbVOFQV2vTg48zWHFnV92t9GLgAx6QeX161GCSXMK5JX854K0nq
/9hb4/XtGoGRD1BrR5S3oVK6cKLsEffQ3wq4GfE5g3e4LhOpA6QFLMxU6Tj6lOHO
mr6KrlAuyMzeCZImx786CtP87ECD+zHFzpx88EBAVIVr/zWUC0Z03cZXklFKLRfQ
YnOahBXxrxjFSPfnQVFkATVqPb3cC87zUEahxYcRycHHed4Q7nlkcKcu/6d2+6O0
XGlcAuqtn9SurObxtn7KPQbZWi99SUguFpD51Orc0AWirWIGom41VBJ1FXHUiSb8
l8A5e9oHNwyweVOIvB0bUu8I2IgTGA5u8ObYhsEX48r6uH7qHWNjGoYm2gG461ec
wYn+x8H/Jum+M3uLKH2ARrECHyOZAlvHWll1YT2XIfD2nTSjkXvirg9InzXhoncZ
W2HU9u+N8Wl9S2dK5sDk+wIZjK2NrNr2kTgnIL3pLPK2QD0+SaDfG0FOt5dimHPd
0Qrj1iLjaEf11O3k5FRYctviPy/7Bxp4gfiNrdSZcvGsf4a1izjYsgR6x/1VDWhW
A2d84q8rA0ac5KH3pQvucziJQbWAkJ2OGdcb3ciyxjUD97kN9X0ymXbDLiXrhy7x
JYit5EUqvLHTpwen+/oFD/Vfc25qiAqjsa9Gqh6RxkiRGjV9ifNo83MvuhgdScFB
XMtEL0ugTBII0V5xfg9OQYE7lwlK0WV59osGI3hlEDcPkqpfV030Yy8Ac0xfnNlL
mWNzFL30/lbp7ujqRsazgT2w1IHZs/KiJ7USMtyKQvZvFiJIu5up1Mk7RMktNkb1
w18yPa98a5E2zVHtgOcwDu1+527UDLt9kw8EMrYw7Z2SZFuWmCIoYHfRZfv4VKEq
71JcF9MphytcpXJalLMVLm9qP2Fb60sSV1qOG1xiS0OhFGTPqFr9Gqj8jvpwTA62
u7DomMcgjaIqHQBexermp8MHhSBFkuPRHN8PqW2JnrnZ2yBBCzt8ggWXEIPvTRhy
9SUjHVen/LBk4ux2tfT2BwXWZTBRyjqmJDcEPFq9OA/InYFbEoZ4jaqqbE3S18pZ
0IQvbS6KT95b9zZhyUSW1ihOoVtBHlYSSFVkycXSiMVFJktEOMNdqsBm+zKwCq21
nV7TSp7bQHQ62mo4zyc5xRk0r/AJTGPY/NPmACewKuxth0zU+rLachA8EsmHel/4
-----END RSA PRIVATE KEY-----
EOF

echo '['Read Key Info With PIN.']'
$toolsdir/keyiread entry

cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
key_pin_file=$tmpdir/pin.txt
EOF

echo '['Read Key Info With PIN File.']'
$toolsdir/keyiread entry

cat > entry <<- EOF
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
key_pin_file=$tmpdir/pin.txt
key_gen_size=2048
EOF
rm $tmpdir/keyfile

echo '['Generate Key With PIN.']'
$toolsdir/keygen entry
egrep '(: |PRIVATE)' $tmpdir/keyfile

echo '['Generate CSR With PIN.']'
rm -f csr.pem
$toolsdir/csrgen entry > csr.pem
egrep '(: |REQUEST)' $tmpdir/csr.pem

for precreate in false true ; do

	rm -fr $tmpdir/${scheme}db
	mkdir -p $tmpdir/${scheme}db
	if $precreate ; then
		echo '['Creating database.']'
		initnssdb "${scheme:+${scheme}:}$tmpdir/${scheme}db" BlahBlah
	else
		echo '['Not Pre-creating database.']'
	fi

	cat > entry <<- EOF
	key_storage_type=NSSDB
	key_storage_location=${scheme:+${scheme}:}$tmpdir/${scheme}db
	key_nickname=Test
	key_pin_file=$tmpdir/pin.txt
	EOF

	echo '['Generating key${scheme:+ \($scheme\)} with PIN.']'
	$toolsdir/keygen entry
	certutil -K -f $tmpdir/pin.txt -d ${scheme:+${scheme}:}$tmpdir/${scheme}db 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g'

	echo '['Reading Key Info With PIN.']'
	$toolsdir/keyiread entry
	certutil -K -f $tmpdir/pin.txt -d ${scheme:+${scheme}:}$tmpdir/${scheme}db 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g'

	echo '['Generating CSR With PIN.']'
	rm -f csr.pem
	$toolsdir/csrgen entry > csr.pem
	egrep '(: |REQUEST)' $tmpdir/csr.pem
	certutil -K -f $tmpdir/pin.txt -d ${scheme:+${scheme}:}$tmpdir/${scheme}db 2>&1 | sed -re 's,rsa .* Test,rsa PRIVATE-KEY Test,g' -e 's,[ \t]+, ,g' -e 's,Services ",Services",g'

done

echo '['Test complete.']'
