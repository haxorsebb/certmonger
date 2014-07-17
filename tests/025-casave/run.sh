#!/bin/bash -e

cd $tmpdir

cat > $tmpdir/entrycb1 <<- EOF
id=EntryCB1
ca_name=CAB1
EOF
cat > $tmpdir/entrycb2 <<- EOF
id=EntryCB2
ca_name=CAB2
EOF
cat > $tmpdir/entrycb3 <<- EOF
id=EntryCB3
ca_name=CAB3
EOF
cat > $tmpdir/entrycd1 <<- EOF
id=EntryCD1
ca_name=CAD1
EOF
cat > $tmpdir/entrycd2 <<- EOF
id=EntryCD2
ca_name=CAD2
EOF
cat > $tmpdir/entrycd3 <<- EOF
id=EntryCD3
ca_name=CAD3
EOF
cat > $tmpdir/entryb1 <<- EOF
id=EntryB1
root_cert_files=$tmpdir/bundle1,$tmpdir/bundle-all
other_root_cert_files=
other_cert_files=
root_cert_dbs=
other_root_cert_dbs=
other_cert_dbs=
EOF
cat > $tmpdir/entryb2 <<- EOF
id=EntryB2
root_cert_files=
other_root_cert_files=$tmpdir/bundle2,$tmpdir/bundle-all
other_cert_files=
root_cert_dbs=
other_root_cert_dbs=
other_cert_dbs=
EOF
cat > $tmpdir/entryb3 <<- EOF
id=EntryB3
root_cert_files=
other_root_cert_files=
other_cert_files=$tmpdir/bundle3,$tmpdir/bundle-all
root_cert_dbs=
other_root_cert_dbs=
other_cert_dbs=
EOF
cat > $tmpdir/entryd1 <<- EOF
id=EntryD1
root_cert_files=
other_root_cert_files=
other_cert_files=
root_cert_dbs=$tmpdir/db1,$tmpdir/dba
other_root_cert_dbs=
other_cert_dbs=
EOF
cat > $tmpdir/entryd2 <<- EOF
id=EntryD2
root_cert_files=
other_root_cert_files=
other_cert_files=
root_cert_dbs=
other_root_cert_dbs=$tmpdir/db2,$tmpdir/dba
other_cert_dbs=
EOF
cat > $tmpdir/entryd3 <<- EOF
id=EntryD3
root_cert_files=
other_root_cert_files=
other_cert_files=
root_cert_dbs=
other_root_cert_dbs=
other_cert_dbs=$tmpdir/db3,$tmpdir/dba
EOF
cat > $tmpdir/entrycab1 <<- EOF
id=EntryCAB1
ca_name=CAB1
root_cert_files=$tmpdir/bundle1,$tmpdir/bundle-all
other_root_cert_files=
other_cert_files=
root_cert_dbs=
other_root_cert_dbs=
other_cert_dbs=
EOF
cat > $tmpdir/entrycab2 <<- EOF
id=EntryCAB2
ca_name=CAB2
root_cert_files=
other_root_cert_files=$tmpdir/bundle2,$tmpdir/bundle-all
other_cert_files=
root_cert_dbs=
other_root_cert_dbs=
other_cert_dbs=
EOF
cat > $tmpdir/entrycab3 <<- EOF
id=EntryCAB3
ca_name=CAB3
root_cert_files=
other_root_cert_files=
other_cert_files=$tmpdir/bundle3,$tmpdir/bundle-all
root_cert_dbs=
other_root_cert_dbs=
other_cert_dbs=
EOF
cat > $tmpdir/entrycad1 <<- EOF
id=EntryCAD1
ca_name=CAD1
root_cert_files=
other_root_cert_files=
other_cert_files=
root_cert_dbs=$tmpdir/db1,$tmpdir/dba
other_root_cert_dbs=
other_cert_dbs=
EOF
cat > $tmpdir/entrycad2 <<- EOF
id=EntryCAD2
ca_name=CAD2
root_cert_files=
other_root_cert_files=
other_cert_files=
root_cert_dbs=
other_root_cert_dbs=$tmpdir/db2,$tmpdir/dba
other_cert_dbs=
EOF
cat > $tmpdir/entrycad3 <<- EOF
id=EntryCAD3
ca_name=CAD3
root_cert_files=
other_root_cert_files=
other_cert_files=
root_cert_dbs=
other_root_cert_dbs=
other_cert_dbs=$tmpdir/db3,$tmpdir/dba
EOF

cat > $tmpdir/cab1 <<- EOF
id=CAB1
ca_type=EXTERNAL
ca_external_helper=$tmpdir/no-such-helper.sh
ca_root_cert_files=$tmpdir/bundle1,$tmpdir/bundle-all
ca_other_root_cert_files=
ca_other_cert_files=
ca_root_cert_dbs=
ca_other_root_cert_dbs=
ca_other_cert_dbs=
ca_root_certs=Root Certificate B1
 -----BEGIN CERTIFICATE-----
 MIIDzzCCAregAwIBAgIDAWweMA0GCSqGSIb3DQEBBQUAMIGNMQswCQYDVQQGEwJB
 VDFIMEYGA1UECgw/QS1UcnVzdCBHZXMuIGYuIFNpY2hlcmhlaXRzc3lzdGVtZSBp
 bSBlbGVrdHIuIERhdGVudmVya2VociBHbWJIMRkwFwYDVQQLDBBBLVRydXN0LW5R
 dWFsLTAzMRkwFwYDVQQDDBBBLVRydXN0LW5RdWFsLTAzMB4XDTA1MDgxNzIyMDAw
 MFoXDTE1MDgxNzIyMDAwMFowgY0xCzAJBgNVBAYTAkFUMUgwRgYDVQQKDD9BLVRy
 dXN0IEdlcy4gZi4gU2ljaGVyaGVpdHNzeXN0ZW1lIGltIGVsZWt0ci4gRGF0ZW52
 ZXJrZWhyIEdtYkgxGTAXBgNVBAsMEEEtVHJ1c3QtblF1YWwtMDMxGTAXBgNVBAMM
 EEEtVHJ1c3QtblF1YWwtMDMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
 AQCtPWFuA/OQO8BBC4SAzewqo51ru27CQoT3URThoKgtUaNR8t4j8DRE/5TrzAUj
 lUC5B3ilJfYKvUWG6Nm9wASOhURh73+nyfrBJcyFLGM/BWBzSQXgYHiVEEvc+RFZ
 znF/QJuKqiTfC0Li21a8StKlDJu3Qz7dg9MmEALP6iPESU7l0+m0iKsMrmKS1GWH
 2WrX9IWf5DMiJaXlyDO6w8dB3F/GaswADm0yqLaHNgBid5seHzTLkDx4iHQF63n1
 k3Flyp3HaxgtPVxO59X4PzF9j4fsCiIvI+n+u33J4PTs63zEsMMtYrWacdaxaujs
 2e3Vcuy+VwHOBVWf3tFgiBCzAgMBAAGjNjA0MA8GA1UdEwEB/wQFMAMBAf8wEQYD
 VR0OBAoECERqlWdVeRFPMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOC
 AQEAVdRU0VlIXLOThaq/Yy/kgM40ozRiPvbY7meIMQQDbwvUB/tOdQ/TLtPAF8fG
 KOwGDREkDg6lXb+MshOWcdzUzg4NCmgybLlBMRmrsQd7TZjTXLDR8KdCoLXEjq/+
 8T/0709GAHbrAvv5ndJAlseIOrifEXnzgGWovR/TeIGgUUw3tKZdJXDRZslo+S4R
 FGjxVJgIrCaSD96JntT6s3kr0qN51OyLrIdTaEJMUVF0HhsnLuP1Hyl0Te2v9+GS
 mYHovjrHF1D2t8b8m7CKa9aIA5GPBnc6hQLdmNVDeD/GMBWsm2vLV7eJUYs66MmE
 DNuxUCAKGkq6ahq97BvIxYSazQ==
 -----END CERTIFICATE-----
ca_other_root_certs=Other Root Certificate B1
 IN CERTIFICATE-----
 MIIEFTCCAv2gAwIBAgIBATANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJTRTEU
 MBIGA1UEChMLQWRkVHJ1c3QgQUIxHTAbBgNVBAsTFEFkZFRydXN0IFRUUCBOZXR3
 b3JrMSAwHgYDVQQDExdBZGRUcnVzdCBQdWJsaWMgQ0EgUm9vdDAeFw0wMDA1MzAx
 MDQxNTBaFw0yMDA1MzAxMDQxNTBaMGQxCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtB
 ZGRUcnVzdCBBQjEdMBsGA1UECxMUQWRkVHJ1c3QgVFRQIE5ldHdvcmsxIDAeBgNV
 BAMTF0FkZFRydXN0IFB1YmxpYyBDQSBSb290MIIBIjANBgkqhkiG9w0BAQEFAAOC
 AQ8AMIIBCgKCAQEA6Rowj4OIFMEg2Dybjxt+A3S72mnTRqX4jsIMEZBRpS9mVEBV
 6tsfSlbunyNu9DnLoblv8n75XYcmYZ4c+OLspoH4IcUkzBEMP9smcnrHAZcHF/nX
 GCwwfQ56HmIexkvA/X1id9NEHif2P0tEs7c42TkfYNVRknMDtABp4/MUTu7R3AnP
 dzRGULD4EfL+OHn3Bzn+UZKXC1sIXzSGAa2Il+tmzV7R/9x98oTaunet3IAIx6eH
 1lWfl2royBFkuucZKT8Rs3iQhCBSWxHveNCD9tVIkNAwHM+A+WD+eeSI8t0A65RF
 62WUaUC6wNW0uLp9BBGo6zEFlpROWCGOn9Bg/QIDAQABo4HRMIHOMB0GA1UdDgQW
 BBSBPjfYkrAfd59ctKtzquf2NGAv+jALBgNVHQ8EBAMCAQYwDwYDVR0TAQH/BAUw
 AwEB/zCBjgYDVR0jBIGGMIGDgBSBPjfYkrAfd59ctKtzquf2NGAv+qFopGYwZDEL
 MAkGA1UEBhMCU0UxFDASBgNVBAoTC0FkZFRydXN0IEFCMR0wGwYDVQQLExRBZGRU
 cnVzdCBUVFAgTmV0d29yazEgMB4GA1UEAxMXQWRkVHJ1c3QgUHVibGljIENBIFJv
 b3SCAQEwDQYJKoZIhvcNAQEFBQADggEBAAP3FUr4JNojVhaTdt02KLmuG7jD8WS6
 IBh4lSknVwW8fCr0uVFV2ocC3g8WFzH4qnkuCRO7r7IgGRLlk/lL+YPoRNWyQSW/
 iHVv/xD8SlTQX/D67zZzfRs2RcYhbbQVuE7PnFylPVoAjgbjPGsye/Kf8Lb93/Ao
 GEjwxrzQvzSAlsJKsW2Ox5BF3i9nrEUEo3rcVZLJR2bYGozH7ZxOmuASu7VqTITh
 4SINhwBk/ox9Yjllpu9CtoAlEmEBqCQTcAARJl/6NVDFSMwGR+gn2HCNX2TmoUQm
 XiLsks3/QppEIW1cxeMiHV9HEufOX1362KqxMy3ZdvJOOjMMK7MtkAY=
 -----END CERTIFICATE-----
ca_other_certs=Other Certificate B1
 -----BEGIN CERTIFICATE-----
 MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJTRTEU
 MBIGA1UEChMLQWRkVHJ1c3QgQUIxHTAbBgNVBAsTFEFkZFRydXN0IFRUUCBOZXR3
 b3JrMSMwIQYDVQQDExpBZGRUcnVzdCBRdWFsaWZpZWQgQ0EgUm9vdDAeFw0wMDA1
 MzAxMDQ0NTBaFw0yMDA1MzAxMDQ0NTBaMGcxCzAJBgNVBAYTAlNFMRQwEgYDVQQK
 EwtBZGRUcnVzdCBBQjEdMBsGA1UECxMUQWRkVHJ1c3QgVFRQIE5ldHdvcmsxIzAh
 BgNVBAMTGkFkZFRydXN0IFF1YWxpZmllZCBDQSBSb290MIIBIjANBgkqhkiG9w0B
 AQEFAAOCAQ8AMIIBCgKCAQEA5B6a/twJWoekn0e+EV+vhDTbYjx5eLfpMLXsDBwq
 xBb/4Oxx64r1EW7tTw2R0hIYLUkVAcKkIhPHEWT/IhKauY5cLwjPcWqzZwFZ8V1G
 87B4pfYOQnrjfxvM0PC3KP0q6p6zsLkEqv32x7SxuCqg+1jxGaBvcCV+PmlKfw8i
 2O+tCBGaKZnhqkRFmhJePp1tUvznoD1oL/BLcHwTOK28FSXx1s6rosAx1i+f4P8U
 WfyEk9mHfExUE+uf0S0R+Bg6Ot4l2ffTQO2kBhLEO+GRwVY18BTcZTYJbqukB8c1
 0cIDMzZbdSZtQvESa0NvS3GU+jQd7RNuyoB/mC9suWXY6QIDAQABo4HUMIHRMB0G
 A1UdDgQWBBQ5lYtii1zJ1IC6WA+XPxUIQ8yYpzALBgNVHQ8EBAMCAQYwDwYDVR0T
 AQH/BAUwAwEB/zCBkQYDVR0jBIGJMIGGgBQ5lYtii1zJ1IC6WA+XPxUIQ8yYp6Fr
 pGkwZzELMAkGA1UEBhMCU0UxFDASBgNVBAoTC0FkZFRydXN0IEFCMR0wGwYDVQQL
 ExRBZGRUcnVzdCBUVFAgTmV0d29yazEjMCEGA1UEAxMaQWRkVHJ1c3QgUXVhbGlm
 aWVkIENBIFJvb3SCAQEwDQYJKoZIhvcNAQEFBQADggEBABmrder4i2VhlRO6aQTv
 hsoToMeqT2QbPxj2qC0sVY8FtzDqQmodwCVRLae/DLPt7wh/bDxGGuoYQ992zPlm
 hpwsaPXpF/gxsxjE1kh9I0xowX67ARRvxdlu3rsEQmr49lx95dr6h+sNNVJn0J6X
 dgWTP5XHAeZpVTh/EGGZyeNfpso+gmNIquIISD6q8rKFYqa0p9m9N5xotS1WfbC3
 P6CxB9bpT9zeRXEwMn8bLgn5v1Kh7sKAPgZcLlVAwRv1cEWw3F369nJad9Jjzc9Y
 iQBCYz95OdBEsIJuQRno3eDBiFrRHnGTHyQwdOUeqN48Jzd/g66ed8/wMLH/S5no
 xqE=
 -----END CERTIFICATE-----
EOF
cat > $tmpdir/cab2 <<- EOF
id=CAB2
ca_type=EXTERNAL
ca_external_helper=$tmpdir/no-such-helper.sh
ca_root_cert_files=
ca_other_root_cert_files=$tmpdir/bundle2,$tmpdir/bundle-all
ca_other_cert_files=
ca_root_cert_dbs=
ca_other_root_cert_dbs=
ca_other_cert_dbs=
ca_root_certs=Root Certificate B2
 -----BEGIN CERTIFICATE-----
 MIIDTDCCAjSgAwIBAgIId3cGJyapsXwwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UE
 BhMCVVMxFDASBgNVBAoMC0FmZmlybVRydXN0MR8wHQYDVQQDDBZBZmZpcm1UcnVz
 dCBDb21tZXJjaWFsMB4XDTEwMDEyOTE0MDYwNloXDTMwMTIzMTE0MDYwNlowRDEL
 MAkGA1UEBhMCVVMxFDASBgNVBAoMC0FmZmlybVRydXN0MR8wHQYDVQQDDBZBZmZp
 cm1UcnVzdCBDb21tZXJjaWFsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
 AQEA9htPZwcroRX1BiLLHwGy43NFBkRJLLtJJRTWzsO3qyxPxkEylFf6EqdbDuKP
 Hx6GGaeqtS25Xw2Kwq+FNXkyLbscYjfysVtKPcrNcV/pQr6U6Mje+SJIZMblq8Yr
 ba0F8PrVC8+a5fBQpIs7R6UjW3p6+DM/uO+Zl+MgwdYoic+U+7lF7eNAFxHUdPAL
 MeIrJmqbTFeurCA+ukV6BfO9m2kVrn1OIGPENXY6BwLJN/3HR+7o8XYdcxXyl6S1
 yHp52UKqK39c/s4mT6NmgTWvRLpUHhwwMmWd5jyTXlBOeuM61G7MGvv50jeuJCqr
 VwMiKA1JdX+3KNp1v47j3A55MQIDAQABo0IwQDAdBgNVHQ4EFgQUnZPGU4teyq8/
 nx4P5ZmVvCT2lI8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDQYJ
 KoZIhvcNAQELBQADggEBAFis9AQOzcAN/wr91LoWXym9e2iZWEnStB03TX8nfUYG
 XUPGhi4+c7ImfU+TqbbEKpqrIZcUsd6M06uJFdhrJNTxFq7YpFzUf1GO7RgBsZNj
 vbz4YYCanrHOQnDiqX0GJX0nof5v7LMeJNrjS1UaADs1tDvZ110w/YETifLCBivt
 Z8SOyUOyXGsViQK8YvxO8rUzqrJv0wqiUOP2O+guRMLbZjipM1ZI8W0bM40NjD9g
 N53Tym1+NH4Nn3J2ixufcv1SNUFFApYvHLKac0khsUlHRUe072o0EclNmsxZt9YC
 nlpOZbWUrhvfKbAW8b8Angc6F2S1BLUjIZkKlTuXfO8=
 -----END CERTIFICATE-----
ca_other_root_certs=Other Root Certificate B2
 -----BEGIN CERTIFICATE-----
 MIIDTDCCAjSgAwIBAgIIfE8EORzUmS0wDQYJKoZIhvcNAQEFBQAwRDELMAkGA1UE
 BhMCVVMxFDASBgNVBAoMC0FmZmlybVRydXN0MR8wHQYDVQQDDBZBZmZpcm1UcnVz
 dCBOZXR3b3JraW5nMB4XDTEwMDEyOTE0MDgyNFoXDTMwMTIzMTE0MDgyNFowRDEL
 MAkGA1UEBhMCVVMxFDASBgNVBAoMC0FmZmlybVRydXN0MR8wHQYDVQQDDBZBZmZp
 cm1UcnVzdCBOZXR3b3JraW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
 AQEAtITMMxcua5Rsa2FSoOujz3mUTOWUgJnLVWREZY9nZOIG41w3SfYvm4SEHi3y
 YJ0wTsyEheIszx6e/jarM3c1RNg1lho9Nuh6DtjVR6FqaYvZ/Ls6rnla1fTWcbua
 kCNrmreIdIcMHl+5ni36q1Mr3Lt2PpNMCAiMHqIjHNRqrSK6mQEubWXLviRmVSRL
 QESxG9fhwoXA3hA/Pe24/PHxI1Pcv2WXb9n5QHGNfb2V1M6+oF4nI979ptAmDgAp
 6zxG8D1gvz9Q0twmQVGeFDdCBKNwV6gbh+0t+nvujArjqWaJGctB+d1ENmHP4ndG
 yH329JKBNv3bNPFyfvMMFr20FQIDAQABo0IwQDAdBgNVHQ4EFgQUBx/S55zawm6i
 QLSwelAQUHTEyL0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDQYJ
 KoZIhvcNAQEFBQADggEBAIlXshZ6qML91tmbmzTCnLQyFE2npN/svqe++EPbkTfO
 tDIuUFUaNU52Q3Eg75N3ThVwLofDwR1t3Mu1J9QsVtFSUzpE0nPIxBsFZVpikpzu
 QY0x2+c06lkh1QF612S4ZDnNye2v7UsDSKegmQGA3GWjNq5lWUhPgkvIZfFXHeVZ
 Lgo/bNjR9eUJtGxUAArgFU2HdW23WJZa3W3SAKD0m0i+wzekujbgfIeFlxoVot4u
 olu9rxj5kFDNcFn4J2dHy8egBzp90SxdbBk6ZrV9/ZFvgrG+CJPbFEfxojfHRZ48
 x3evZKiT3/Zpg4Jg8klCNO1aAFSFHBY2kgxc+qatv9s=
 -----END CERTIFICATE-----
ca_other_certs=Other Certificate B2
 -----BEGIN CERTIFICATE-----
 MIIB/jCCAYWgAwIBAgIIdJclisc/elQwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMC
 VVMxFDASBgNVBAoMC0FmZmlybVRydXN0MSAwHgYDVQQDDBdBZmZpcm1UcnVzdCBQ
 cmVtaXVtIEVDQzAeFw0xMDAxMjkxNDIwMjRaFw00MDEyMzExNDIwMjRaMEUxCzAJ
 BgNVBAYTAlVTMRQwEgYDVQQKDAtBZmZpcm1UcnVzdDEgMB4GA1UEAwwXQWZmaXJt
 VHJ1c3QgUHJlbWl1bSBFQ0MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQNMF4bFZ0D
 0KF5Nbc6PJJ6yhUczWLznCZcBz3lVPqj1swS6vQUX+iOGasvLkjmrBhDeKzQN8O9
 ss0s5kfiGuZjuD0uL3jET9v0D6RoTFVya5UdThhClXjMNzyR4ptlKymjQjBAMB0G
 A1UdDgQWBBSaryl6wBE1NSZRMADDav5A1a7WPDAPBgNVHRMBAf8EBTADAQH/MA4G
 A1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNnADBkAjAXCfOHiFBar8jAQr9HX/Vs
 aobgxCd05DhT1wV/GzTjxi+zygk8N53X57hG8f2h4nECMEJZh0PUUd+60wkyWs6I
 flc9nF9Ca/UHLbXwgpP5WW+uZPpY5Yse42O+tYHNbwKMeQ==
 -----END CERTIFICATE-----
EOF
cat > $tmpdir/cab3 <<- EOF
id=CAB3
ca_type=EXTERNAL
ca_external_helper=$tmpdir/no-such-helper.sh
ca_root_cert_files=
ca_other_root_cert_files=
ca_other_cert_files=$tmpdir/bundle3,$tmpdir/bundle-all
ca_root_cert_dbs=
ca_other_root_cert_dbs=
ca_other_cert_dbs=
ca_root_certs=Root Certificate B3
 -----BEGIN CERTIFICATE-----
 MIIDpDCCAoygAwIBAgIBATANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEc
 MBoGA1UEChMTQW1lcmljYSBPbmxpbmUgSW5jLjE2MDQGA1UEAxMtQW1lcmljYSBP
 bmxpbmUgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAxMB4XDTAyMDUyODA2
 MDAwMFoXDTM3MTExOTIwNDMwMFowYzELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE0Ft
 ZXJpY2EgT25saW5lIEluYy4xNjA0BgNVBAMTLUFtZXJpY2EgT25saW5lIFJvb3Qg
 Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkgMTCCASIwDQYJKoZIhvcNAQEBBQADggEP
 ADCCAQoCggEBAKgv6KRpBgNHw+kqmP8ZonCaxlCyfqXfaE0bfA+2l2h9LaaLl+lk
 hsmj76CGv2BlnEtUiMJIxUo5vxTjWVXlGbR0yLQFOVwWpeKVBeASrlmLojNoWBym
 1BW32J/X3HGrfpq/m44zDyL9Hy7nBzbvYjnF3cu6JRQj3gzGPTzOggjmZj7aUTsW
 OqMFf6Dch9Wc/HKpoH145LcxVR5lu9RhsCFg7RAycsWSJR74kEoYeEfffjA3PlAb
 2xzTa5qGUwew76wGePiEmf4hjUyAtgyC9mZweRrTT6PP8c9GsEsPPt2IYriMqQko
 O3rHl+Ee5fSfwMCuJKDIodkP1nsmgmkyPacCAwEAAaNjMGEwDwYDVR0TAQH/BAUw
 AwEB/zAdBgNVHQ4EFgQUAK3Zo/Z59m50qX8zPYEX10zPM94wHwYDVR0jBBgwFoAU
 AK3Zo/Z59m50qX8zPYEX10zPM94wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEB
 BQUAA4IBAQB8itEfGDeC4Liwo+1WlchiYZwFos3CYiZhzRAW18y0ZTTQEYqtqKkF
 Zu90821fnZmv9ov761KyBZiibyrFVL0lvV+uyIbqRizBs73B6UlwGBaXCBOMIOAb
 LjpHyx7kADCVW/RFo8AasAFOq73AI25jP4BKxQft3OJvx8Fi8eNy1gTIdGcL+oir
 oQHIb/AUr9KZzVGTfu0uOMe9zkZQPXLjeSWdm4grECDdpbgyn43gKd8hdIaC2y+C
 MMbHNYaz+ZZfRtsMRf3zUMNvxsNIrUam4SdHCh0Om7bCd39j8uB9Gr784N/Xx6ds
 sPmuujz9dLQR6FgNgLzTqIA6me11zEZ7
 -----END CERTIFICATE-----
ca_other_root_certs=Other Root Certificate B3
 -----BEGIN CERTIFICATE-----
 MIIDoDCCAoigAwIBAgIBMTANBgkqhkiG9w0BAQUFADBDMQswCQYDVQQGEwJKUDEc
 MBoGA1UEChMTSmFwYW5lc2UgR292ZXJubWVudDEWMBQGA1UECxMNQXBwbGljYXRp
 b25DQTAeFw0wNzEyMTIxNTAwMDBaFw0xNzEyMTIxNTAwMDBaMEMxCzAJBgNVBAYT
 AkpQMRwwGgYDVQQKExNKYXBhbmVzZSBHb3Zlcm5tZW50MRYwFAYDVQQLEw1BcHBs
 aWNhdGlvbkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp23gdE6H
 j6UG3mii24aZS2QNcfAKBZuOquHMLtJqO8F6tJdhjYq+xpqcBrSGUeQ3DnR4fl+K
 f5Sk10cI/VBaVuRorChzoHvpfxiSQE8tnfWuREhzNgaeZCw7NCPbXCbkcXmP1G55
 IrmTwcrNwVbtiGrXoDkhBFcsovW8R0FPXjQilbUfKW1eSvNNcr5BViCH/OlQR9cw
 FO5cjFW6WY2H/CPek9AEjP3vbb3QesmlOmpyM8ZKDQUXKi17safY1vC+9D/qDiht
 QWEjdnjDuGWk81quzMKq2edY3rZ+nYVunyoKb58DKTCXKB28t89UKU5RMfkntigm
 /qJj5kEW8DOYRwIDAQABo4GeMIGbMB0GA1UdDgQWBBRUWssmP3HMlEYNllPqa0jQ
 k/5CdTAOBgNVHQ8BAf8EBAMCAQYwWQYDVR0RBFIwUKROMEwxCzAJBgNVBAYTAkpQ
 MRgwFgYDVQQKDA/ml6XmnKzlm73mlL/lupwxIzAhBgNVBAsMGuOCouODl+ODquOC
 seODvOOCt+ODp+ODs0NBMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
 ggEBADlqRHZ3ODrso2dGD/mLBqj7apAxzn7s2tGJfHrrLgy9mTLnsCTWw//1sogJ
 hyzjVOGjprIIC8CFqMjSnHH2HZ9g/DgzE+Ge3Atf2hZQKXsvcJEPmbo0NI2VdMV+
 eKlmXb3KIXdCEKxmJj3ekav9FfBv7WxfEPjzFvYDio+nEhEMy/0/ecGc/WLuo89U
 DNErXxc+4z6/wCs+CZv+iKZ+tJIX/COUgb1up8WMwusRRdv4QcmWdupwX3kSa+Sj
 B1oF7ydJzyGfikwJcGapJsErEU4z0g781mzSDjJkaP+tBXhfAx2o45CsJOAPQKdL
 rosot4LKGAfmt1t06SAZf7IbiVQ=
 -----END CERTIFICATE-----
ca_other_certs=Other Certificate B3
 -----BEGIN CERTIFICATE-----
 MIIDdzCCAl+gAwIBAgIIXDPLYixfszIwDQYJKoZIhvcNAQELBQAwPDEeMBwGA1UE
 AwwVQXRvcyBUcnVzdGVkUm9vdCAyMDExMQ0wCwYDVQQKDARBdG9zMQswCQYDVQQG
 EwJERTAeFw0xMTA3MDcxNDU4MzBaFw0zMDEyMzEyMzU5NTlaMDwxHjAcBgNVBAMM
 FUF0b3MgVHJ1c3RlZFJvb3QgMjAxMTENMAsGA1UECgwEQXRvczELMAkGA1UEBhMC
 REUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCVhTuXbyo7LjvPpvMp
 Nb7PGKw+qtn4TaA+Gke5vJrf8v7MPkfoepbCJI419KkM/IL9bcFyYie96mvr54rM
 VD6QUM+A1JX76LWC1BTFtqlVJVfbsVD2sGBkWXppzwO3bw2+yj5vdHLqqjAqc2K+
 SZFhyBH+DgMq92og3AIVDV4VavzjgsG1xZ1kCWyjWZgHJ8cblithdHFsQ/H3NYkQ
 4J7sVaE3IqKHBAUsR320HLliKWYoyrfhk/WklAOZuXCFteZI6o1Q/NnezG8HDt0L
 cp2AMBYHlT8oDv3FdU9T1nSatCQujgKRz3bFmx5VdJx4IbHwLfELn8LVlhgf8FQi
 eowHAgMBAAGjfTB7MB0GA1UdDgQWBBSnpQaxLKYJYO7Rl+lwrrw7GWzbITAPBgNV
 HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFKelBrEspglg7tGX6XCuvDsZbNshMBgG
 A1UdIAQRMA8wDQYLKwYBBAGwLQMEAQEwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3
 DQEBCwUAA4IBAQAmdzTblEiGKkGdLD4GkGDEjKwLVLgfuXvTBznk+j57sj1O7Z8j
 vZfza1zv7v1Apt+hk6EKhqzvINB5Ab149xnYJDE0BAGmuhWawyfc2E8PzBhj/5kP
 DpFrdRbhIfzYJsdHt6bPWHJxfrrhTZVHO8mvbaG0weyJ9rQPOLXiZNwlz6bb65pc
 maHFCN795trV1lpFDMS3wrUU77QR/w4VtfX128a961qn8FYiqTxlVMYVqL2Gns2D
 lmh6cYGJ4Qvh6hEbaAjMaZ7snkGeRDImeuKHCnE96+RapNLbxc3G3mB/ufNPRJLv
 KrcYPqcZ2Qt9sTdBQrC6YB3y/gkRsPCHe6ed
 -----END CERTIFICATE-----
EOF
cat > $tmpdir/cad1 <<- EOF
id=CAD1
ca_type=EXTERNAL
ca_external_helper=$tmpdir/no-such-helper.sh
ca_root_cert_files=
ca_other_root_cert_files=
ca_other_cert_files=
ca_root_cert_dbs=$tmpdir/db1,$tmpdir/dba
ca_other_root_cert_dbs=$tmpdir/dba
ca_other_cert_dbs=$tmpdir/dba
ca_root_certs=Root Certificate D1
 -----BEGIN CERTIFICATE-----
 MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ
 RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD
 VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX
 DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y
 ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy
 VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr
 mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr
 IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK
 mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu
 XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy
 dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye
 jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1
 BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
 DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92
 9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx
 jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0
 Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz
 ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS
 R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp
 -----END CERTIFICATE-----
ca_other_root_certs=Other Root Certificate D1
 -----BEGIN CERTIFICATE-----
 MIIDUzCCAjugAwIBAgIBATANBgkqhkiG9w0BAQUFADBLMQswCQYDVQQGEwJOTzEd
 MBsGA1UECgwUQnV5cGFzcyBBUy05ODMxNjMzMjcxHTAbBgNVBAMMFEJ1eXBhc3Mg
 Q2xhc3MgMiBDQSAxMB4XDTA2MTAxMzEwMjUwOVoXDTE2MTAxMzEwMjUwOVowSzEL
 MAkGA1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MR0wGwYD
 VQQDDBRCdXlwYXNzIENsYXNzIDIgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEP
 ADCCAQoCggEBAIs8B0XY9t/mx8q6jUPFR42wWsE425KEHK8T1A9vNkYgxC7McXA0
 ojTTNy7Y3Tp3L8DrKehc0rWpkTSHIln+zNvnma+WwajHQN2lFYxuyHyXA8vmIPLX
 l18xoS830r7uvqmtqEyeIWZDO6i88wmjONVZJMHCR3axiFyCO7srpgTXjAePzdVB
 HfCuuCkslFJgNJQ72uA40Z0zPhX0kzLFANq1KWYOOngPIVJfAuWSeyXTkh4vFZ2B
 5J2O6O+JzhRMVB0cgRJNcKi+EAUXfh/RuFdV7c27UsKwHnjCTTZoy1YmwVLBvXb3
 WNVyfh9EdrsAiR0WnVE1703CVu9r4Iw7DekCAwEAAaNCMEAwDwYDVR0TAQH/BAUw
 AwEB/zAdBgNVHQ4EFgQUP42aWYv8e3uco684sDntkHGA1sgwDgYDVR0PAQH/BAQD
 AgEGMA0GCSqGSIb3DQEBBQUAA4IBAQAVGn4TirnoB6NLJzKyQJHyIdFkhb5jatLP
 gcIV1Xp+DCmsNx4cfHZSldq1fyOhKXdlyTKdqC5Wq2B2zha0jX94wNWZUYN/Xtm+
 DKhQ7SLHrQVMdvvt7h5HZPb3J31cKA9FxVxiXqaakZG3Uxcu3K1gnZZkOb1naLKu
 BctN518fV4bVIJwo+28TOPX2EZL2fZleHwzoq0QkKXJAPTZSr4xYkHPB7GEseaHs
 h7U/2k3ZIQAw3pDaDtMaSKk+hQsUi4y8QZ5q9w5wwDX3OaJdZtB7WZ+oRxKaJyOk
 LY4ng5IgodcVf/EuGO70SH8vf/GhGLWhC5SgYiAynB321O+/TIho
 -----END CERTIFICATE-----
ca_other_certs=Other Certificate D1
 -----BEGIN CERTIFICATE-----
 MIIDUzCCAjugAwIBAgIBAjANBgkqhkiG9w0BAQUFADBLMQswCQYDVQQGEwJOTzEd
 MBsGA1UECgwUQnV5cGFzcyBBUy05ODMxNjMzMjcxHTAbBgNVBAMMFEJ1eXBhc3Mg
 Q2xhc3MgMyBDQSAxMB4XDTA1MDUwOTE0MTMwM1oXDTE1MDUwOTE0MTMwM1owSzEL
 MAkGA1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MR0wGwYD
 VQQDDBRCdXlwYXNzIENsYXNzIDMgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEP
 ADCCAQoCggEBAKSO13TZKWTeXx+HgJHqTjnmGcZEC4DVC69TB4sSveZn8AKxifZg
 isRbsELRwCGoy+Gb72RRtqfPFfV0gGgEkKBYouZ0plNTVUhjP5JW3SROjvi6K//z
 NIqeKNc0n6wv1g/xpC+9UrJJhW05NfBEMJNGJPO251P7vGGvqaMU+8IXF4Rs4HyI
 +MkcVyzwPX6UvCWThOiaAJpFBUJXgPROztmuOfbIUxAMZTpHe2DC1vqRycZxbL2R
 hzyRhkmr8w+gbCZ2Xhysm3HljbybIR6c1jh+JIAVMYKWsUnTYjdbiAwKYjT+p0h+
 mbEwi5A3lRyoH6UsjfRVyNvdWQrCrXig9IsCAwEAAaNCMEAwDwYDVR0TAQH/BAUw
 AwEB/zAdBgNVHQ4EFgQUOBTmyPCppAP0Tj4io1vy1uCtQHQwDgYDVR0PAQH/BAQD
 AgEGMA0GCSqGSIb3DQEBBQUAA4IBAQABZ6OMySU9E2NdFm/soT4JXJEVKirZgCFP
 Bdy7pYmrEzMqnji3jG8CcmPHc3ceCQa6Oyh7pEfJYWsICCD8igWKH7y6xsL+z27s
 EzNxZy5p+qksP2bAEllNC1QCkoS72xLvg3BweMhT+t/Gxv/ciC8HwEmdMldg0/L2
 mSlf56oBzKwzqBwKu5HEA6BvtjT5htOzdlSY9EqBs1OdTUDs5XcTRa9bqh/YL0yC
 e/4qxFi7T/ye/QNlGioOw6UgFpRreaaiErS7GqQjel/wroQk5PMr+4okoyeYZdow
 dXb8GZHo2+ubPzK/QJcHJrrM85SFSnonk8+QQtS4Wxam58tAA915
 -----END CERTIFICATE-----
EOF
cat > $tmpdir/cad2 <<- EOF
id=CAD2
ca_type=EXTERNAL
ca_external_helper=$tmpdir/no-such-helper.sh
ca_root_cert_files=
ca_other_root_cert_files=
ca_other_cert_files=
ca_root_cert_dbs=$tmpdir/dba
ca_other_root_cert_dbs=$tmpdir/db2,$tmpdir/dba
ca_other_cert_dbs=$tmpdir/dba
ca_root_certs=Root Certificate D2
 -----BEGIN CERTIFICATE-----
 MIIEDzCCAvegAwIBAgIBATANBgkqhkiG9w0BAQUFADBKMQswCQYDVQQGEwJTSzET
 MBEGA1UEBxMKQnJhdGlzbGF2YTETMBEGA1UEChMKRGlzaWcgYS5zLjERMA8GA1UE
 AxMIQ0EgRGlzaWcwHhcNMDYwMzIyMDEzOTM0WhcNMTYwMzIyMDEzOTM0WjBKMQsw
 CQYDVQQGEwJTSzETMBEGA1UEBxMKQnJhdGlzbGF2YTETMBEGA1UEChMKRGlzaWcg
 YS5zLjERMA8GA1UEAxMIQ0EgRGlzaWcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
 ggEKAoIBAQCS9jHBfYj9mQGp2HvycXXxMcbzdWb6UShGhJd4NLxs/LxFWYgmGErE
 Nx+hSkS943EE9UQX4j/8SFhvXJ56CbpRNyIjZkMhsDxkovhqFQ4/61HhVKndBpnX
 mjxUizkDPw/Fzsbrg3ICqB9x8y34dQjbYkzo+s7552oftms1grrijxaSfQUMbEYD
 XcDtab86wYqg6I7ZuUUohwjstMoVvoLdtUSLLa2GDGhibYVW8qwUYzrG0ZmsNHhW
 S8+2rT+MitcE5eN4TPWGqvWP+j1scaMtymfraHtuM6kMgiioTGohQBUgDCZbg8Kp
 FhXAJIJdKxatymP2dACw30PEEGBWZ2NFAgMBAAGjgf8wgfwwDwYDVR0TAQH/BAUw
 AwEB/zAdBgNVHQ4EFgQUjbJJaJ1yCCW5wCf1UJNWSEZx+Y8wDgYDVR0PAQH/BAQD
 AgEGMDYGA1UdEQQvMC2BE2Nhb3BlcmF0b3JAZGlzaWcuc2uGFmh0dHA6Ly93d3cu
 ZGlzaWcuc2svY2EwZgYDVR0fBF8wXTAtoCugKYYnaHR0cDovL3d3dy5kaXNpZy5z
 ay9jYS9jcmwvY2FfZGlzaWcuY3JsMCygKqAohiZodHRwOi8vY2EuZGlzaWcuc2sv
 Y2EvY3JsL2NhX2Rpc2lnLmNybDAaBgNVHSAEEzARMA8GDSuBHpGT5goAAAABAQEw
 DQYJKoZIhvcNAQEFBQADggEBAF00dGFMrzvY/59tWDYcPQuBDRIrRhCA/ec8J9B6
 yKm2fnQwM6M6int0wHl5QpNt/7EpFIKrIYwvF/k/Ji/1WcbvgAa3mkkp7M5+cTxq
 EEHA9tOasnxakZzArFvITV734VP/Q3f8nktnbNfzg9Gg4H8l37iYC5oyOGwwoPP/
 CBUz91BKez6jPiCp3C9WgArtQVCwyfTssuMmRAAOb54GvCKWU3BlxFAKRmukLyeB
 EicTXxChds6KezfqwzlhA5WYOudsiCUI/HloDYd9Yvi0X/vF2Ey9WLw/Q1vUHgFN
 PGO+I++MzVpQuGhU+QqZMxEA4Z7CRneC9VkGjCFMhwnN5ag=
 -----END CERTIFICATE-----
ca_other_root_certs=Other Root Certificate D2
 -----BEGIN CERTIFICATE-----
 MIIDVTCCAj2gAwIBAgIESTMAATANBgkqhkiG9w0BAQUFADAyMQswCQYDVQQGEwJD
 TjEOMAwGA1UEChMFQ05OSUMxEzARBgNVBAMTCkNOTklDIFJPT1QwHhcNMDcwNDE2
 MDcwOTE0WhcNMjcwNDE2MDcwOTE0WjAyMQswCQYDVQQGEwJDTjEOMAwGA1UEChMF
 Q05OSUMxEzARBgNVBAMTCkNOTklDIFJPT1QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
 DwAwggEKAoIBAQDTNfc/c3et6FtzF8LRb+1VvG7q6KR5smzDo+/hn7E7SIX1mlwh
 IhAsxYLO2uOabjfhhyzcuQxauohV3/2q2x8x6gHx3zkBwRP9SFIhxFXf2tizVHa6
 dLG3fdfA6PZZxU3Iva0fFNrfWEQlMhkqx35+jq44sDB7R3IJMfAw28Mbdim7aXZO
 V/kbZKKTVrdvmW7bCgScEeOAH8tjlBAKqeFkgjH5jCftppkA9nCTGPihNIaj3XrC
 GHn2emU1z5DrvTOTn1OrczvmmzQgLx3vqR1jGqCA2wMv+SYahtKNu6m+UjqHZ0gN
 v7Sg2Ca+I19zN38m5pIEo3/PIKe38zrKy5nLAgMBAAGjczBxMBEGCWCGSAGG+EIB
 AQQEAwIABzAfBgNVHSMEGDAWgBRl8jGtKvf33VKWCscCwQ7vptU7ETAPBgNVHRMB
 Af8EBTADAQH/MAsGA1UdDwQEAwIB/jAdBgNVHQ4EFgQUZfIxrSr3991SlgrHAsEO
 76bVOxEwDQYJKoZIhvcNAQEFBQADggEBAEs17szkrr/Dbq2flTtLP1se31cpolnK
 OOK5Gv+e5m4y3R6u6jW39ZORTtpC4cMXYFDy0VwmuYK36m3knITnA3kXr5g9lNvH
 ugDnuL8BV8F3RTIMO/G0HAiw/VGgod2aHRM2mm23xzy54cXZF/qD1T0VoDy7Hgvi
 yJA/qIYM/PmLXoXLT1tLYhFHxUV8BS9BsZ4QaRuZluBVeftOhpm4lNqGOGqTo+fL
 buXf6iFViZx9fX+Y9QCJ7uOEwFyWtcVG6kbghVW2G8kS1sHNzYDzAgE8yGnLRUhj
 2JTQ7IUOO04RZfSCjKY9ri4ilAnIXOo8gV0WKgOXFlUJ24pBgp5mmxE=
 -----END CERTIFICATE-----
ca_other_certs=Other Certificate D2
 -----BEGIN CERTIFICATE-----
 MIIEHTCCAwWgAwIBAgIQToEtioJl4AsC7j41AkblPTANBgkqhkiG9w0BAQUFADCB
 gTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
 A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxJzAlBgNV
 BAMTHkNPTU9ETyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjEyMDEwMDAw
 MDBaFw0yOTEyMzEyMzU5NTlaMIGBMQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3Jl
 YXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01P
 RE8gQ0EgTGltaXRlZDEnMCUGA1UEAxMeQ09NT0RPIENlcnRpZmljYXRpb24gQXV0
 aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ECLi3LjkRv3
 UcEbVASY06m/weaKXTuH+7uIzg3jLz8GlvCiKVCZrts7oVewdFFxze1CkU1B/qnI
 2GqGd0S7WWaXUF601CxwRM/aN5VCaTwwxHGzUvAhTaHYujl8HJ6jJJ3ygxaYqhZ8
 Q5sVW7euNJH+1GImGEaaP+vB+fGQV+useg2L23IwambV4EajcNxo2f8ESIl33rXp
 +2dtQem8Ob0y2WIC8bGoPW43nOIv4tOiJovGuFVDiOEjPqXSJDlqR6sA1KGzqSX+
 DT+nHbrTUcELpNqsOO9VUCQFZUaTNE8tja3G1CEZ0o7KBWFxB3NH5YoZEr0ETc5O
 nKVIrLsm9wIDAQABo4GOMIGLMB0GA1UdDgQWBBQLWOWLxkwVN6RAqTCpIb5HNlpW
 /zAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBJBgNVHR8EQjBAMD6g
 PKA6hjhodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9DZXJ0aWZpY2F0aW9u
 QXV0aG9yaXR5LmNybDANBgkqhkiG9w0BAQUFAAOCAQEAPpiem/Yb6dc5t3iuHXIY
 SdOH5EOC6z/JqvWote9VfCFSZfnVDeFs9D6Mk3ORLgLETgdxb8CPOGEIqB6BCsAv
 IC9Bi5HcSEW88cbeunZrM8gALTFGTO3nnc+IlP8zwFboJIYmuNg4ON8qa90SzMc/
 RxdMosIGlgnW2/4/PEZB31jiVg88O8EckzXZOFKs7sjsLjBOlDW0JB9LeGna8gI4
 zJVSk/BwJVmcIGfE7vmLV2H0knZ9P4SNVbfo5azV8fUZVqZa+5Acr5Pr5RzUZ5dd
 BA6+C4OmF4O5MBKgxTMVBbkN+8cFduPYSo38NBejxiEovjBFMR7HeL5YYTisO+IB
 ZQ==
 -----END CERTIFICATE-----
EOF
cat > $tmpdir/cad3 <<- EOF
id=CAD3
ca_type=EXTERNAL
ca_external_helper=$tmpdir/no-such-helper.sh
ca_root_cert_files=
ca_other_root_cert_files=
ca_other_cert_files=
ca_root_cert_dbs=,$tmpdir/dba
ca_other_root_cert_dbs=,$tmpdir/dba,
ca_other_cert_dbs=$tmpdir/db3,$tmpdir/dba
ca_root_certs=Root Certificate D3
 -----BEGIN CERTIFICATE-----
 MIICiTCCAg+gAwIBAgIQH0evqmIAcFBUTAGem2OZKjAKBggqhkjOPQQDAzCBhTEL
 MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
 BxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT
 IkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwMzA2MDAw
 MDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy
 ZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N
 T0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlv
 biBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQDR3svdcmCFYX7deSR
 FtSrYpn1PlILBs5BAH+X4QokPB0BBO490o0JlwzgdeT6+3eKKvUDYEs2ixYjFq0J
 cfRK9ChQtP6IHG4/bC8vCVlbpVsLM5niwz2J+Wos77LTBumjQjBAMB0GA1UdDgQW
 BBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
 BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjEA7wNbeqy3eApyt4jf/7VGFAkK+qDm
 fQjGGoe9GKhzvSbKYAydzpmfz1wPMOG+FDHqAjAU9JM8SaczepBGR7NjfRObTrdv
 GDeAU/7dIOA1mjbRxwG55tzd8/8dLDoWV9mSOdY=
 -----END CERTIFICATE-----
ca_other_root_certs=Other Root Certificate D3
 -----BEGIN CERTIFICATE-----
 MIIDqDCCApCgAwIBAgIJAP7c4wEPyUj/MA0GCSqGSIb3DQEBBQUAMDQxCzAJBgNV
 BAYTAkZSMRIwEAYDVQQKDAlEaGlteW90aXMxETAPBgNVBAMMCENlcnRpZ25hMB4X
 DTA3MDYyOTE1MTMwNVoXDTI3MDYyOTE1MTMwNVowNDELMAkGA1UEBhMCRlIxEjAQ
 BgNVBAoMCURoaW15b3RpczERMA8GA1UEAwwIQ2VydGlnbmEwggEiMA0GCSqGSIb3
 DQEBAQUAA4IBDwAwggEKAoIBAQDIaPHJ1tazNHUmgh7stL7qXOEm7RFHYeGifBZ4
 QCHkYJ5ayGPhxLGWkv8YbWkj4Sti993iNi+RB7lIzw7sebYs5zRLcAglozyHGxny
 gQcPOJAZ0xH+hrTy0V4eHpbNgGzOOzGTtvKg0KmVEn2lmsxryIRWijOp5yIVUxbw
 zBfsV1/pogqYCd7jX5xv3EjjhQsVWqa6n6xI4wmy9/Qy3l40vhx4XUJbzg4ij02Q
 130yGLMLLGq/jj8UEYkgDncUtT2UCIf3JR7VsmAA7G8qKCVuKj4YYxclPz5EIBb2
 JsglrgVKtOdjLPOMFlN+XPsRGgjBRmKfIrjxwo1p3Po6WAbfAgMBAAGjgbwwgbkw
 DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUGu3+QTmQtCRZvgHyUtVF9lo53BEw
 ZAYDVR0jBF0wW4AUGu3+QTmQtCRZvgHyUtVF9lo53BGhOKQ2MDQxCzAJBgNVBAYT
 AkZSMRIwEAYDVQQKDAlEaGlteW90aXMxETAPBgNVBAMMCENlcnRpZ25hggkA/tzj
 AQ/JSP8wDgYDVR0PAQH/BAQDAgEGMBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG
 9w0BAQUFAAOCAQEAhQMeknH2Qq/ho2Ge6/PAD/Kl1NqV5ta+aDY9fm4fTIrv0Q8h
 bV6lUmPOEvjvKtpv6zf+EwLHyzs+ImvaYS5/1HI93TDhHkxAGYwP15zRgzB7mFnc
 fca5DClMoTOi62c6ZYTTluLtdkVwj7Ur3vkj1kluPBS1xp81HlDQwY9qcEQCYsuu
 HWhBp6pX6FOqB9IG9tUUBguRA3UsbHK1YZWaDYu5Def131TN3ubY1gkIl2PlwS6w
 t0QmwCbAr1UwnjvVNioZBPRcHv/PLLf/0P2HQBHVESO7SMAhqaQoLf0V+LBOK/Qw
 WyH8EZE0vkHve52Xdf+XlcCWWC/qu0bXu+TZLg==
 -----END CERTIFICATE-----
ca_other_certs=Other Certificate D3
 -----BEGIN CERTIFICATE-----
 MIIDkjCCAnqgAwIBAgIRAIW9S/PY2uNp9pTXX8OlRCMwDQYJKoZIhvcNAQEFBQAw
 PTELMAkGA1UEBhMCRlIxETAPBgNVBAoTCENlcnRwbHVzMRswGQYDVQQDExJDbGFz
 cyAyIFByaW1hcnkgQ0EwHhcNOTkwNzA3MTcwNTAwWhcNMTkwNzA2MjM1OTU5WjA9
 MQswCQYDVQQGEwJGUjERMA8GA1UEChMIQ2VydHBsdXMxGzAZBgNVBAMTEkNsYXNz
 IDIgUHJpbWFyeSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANxQ
 ltAS+DXSCHh6tlJw/W/uz7kRy1134ezpfgSN1sxvc0NXYKwzCkTsA18cgCSR5aiR
 VhKC9+Ar9NuuYS6JEI1rbLqzAr3VNsVINyPi8Fo3UjMXEuLRYE2+L0ER4/YXJQyL
 kcAbmXuZVg2v7tK8R1fjeUl7NIknJITesezpWE7+Tt9avkGtrAjFGA7v0lPubNCd
 EgETjdyAYveVqUSISnFOYFWe2yMZeVYHDD9jC1yw4r5+FfyUM1hBOHTE4Y+L3yas
 H7WLO7dDWWuwJKZtkIvEcupdM5i3y95ee++U8Rs+yskhwcWYAqqi9lt3m/V+llU0
 HGdpwPFC40es/CgcZlUCAwEAAaOBjDCBiTAPBgNVHRMECDAGAQH/AgEKMAsGA1Ud
 DwQEAwIBBjAdBgNVHQ4EFgQU43Mt38sOKAze3bOkynm4jrvoMIkwEQYJYIZIAYb4
 QgEBBAQDAgEGMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly93d3cuY2VydHBsdXMu
 Y29tL0NSTC9jbGFzczIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQCnVM+IRBnL39R/
 AN9WM2K191EBkOvDP9GIROkkXe/nFL0gt5o8AP5tn9uQ3Nf0YtaLcF3n5QRIqWh8
 yfFC82x/xXp8HVGIutIKPidd3i1RTtMTZGnkLuPT55sJmabglZvOGtd/vjzOUrMR
 FcEPF80Du5wlFbqidon8BvEY0JNLDnyCt6X09l/+7UCmnYR0ObncHoUW2ikbhiMA
 ybuJfm6AiB4vFLQDJKgybwOaRywwvlbGp0ICcBvqQNi6BQNwB6SW//1IMwrh3KWB
 kJtN3X3n57LNXMhqlfil9o3EXXgIvnsG1knPGTZQIy4I5p4FTUcY1Rbpsda2ENW7
 l7+ijrRU
 -----END CERTIFICATE-----
EOF
cat > $tmpdir/cada <<- EOF
id=CADA
ca_type=EXTERNAL
ca_external_helper=$tmpdir/no-such-helper.sh
ca_root_cert_files=$tmpdir/bundle-all
ca_other_root_cert_files=
ca_other_cert_files=
ca_root_cert_dbs=$tmpdir/dba
ca_other_root_cert_dbs=,$tmpdir/dba
ca_other_cert_dbs=,$tmpdir/dba
ca_root_certs=Root Certificate DA
 -----BEGIN CERTIFICATE-----
 MIICiDCCAg2gAwIBAgIQNfwmXNmET8k9Jj1Xm67XVjAKBggqhkjOPQQDAzCBhDEL
 MAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjE4MDYGA1UECxMvKGMp
 IDIwMDcgdGhhd3RlLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxJDAi
 BgNVBAMTG3RoYXd0ZSBQcmltYXJ5IFJvb3QgQ0EgLSBHMjAeFw0wNzExMDUwMDAw
 MDBaFw0zODAxMTgyMzU5NTlaMIGEMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhh
 d3RlLCBJbmMuMTgwNgYDVQQLEy8oYykgMjAwNyB0aGF3dGUsIEluYy4gLSBGb3Ig
 YXV0aG9yaXplZCB1c2Ugb25seTEkMCIGA1UEAxMbdGhhd3RlIFByaW1hcnkgUm9v
 dCBDQSAtIEcyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEotWcgnuVnfFSeIf+iha/
 BebfowJPDQfGAFG6DAJSLSKkQjnE/o/qycG+1E3/n3qe4rF8mq2nhglzh9HnmuN6
 papu+7qzcMBniKI11KOasf2twu8x+qi58/sIxpHR+ymVo0IwQDAPBgNVHRMBAf8E
 BTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUmtgAMADna3+FGO6Lts6K
 DPgR4bswCgYIKoZIzj0EAwMDaQAwZgIxAN344FdHW6fmCsO99YCKlzUNG4k8VIZ3
 KMqh9HneteY4sPBlcIx/AlTCv//YoT7ZzwIxAMSNlPzcU9LcnXgWHxUzI1NS41ox
 XZ3Krr0TKUQNJ1uo52icEvdYPy5yAlejj6EULg==
 -----END CERTIFICATE-----
EOF

entries=" -e entryb1 -e entryb2 -e entryb3 -e entryd1 -e entryd2 -e entryd3"
centries=" -e entrycb1 -e entrycb2 -e entrycb3 -e entrycd1 -e entrycd2 -e entrycd3"
caentries=" -e entrycab1 -e entrycab2 -e entrycab3 -e entrycad1 -e entrycad2 -e entrycad3"
cas=" -c cab1 -c cab2 -c cab3 -c cad1 -c cad2 -c cad3 -c cada"

for which in CAB1 CAB2 CAB3 CAD1 CAD2 CAD3 EntryB1 EntryB2 EntryB3 EntryD1 EntryD2 EntryD3 EntryCB1 EntryCB2 EntryCB3 EntryCD1 EntryCD2 EntryCD3 EntryCAB1 EntryCAB2 EntryCAB3 EntryCAD1 EntryCAD2 EntryCAD3 ; do
	echo "[($which)]"
	rm -f $tmpdir/bundle1 $tmpdir/bundle2 $tmpdir/bundle3 $tmpdir/bundle-all
	rm -fr $tmpdir/db1 $tmpdir/db2 $tmpdir/db3 $tmpdir/dba
	mkdir $tmpdir/db1 $tmpdir/db2 $tmpdir/db3 $tmpdir/dba
	$toolsdir/casave $entries $centries $caentries $cas $which
	for bundle in 1 2 3 -all ; do
		echo "[bundle$bundle]"
		touch "bundle$bundle"
		cat "bundle$bundle" > "oldbundle$bundle"
		if test `grep 'BEGIN CERTIFICATE-----' "bundle$bundle" | wc -l` \
			-ne `grep 'END CERTIFICATE-----' "bundle$bundle" | wc -l` ; then
			echo Storage error: possibly-truncated certs in "bundle$bundle".
			cat "bundle$bundle"
			exit 1
		fi
		grep 'BEGIN CERTIFICATE-----' "bundle$bundle" | wc -l
	done
	for db in 1 2 3 a ; do
		echo "[db$db]"
		certutil -L -d "db$db" 2> /dev/null | \
		grep , | grep -v JAR/XPI | sed -r 's, +, ,g' | \
		env LANG=C sort | tee "olddblist$db"
	done
	$toolsdir/casave $entries $centries $caentries $cas $which
	for bundle in 1 2 3 -all ; do
		diff -u "bundle$bundle" "oldbundle$bundle"
	done
	for db in 1 2 3 a ; do
		certutil -L -d "db$db" 2> /dev/null | \
		grep , | grep -v JAR/XPI | sed -r 's, +, ,g' | \
		env LANG=C sort > "dblist$db"
		diff -u "olddblist$db" "dblist$db"
	done
	echo
done

echo OK.
