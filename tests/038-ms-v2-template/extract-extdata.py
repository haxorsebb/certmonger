#!/bin/python2

# Given `openssl asn1parse` output of a CSR, look for the V2 Template
# extension and output its data if found.  Nonzero exit status if
# not found.

import binascii
import re
import sys

STATE_SEARCH, STATE_FOUND, STATE_DONE = range(3)

state = STATE_SEARCH

for line in sys.stdin:
    if state == STATE_SEARCH and ':1.3.6.1.4.1.311.21.7' in line:
        state = STATE_FOUND
        continue

    # look for first OCTET STRING once we're in STATE_FOUND
    #
    if state == STATE_FOUND and 'OCTET STRING' in line:
        result = re.search(r'\[HEX DUMP\]:(\w*)', line)
        sys.stdout.write(binascii.unhexlify(result.group(1)))
        state = STATE_DONE
        break

if state != STATE_DONE:
    sys.exit(1)
