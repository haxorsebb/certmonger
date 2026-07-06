#!/bin/bash -e
#
# Rekey integration test (ML-DSA).  Same flow as 030-rekey with
# REKEY_KEY_TYPE=mldsa: initial ML-DSA-44 key, rekey to ML-DSA-65.
# Exercises keyiread next-key handling for mixed ML-DSA sizes.
# Skipped unless ML-DSA is allowed in NSS crypto policy (see prequal.sh).
# Included in make check only when configure enables ML-DSA.

export REKEY_KEY_TYPE=mldsa
export REKEY_ML_DSA_INITIAL=44
export REKEY_ML_DSA_REKEY=65
. "$srcdir"/030-rekey/rekey-body.sh
