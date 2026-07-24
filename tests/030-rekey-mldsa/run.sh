#!/bin/bash -e
#
# Rekey integration test for all ML-DSA size transitions:
#   ML-DSA-44 → ML-DSA-65, then ML-DSA-65 → ML-DSA-87.

export REKEY_KEY_TYPE=mldsa

export REKEY_ML_DSA_INITIAL=44
export REKEY_ML_DSA_REKEY=65
. "$srcdir"/030-rekey/rekey-body.sh

rm -f "$tmpdir"/*.db

export REKEY_ML_DSA_INITIAL=65
export REKEY_ML_DSA_REKEY=87
. "$srcdir"/030-rekey/rekey-body.sh
