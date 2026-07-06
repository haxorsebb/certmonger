#!/bin/bash -e
#
# Rekey integration test (RSA-2048).  Shared logic lives in rekey-body.sh.
# Optional ML-DSA variant: tests/030-rekey-mldsa (enabled via HAVE_ML_DSA).
# Manual override: REKEY_KEY_TYPE=mldsa tests/030-rekey/run.sh is not used for
# make check; use the 030-rekey-mldsa test directory instead.

export REKEY_KEY_TYPE=${REKEY_KEY_TYPE:-rsa}
. "$srcdir"/030-rekey/rekey-body.sh
