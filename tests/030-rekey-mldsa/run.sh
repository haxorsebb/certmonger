#!/bin/bash -e
#
# Rekey integration test for ML-DSA size transitions (cross-size and same-size):
#   44→65, 65→87, 44→44, 65→65, 87→87.

export REKEY_KEY_TYPE=mldsa

for pair in 44:65 65:87 44:44 65:65 87:87 ; do
	export REKEY_ML_DSA_INITIAL=${pair%:*}
	export REKEY_ML_DSA_REKEY=${pair#*:}
	. "$srcdir"/030-rekey/rekey-body.sh
	rm -f "$tmpdir"/*.db
done
