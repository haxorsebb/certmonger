#!/bin/bash -e

TOOL="${toolsdir}/validate_sm_fromfile"

exit_code=0

invalid_null_file=${tmpdir}/submit-from-empty-file.test
valid_size_file=${tmpdir}/submit-from-valid-file.test

if [ ! -x "$TOOL" ]; then
	echo "FAIL: tool not found or not executable: $TOOL"
	exit 1
fi

printf '\x00' > "${invalid_null_file}"

yes 'test line' | head -c $((1024 * 1024)) > "${valid_size_file}"

if "$TOOL" "$valid_size_file"; then
	echo "[TEST] Valid size: OK"
else
	echo "[TEST] Valid size: FAIL"
	exit_code=1
fi

if "$TOOL" "$invalid_null_file"; then
	echo "[TEST] Null file: FAIL"
	exit_code=1
else
	echo "[TEST] Null file: OK"
fi

exit ${exit_code}
