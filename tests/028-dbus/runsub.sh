#!/bin/bash
exec > "$TMPDIR"/runsub.out 2> "$TMPDIR"/runsub.err
cd "$TMPDIR"
source prequal.sh
echo "[[ getcert ]]"
for i in `seq 60` ; do
	if getcert status -s -i Buddy ; then
		break
	fi
	sleep 1
done
getcert status -s -v -i Buddy
getcert list -s
getcert list-cas -s
echo ""
echo "[[ API ]]"
for i in ./*.py ; do
	echo "[" `basename "$i"` "]"
	python $i
done
