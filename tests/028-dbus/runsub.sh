#!/bin/bash
exec > "$TMPDIR"/runsub.out 2> "$TMPDIR"/runsub.err
for i in `seq 60` ; do
	if test -s "$TMPDIR"/test.crt ; then
		break
	fi
	sleep 1
done
cd "$TMPDIR"
source prequal.sh
echo "[[ getcert ]]"
for i in `seq 60` ; do
	if "$TMPDIR"/getcert status -s -i Buddy ; then
		break
	fi
	sleep 1
done
"$TMPDIR"/getcert status -s -v -i Buddy
"$TMPDIR"/getcert list -s
"$TMPDIR"/getcert list-cas -s
echo ""
echo "[[ API ]]"
for i in ./*.py ; do
	echo "[" `basename "$i"` "]"
	python $i
done
