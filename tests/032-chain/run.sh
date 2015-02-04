#!/bin/bash
cd "$tmpdir"
$toolsdir/cachain.sh 5 2> /dev/null
for c0 in ca0 ca1 ca2 ca3 ca4 ca5 ee ; do
for c1 in ca0 ca1 ca2 ca3 ca4 ca5 ee ; do
if test $c1 = $c0 ; then
	continue
fi
for c2 in ca0 ca1 ca2 ca3 ca4 ca5 ee ; do
if test $c2 = $c0 -o $c2 = $c1 ; then
	continue
fi
for c3 in ca0 ca1 ca2 ca3 ca4 ca5 ee ; do
if test $c3 = $c0 -o $c3 = $c1 -o $c3 = $c2 ; then
	continue
fi
for c4 in ca0 ca1 ca2 ca3 ca4 ca5 ee ; do
if test $c4 = $c0 -o $c4 = $c1 -o $c4 = $c2 -o $c4 = $c3 ; then
	continue
fi
for c5 in ca0 ca1 ca2 ca3 ca4 ca5 ee ; do
if test $c5 = $c0 -o $c5 = $c1 -o $c5 = $c2 -o $c5 = $c3 -o $c5 = $c4 ; then
	continue
fi
for c6 in ca0 ca1 ca2 ca3 ca4 ca5 ee ; do
if test $c6 = $c0 -o $c6 = $c1 -o $c6 = $c2 -o $c6 = $c3 -o $c6 = $c4 -o $c6 = $c5 ; then
	continue
fi

echo "["$c0.crt,$c1.crt,$c2.crt,$c3.crt,$c4.crt,$c5.crt,$c6.crt"]" > expected
echo "TOP:" >> expected
cat ca0.crt >> expected
echo "LEAF:" >> expected
cat ee.crt >> expected
j=1
for cert in ca5 ca4 ca3 ca2 ca1 ; do
	echo $j":" >> expected
	cat $cert.crt >> expected
	j=$((j+1))
done
$toolsdir/pk7parse $c0.crt $c1.crt $c2.crt $c3.crt $c4.crt $c5.crt $c6.crt > actual
if ! cmp actual expected ; then
	echo Order is wrong with $c0.crt,$c1.crt,$c2.crt,$c3.crt,$c4.crt,$c5.crt,$c6.crt.
	exit 1
fi
done
done
done
done
done
done
done
echo OK
exit 0
