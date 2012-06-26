#!/bin/sh -e
count=0
for good in good.profileSubmit* ; do
	$toolsdir/dparse submit $good
	count=`expr $count + 1`
done
for good in good.profileReview* ; do
	$toolsdir/dparse review $good
	count=`expr $count + 1`
done
for good in good.checkRequest* ; do
	$toolsdir/dparse check $good
	count=`expr $count + 1`
done
for good in good.displayCertFromRequest* ; do
	$toolsdir/dparse fetch $good
	count=`expr $count + 1`
done
for bad in bad.profileSubmit* ; do
	$toolsdir/dparse submit $bad
	count=`expr $count + 1`
done
for bad in bad.profileReview* ; do
	$toolsdir/dparse review $bad
	count=`expr $count + 1`
done
for bad in bad.profileProcess* ; do
	$toolsdir/dparse approve $bad
	count=`expr $count + 1`
done
for bad in bad.checkRequest* ; do
	$toolsdir/dparse check $bad
	count=`expr $count + 1`
done
for bad in bad.displayCertFromRequest* ; do
	$toolsdir/dparse fetch $bad
	count=`expr $count + 1`
done
echo $count samples.
