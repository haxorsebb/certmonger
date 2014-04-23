#!/bin/bash -e
count=0
for role in agent end-user ; do
for good in good.profileSubmit* ; do
	$toolsdir/dparse submit $role $good
	count=`expr $count + 1`
done
for good in good.profileReview* ; do
	$toolsdir/dparse review $role $good
	count=`expr $count + 1`
done
for good in good.checkRequest* ; do
	$toolsdir/dparse check $role $good
	count=`expr $count + 1`
done
for good in good.displayCertFromRequest* ; do
	$toolsdir/dparse fetch $role $good
	count=`expr $count + 1`
done
for bad in bad.profileSubmit* ; do
	$toolsdir/dparse submit $role $bad
	count=`expr $count + 1`
done
for bad in bad.profileReview* ; do
	$toolsdir/dparse review $role $bad
	count=`expr $count + 1`
done
for bad in bad.profileProcess* ; do
	$toolsdir/dparse approve $role $bad
	count=`expr $count + 1`
done
for bad in bad.checkRequest* ; do
	$toolsdir/dparse check $role $bad
	count=`expr $count + 1`
done
for bad in bad.displayCertFromRequest* ; do
	$toolsdir/dparse fetch $role $bad
	count=`expr $count + 1`
done
done
echo $count samples.
