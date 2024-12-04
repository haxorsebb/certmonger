#!/bin/bash -e
count=0
for role in agent end-entity ; do
for good in good.profileSubmit*.xml ; do
	$toolsdir/dparse submit $role $good
	count=`expr $count + 1`
done
for good in good.profileReview* ; do
	$toolsdir/dparse review $role $good
	count=`expr $count + 1`
done
for good in good.checkRequest*.xml ; do
	$toolsdir/dparse check $role $good
	count=`expr $count + 1`
done
for good in good.displayCertFromRequest*.xml ; do
	$toolsdir/dparse fetch $role $good
	count=`expr $count + 1`
done
for good in good.profileList*.xml ; do
	$toolsdir/dparse profiles $role $good
	count=`expr $count + 1`
done
for bad in bad.profileSubmit*.xml ; do
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
for bad in bad.checkRequest*.xml ; do
	$toolsdir/dparse check $role $bad
	count=`expr $count + 1`
done
for bad in bad.displayCertFromRequest* ; do
	$toolsdir/dparse fetch $role $bad
	count=`expr $count + 1`
done
done

for role in json ; do
for good in good.profileSubmit*.json ; do
	$toolsdir/dparse submit $role $good
	count=`expr $count + 1`
done
for good in good.checkRequest*.json ; do
	$toolsdir/dparse check $role $good
	count=`expr $count + 1`
done
for good in good.displayCertFromRequest*.json ; do
	$toolsdir/dparse fetch $role $good
	count=`expr $count + 1`
done
for good in good.profileList*.json ; do
	$toolsdir/dparse profiles $role $good
	count=`expr $count + 1`
done
for bad in bad.profileSubmit*.json ; do
	$toolsdir/dparse submit $role $bad
	count=`expr $count + 1`
done
for bad in bad.checkRequest*.json ; do
	$toolsdir/dparse check $role $bad
	count=`expr $count + 1`
done
for bad in bad.displayCertFromRequest*.json ; do
	$toolsdir/dparse fetch $role $bad
	count=`expr $count + 1`
done
done
echo $count samples.
