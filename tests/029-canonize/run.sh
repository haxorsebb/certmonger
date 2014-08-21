#!/bin/bash -e
cd $tmpdir
mkdir subdir
ln -s subdir otherdir
touch subdir/file
canon() {
	for loc in "$@" ; do
		$toolsdir/canon "$loc" | sed -r "s|$tmpdir|"'${tmpdir}'"|g"
		if `$toolsdir/canon dbm:"$loc"` != dbm:`$toolsdir/canon "$loc"` ; then
			echo `$toolsdir/canon dbm:"$loc"` -ne dbm:`$toolsdir/canon "$loc"`
			exit 1
		fi
		if `$toolsdir/canon sql:"$loc"` != sql:`$toolsdir/canon "$loc"` ; then
			echo `$toolsdir/canon sql:"$loc"` -ne sql:`$toolsdir/canon "$loc"`
			exit 1
		fi
	done
}
for loc in `pwd` . subdir subdir/ subdir/.. subdir/../subdir otherdir otherdir/ otherdir// otherdir/.. otherdir//../subdir `pwd`/otherdir//../subdir subdir/../otherdir subdir/file subdir/../subdir/file otherdir/file otherdir/../subdir/file subdir/../otherdir/file not-there subdir/not-there otherdir/not-there ; do
	canon $loc
done
