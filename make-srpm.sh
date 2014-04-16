#!/bin/bash
#
# Set $FORCE_VERSION to force the version.
# Set $FORCE_RELEASE to force the release.
#
tmpdir=`mktemp -d`
if test -z "$tmpdir" ; then
	echo Need mktemp.
	exit 1
fi
trap 'rm -fr "$tmpdir"' EXIT

CHECKOUTDIR=$PWD
pushd "$tmpdir" > /dev/null
git clone -q "$CHECKOUTDIR" cm
cd cm
qs() {
	rpm -q --define 'debug_package 0' --specfile "$tmpdir"/cm/certmonger.spec "$@"
}
VERSION=${FORCE_VERSION:-`qs --qf '%{version}'`}
RELEASE=${FORCE_RELEASE:-`qs --qf '%{release}'`}
sed -e "s|^Version:.*|Version: $VERSION|g" \
    -e "s|^Release:.*|Release: $RELEASE|g" \
	"$tmpdir"/cm/certmonger.spec > "$tmpdir"/certmonger.spec
autoreconf -i -f && \
configure_dist_target_only=true \
./configure --disable-maintainer-mode --disable-systemd --disable-sysvinit \
	--without-idn --without-openssl --without-gmp \
	--disable-ec --disable-dsa \
	"$@" && \
make dist VERSION="$VERSION" PACKAGE_VERSION="$VERSION" && \
rpmbuild --define "_topdir $tmpdir"/cm \
	 --define "_srcrpmdir $tmpdir"/cm \
	 --define "_sourcedir $tmpdir"/cm \
	-bs "$tmpdir"/certmonger.spec && \
cp -v *.src.rpm $CHECKOUTDIR
popd > /dev/null
