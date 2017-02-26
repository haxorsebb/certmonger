#!/bin/bash
topdir=$(cd ../..; pwd)
echo '#!/bin/bash -x' > build-all-images.sh
echo 'set -e' >> build-all-images.sh
echo '#!/bin/bash -x' > test-all.sh
echo 'set -e' >> test-all.sh
uid=`id -u`
gid=`id -g`
for dist in fedora debian ubuntu centos ; do
	env=
	pre=
	case $dist in
		fedora)
			versions="24 25 rawhide"
			install="dnf -q -y install --best --allowerasing"
			pre="RUN dnf -q -y distro-sync"
			first="dbus dbus-x11 redhat-rpm-config"
			tools="autoconf automake binutils dos2unix expect gawk gcc git libtool make mktemp python unix2dos which"
			libraries="openssl-devel nss-devel   libuuid-devel libtevent-devel dbus-devel    libcurl-devel        libxml2-devel xmlrpc-c-devel        libidn-devel krb5-devel  openldap-devel popt-devel diffutils  dbus-python openssl nss-tools     gettext-devel    glibc-devel gmp-devel"
			;;
		centos)
			versions="5 6 7"
			install="yum -q -y install"
			pre="RUN yum -q -y update"
			first="dbus dbus-x11 redhat-rpm-config"
			tools="autoconf automake binutils dos2unix expect gawk gcc git libtool make mktemp python unix2dos which"
			libraries="openssl-devel nss-devel   libuuid-devel libtevent-devel dbus-devel    libcurl-devel        libxml2-devel xmlrpc-c-devel        libidn-devel krb5-devel  openldap-devel popt-devel diffutils  dbus-python openssl nss-tools     gettext-devel    glibc-devel"
			;;
		debian)
			versions="wheezy jessie stretch sid"
			env="ENV DEBIAN_FRONTEND=noninteractive"
			pre="RUN apt-get clean && apt-get update"
			install="apt-get -y -qq install --no-install-recommends"
			first="apt-utils dbus dbus-x11"
			tools="autoconf automake autopoint binutils dos2unix expect gawk gcc git libtool make mktemp python"
			libraries="libssl-dev    libnss3-dev uuid-dev      libtevent-dev   libdbus-1-dev libcurl4-openssl-dev libxml2-dev   libxmlrpc-core-c3-dev libidn11-dev libkrb5-dev libldap2-dev   libpopt-dev diffutils python-dbus openssl libnss3-tools libgettextpo-dev libc6-dev   libgmp-dev"
			;;
		ubuntu)
			versions="trusty xenial zesty"
			env="ENV DEBIAN_FRONTEND=noninteractive"
			pre="RUN apt-get clean && apt-get update"
			first="apt-utils dbus dbus-x11"
			install="apt-get -y -qq install --no-install-recommends"
			tools="autoconf automake autopoint binutils dos2unix expect gawk gcc git libtool make mktemp python"
			libraries="libssl-dev    libnss3-dev uuid-dev      libtevent-dev   libdbus-1-dev libcurl4-openssl-dev libxml2-dev   libxmlrpc-core-c3-dev libidn11-dev libkrb5-dev libldap2-dev   libpopt-dev diffutils python-dbus openssl libnss3-tools libgettextpo-dev libc6-dev   libgmp-dev"
			;;
	esac
	for version in $versions ; do
		combo="$dist"-"$version"
		morelibraries=
		case "$combo" in
			centos-5)
				morelibraries=bind-libbind-devel
				;;
		esac
		mkdir -p "$combo"
		cat > "$combo"/Dockerfile <<- EOF
		FROM $dist:$version
		$env
		$pre
		RUN $install $first
		RUN $install $tools
		RUN $install $libraries $morelibraries
		RUN mkdir /build
		RUN echo certmongerbuilder::$uid:$gid:certmonger builder:/build:/bin/bash >> /etc/passwd
		RUN echo certmongerbuilder::$gid: >> /etc/group
		RUN chown -R $uid:$gid /build
		USER $uid:$gid
		EOF
		echo '#!/bin/bash -x' > build-"$combo"-image.sh
		echo docker build -t certmonger-dev:"$combo" ./"$combo"/ >> build-"$combo"-image.sh
		chmod +x build-"$combo"-image.sh
		echo docker build -t certmonger-dev:"$combo" ./"$combo"/ >> build-all-images.sh
		echo '#!/bin/bash -x' > test-"$combo".sh
		echo docker inspect certmonger-build-"$combo" \> /dev/null 2\> /dev/null \&\& docker rm -f certmonger-build-"$combo" >> test-"$combo".sh
		echo docker run --security-opt no-new-privileges -v "$topdir":/source:ro -it --name certmonger-build-"$combo" certmonger-dev:"$combo" /source/tests/docker/build-and-test.sh >> test-"$combo".sh
		chmod +x test-"$combo".sh
		echo docker inspect certmonger-build-"$combo" \> /dev/null 2\> /dev/null \&\& docker rm -f certmonger-build-"$combo" >> test-all.sh
		echo docker run --security-opt no-new-privileges -v "$topdir":/source:ro -it --name certmonger-build-"$combo" certmonger-dev:"$combo" /source/tests/docker/build-and-test.sh >> test-all.sh
	done
done
chmod +x build-all-images.sh
chmod +x test-all.sh
