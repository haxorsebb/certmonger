srpm:
	dnf -y install git
	$(eval version := $(shell grep AC_INIT configure.ac | cut -d, -f2 | rev | cut -c2- | rev))
	git archive -v --format=tar --prefix=certmonger-${version}/ HEAD | gzip > certmonger-${version}.tar.gz
	rpmbuild \
		--define "_sourcedir `pwd`" \
		--define "_srcrpmdir ${outdir}" \
		-bs `pwd`/certmonger.spec
