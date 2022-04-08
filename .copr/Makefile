srpm:
	pushd "${cloned_repodir}"; \
	git archive -v --format=tar --prefix=certmonger-0.79.15/ HEAD | gzip > certmonger-0.79.15.tar.gz; \
	rpmbuild \
		 --define "_sourcedir `pwd`" \
		--define "_srcrpmdir ${outdir}" \
		-bs `pwd`/certmonger.spec; \
	popd

