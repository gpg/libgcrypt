## Process this file with automake to produce Makefile.in

SUBDIRS = jnlib util mpi cipher src doc
EXTRA_DIST = README-alpha BUGS
DISTCLEANFILES = gcrypt-defs.h 


# Add all the files listed in "distfiles" files to the distribution,
# apply version number s to some files and create a VERSION file which
# we need for the Prereq: patch file trick.
dist-hook:
	@set -e; \
	 for file in `cd $(top_srcdir); find . -type f -name distfiles`; do \
	    dir=`dirname $$file` ; $(mkinstalldirs) $(distdir)/$$dir ; \
	    for i in distfiles `cat $(top_srcdir)/$$file` ; do \
		ln $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i 2> /dev/null \
		|| cp -p $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i; \
	    done ; \
	done
	@set -e; \
	sed -e 's/@pkg_version@/$(VERSION)/g' \
	    $(top_srcdir)/scripts/gnupg.spec.in \
	    > $(distdir)/scripts/gnupg.spec ; \
	echo "$(VERSION)" > $(distdir)/VERSION


