DIST_SUBDIRS = src doc tests
SUBDIRS = src doc tests
EXTRA_DIST = BUGS autogen.sh DESIGN
DISTCLEANFILES = 


# Add all the files listed in "distfiles" files to the distribution,
# apply version number s to some files and create a VERSION file which
# we need for the Prereq: patch file trick. 
dist-hook:
	@set -e; \
	 for file in `cd $(top_srcdir); \
	      find . -type f -name distfiles`; do \
	    dir=`dirname $$file` ; $(mkinstalldirs) $(distdir)/$$dir ; \
	    for i in distfiles `cat $(top_srcdir)/$$file` ; do \
		ln $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i 2> /dev/null \
		|| cp -p $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i; \
	    done ; \
	done
	@set -e; \
	echo "$(VERSION)" > $(distdir)/VERSION
