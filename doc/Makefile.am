## Process this file with automake to create Makefile.in

sgml_source = reference.sgml \
              cipher-ref.sgml digest-ref.sgml misc-ref.sgml pubkey-ref.sgml 

EXTRA_DIST = $(sgml_source) version.sgml.in \
             reference.dvi reference.html reference.ps reference.texi

pkgdata_DATA = reference.dvi reference.ps reference.html reference.texi

BUILT_SOURCES = version.sgml \
             reference.dvi reference.html reference.ps reference.texi
CLEANFILES = reference.aux reference.log reference.tex reference.dvi

reference.sgml : version.sgml


%.ps : %.dvi
	dvips -o $@ $<

# we might want something like this: -V generate-book-toc  
# or use a custom stylesheet.
%.dvi : %.sgml
	$(DB2ANY) --mode dvi $<

%.html : %.sgml
	$(DB2ANY) --mode html $<

%.texi : %.sgml
	$(DB2ANY) --mode texinfo $<

