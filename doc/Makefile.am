## Process this file with automake to create Makefile.in

BUILT_SOURCES = version.sgml reference.html reference.ps


#EXTRA_DIST = version.sgml.in $(BUILT_SOURCES)

# pkgdata_DATA = reference.html reference.ps


CLEANFILES = reference.aux reference.log reference.tex reference.dvi


# reference.sgml : version.sgml


if HAVE_DB2MAN
%.1 : %.sgml
	$(DB2MAN) $<  >$@
endif

if HAVE_DB2TEX
%.ps : %.dvi
	dvips -o $@ $<

%.tex : %.sgml
	$(DB2TEX) -V generate-book-toc $< > $@

%.dvi : %.tex
	$(JADETEX) $<
endif

if HAVE_DB2HTML
%.html : %.sgml
	$(DB2HTML) --nosplit $<
endif





