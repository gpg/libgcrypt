## Process this file with automake to produce Makefile.in

# It seems that we need gcrypt.m4 here too
EXTRA_DIST = gcrypt-config.in  gcrypt.m4

INCLUDES =  -I$(top_srcdir)/include -I$(top_srcdir)/intl

lib_LTLIBRARIES = libgcrypt.la

bin_SCRIPTS = gcrypt-config

m4datadir = $(datadir)/aclocal
m4data_DATA = gcrypt.m4

noinst_PROGRAMS = testapi sexp
sexp_SOURCES = sexp.c
sexp_LDADD =  libgcrypt.la
testapi_SOURCES = testapi.c
testapi_LDADD = libgcrypt.la

include_HEADERS = gcrypt.h

libgcrypt_la_LDFLAGS = -version-info 0:0:0 -export-symbols libgcrypt.sym
libgcrypt_la_SOURCES =	 g10lib.h \
			 mpi.h \
			 cipher.h \
			 misc.c  \
			 global.c \
			 sexp.c \
			 wrapper.c \
			 stdmem.c \
			 stdmem.h \
			 secmem.c \
			 secmem.h

libgcrypt_la_DEPENDENCIES = libgcrypt.sym
libgcrypt_la_LIBADD = ../cipher/libcipher.la  \
		      ../mpi/libmpi.la


BUILT_SOURCES = libgcrypt.sym

# libtool's --export-symbols-regex does not work in 1.3.2
# so we do it ourself
libgcrypt.sym: $(libgcrypt_la_OBJECTS)
	    $(NM) $(libgcrypt_la_OBJECTS) \
	      | $(AWK) '$$2=="T" && $$3 ~ /^gcry_/ {print $$3}' >libgcrypt.sym



