## Process this file with automake to produce Makefile.in

# Libtool -version-info for libgcrypta.  See (libtool)Versioning
#
# 1. No interfaces changed, only implementations (good): Increment REVISION.
#
# 2. Interfaces added, none removed (good): Increment CURRENT, increment
#    AGE, set REVISION to 0.
#
# 3. Interfaces removed (BAD, breaks upward compatibility): Increment
#    CURRENT, set AGE and REVISION to 0.
#
# Rember to change this just before a release.


# It seems that we need gcrypt.m4 here too
EXTRA_DIST = libgcrypt-config.in  libgcrypt.m4

#INCLUDES =  -I$(top_srcdir)/intl

#OMIT_DEPENDENCIES = types.h


lib_LTLIBRARIES = libgcrypt.la

bin_SCRIPTS = libgcrypt-config

m4datadir = $(datadir)/aclocal
m4data_DATA = libgcrypt.m4

noinst_PROGRAMS = testapi
testapi_SOURCES = testapi.c
testapi_LDADD = libgcrypt.la

include_HEADERS = gcrypt.h

libgcrypt_la_LDFLAGS = -version-info \
      @LIBGCRYPT_LT_CURRENT@:@LIBGCRYPT_LT_REVISION@:@LIBGCRYPT_LT_AGE@ 
# limiting the exported symbols is not good for debugging.
#      -export-symbols libgcrypt.sym

libgcrypt_la_SOURCES =	 g10lib.h \
		         types.h \
			 cipher.h \
			 misc.c  \
			 global.c \
			 sexp.c \
			 stdmem.c \
			 stdmem.h \
			 secmem.c \
			 secmem.h \
		         mpi.h

libgcrypt_la_DEPENDENCIES = libgcrypt.sym \
			    ../cipher/libcipher.la ../mpi/libmpi.la
libgcrypt_la_LIBADD = ../cipher/libcipher.la  \
		      ../mpi/libmpi.la


BUILT_SOURCES = libgcrypt.sym

# libtool's --export-symbols-regex does not work in 1.3.2
# so we do it ourself
libgcrypt.sym: $(libgcrypt_la_OBJECTS)
	    $(NM) $(libgcrypt_la_OBJECTS) \
	      | $(AWK) '$$2=="T" && $$3 ~ /^gcry_/ {print $$3}' >libgcrypt.sym

