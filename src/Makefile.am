## Process this file with automake to produce Makefile.in

## EXTRA_DIST =
INCLUDES =  -I$(top_srcdir)/include -I$(top_srcdir)/intl

lib_LTLIBRARIES = libgcrypt.la

#noinst_PROGRAMS = sexp
#sexp_SOURCES = sexp.c mpiapi.c
#sexp_LDADD =  ../cipher/libcipher.la ../mpi/libmpi.la	../util/libutil.la ./libgcrypt.la @INTLLIBS@


libgcrypt_la_LDFLAGS = -version-info 0:0:0 -export-symbols libgcrypt.sym
libgcrypt_la_SOURCES =	 gcrypt.h \
			 misc.c  \
			 global.c \
			 sexp.c \
			 mpiapi.c

libgcrypt_la_DEPENDENCIES = libgcrypt.sym
libgcrypt_la_LIBADD = ../cipher/libcipher.la  \
		      ../mpi/libmpi.la

BUILT_SOURCES = libgcrypt.sym

# libtool's --export-symbols-regex does not work in 1.3.2
# so we do it ourself
libgcrypt.sym: $(libgcrypt_la_OBJECTS)
	    $(NM) $(libgcrypt_la_OBJECTS) \
	      | $(AWK) '$$2=="T" && $$3 ~ /^gcry_/ {print $$3}' >libgcrypt.sym

