# Copyright (C) 1998,1999,2000,2001,2002,2003 Free Software Foundation, Inc.
#
# This file is part of Libgcrypt.
#
# Libgcrypt is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Libgcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

EXTRA_DIST = libgcrypt-config.in libgcrypt.m4 libgcrypt.vers
bin_SCRIPTS = libgcrypt-config
m4datadir = $(datadir)/aclocal
m4data_DATA = libgcrypt.m4
include_HEADERS = gcrypt.h gcrypt-module.h

# Enable thread-library-specific versions of the library.
if HAVE_PTHREAD
  ltlib_libgcrypt_pthread = libgcrypt-pthread.la
else
  ltlib_libgcrypt_pthread =
endif
if HAVE_PTH
  ltlib_libgcrypt_pth = libgcrypt-pth.la
else
  ltlib_libgcrypt_pth =
endif

noinst_LTLIBRARIES = libgcrypt-real.la
lib_LTLIBRARIES = libgcrypt.la \
	$(ltlib_libgcrypt_pthread) $(ltlib_libgcrypt_pth)

if HAVE_LD_VERSION_SCRIPT
  libgcrypt_version_script_cmd = -Wl,--version-script=$(srcdir)/libgcrypt.vers
else
  libgcrypt_version_script_cmd = 
endif

libgcrypt_real_la_SOURCES = \
g10lib.h types.h cipher.h \
misc.c  \
global.c \
sexp.c \
stdmem.c stdmem.h \
secmem.c secmem.h \
mpi.h \
missing-string.c \
module.c

libgcrypt_real_la_DEPENDENCIES = \
	../cipher/libcipher.la ../mpi/libmpi.la \
	$(srcdir)/libgcrypt.vers

libgcrypt_real_la_LIBADD = \
	../cipher/libcipher.la ../mpi/libmpi.la @GPG_ERROR_LIBS@

# Include backwards-compatible ath-approaches in the main library.
if HAVE_PTH
  ath_pth_src = ath-pth-compat.c
else
  ath_pth_src =
endif
if HAVE_PTHREAD
  ath_pthread_src = ath-pthread-compat.c
else
  ath_pthread_src =
endif
libgcrypt_la_SOURCES = ath.h ath-compat.c $(ath_pth_src) $(ath_pthread_src)

# These are the new ath-approaches.
libgcrypt_pthread_la_SOURCES = ath.h ath-pthread.c
libgcrypt_pth_la_SOURCES = ath.h ath-pth.c

AM_CFLAGS = @GPG_ERROR_CFLAGS@

# The standard version.
libgcrypt_la_LDFLAGS = $(libgcrypt_version_script_cmd) -version-info \
  @LIBGCRYPT_LT_CURRENT@:@LIBGCRYPT_LT_REVISION@:@LIBGCRYPT_LT_AGE@
libgcrypt_la_DEPENDENCIES = libgcrypt-real.la \
	@LTLIBOBJS@ $(srcdir)/libgcrypt.vers
libgcrypt_la_LIBADD = libgcrypt-real.la @LTLIBOBJS@ \
	@GPG_ERROR_LIBS@

# The pthread version.
libgcrypt_pthread_la_LDFLAGS = $(libgcrypt_version_script_cmd) -version-info \
	@LIBGCRYPT_LT_CURRENT@:@LIBGCRYPT_LT_REVISION@:@LIBGCRYPT_LT_AGE@
libgcrypt_pthread_la_DEPENDENCIES = libgcrypt-real.la \
	@LTLIBOBJS@ $(srcdir)/libgcrypt.vers
libgcrypt_pthread_la_LIBADD = libgcrypt-real.la @LTLIBOBJS@ \
	-lpthread @GPG_ERROR_LIBS@

# The pth version.
libgcrypt_pth_la_LDFLAGS = $(libgcrypt_version_script_cmd) -version-info \
	@LIBGCRYPT_LT_CURRENT@:@LIBGCRYPT_LT_REVISION@:@LIBGCRYPT_LT_AGE@
libgcrypt_pth_la_DEPENDENCIES = libgcrypt-real.la \
	@LTLIBOBJS@ $(srcdir)/libgcrypt.vers
libgcrypt_pth_la_LIBADD = libgcrypt-real.la @LTLIBOBJS@ \
	@PTH_LIBS@ @GPG_ERROR_LIBS@
