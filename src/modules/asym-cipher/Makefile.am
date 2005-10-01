noinst_LTLIBRARIES = libgcrypt-ac-modules.la

libgcrypt_ac_modules_la_SOURCES = \
rsa.c rsa.h \
dsa.c dsa.h \
elg.c elg.h

libgcrypt_ac_modules_la_CFLAGS = \
-I$(top_builddir)/src/subsystems/mpi \
-I$(top_srcdir)/src/modules/hash \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src \
@GPG_ERROR_CFLAGS@
