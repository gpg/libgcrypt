noinst_LTLIBRARIES = libgcrypt-ac.la

EXTRA_DIST = README

libgcrypt_ac_la_SOURCES = \
core.c \
interface.c \
gcrypt-ac-common.h \
gcrypt-ac-internal.h \
gcrypt-ac.h

libgcrypt_ac_la_CFLAGS = \
-I$(top_builddir)/src/subsystems/mpi \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src \
-I$(top_srcdir)/src/subsystems/hash/modules \
@GPG_ERROR_CFLAGS@
