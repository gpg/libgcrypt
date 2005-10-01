noinst_LTLIBRARIES = libgcrypt-secmem.la

EXTRA_DIST = README

libgcrypt_secmem_la_CFLAGS = \
-I$(top_builddir)/src/subsystems/mpi \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src \
-I$(top_srcdir)/src/include \
@GPG_ERROR_CFLAGS@

libgcrypt_secmem_la_SOURCES = \
core.c \
interface.c \
gcrypt-secmem.h \
gcrypt-secmem-common.h \
gcrypt-secmem-internal.h
