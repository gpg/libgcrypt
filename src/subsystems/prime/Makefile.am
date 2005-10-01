noinst_LTLIBRARIES = libgcrypt-prime.la

EXTRA_DIST = README

libgcrypt_prime_la_CFLAGS = \
-I$(top_builddir)/src/subsystems/mpi \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src \
-I$(top_srcdir)/src/include \
@GPG_ERROR_CFLAGS@

libgcrypt_prime_la_SOURCES = \
core.c \
interface.c \
gcrypt-prime-internal.h \
gcrypt-prime-common.h \
gcrypt-prime.h
