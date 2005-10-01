noinst_LTLIBRARIES = libgcrypt-sexp.la

EXTRA_DIST = README

libgcrypt_sexp_la_CFLAGS = \
-I$(top_builddir)/src/subsystems/mpi \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src \
-I$(top_srcdir)/src/include \
@GPG_ERROR_CFLAGS@

libgcrypt_sexp_la_SOURCES = \
core.c \
interface.c \
gcrypt-sexp-internal.h \
gcrypt-sexp-common.h \
gcrypt-sexp.h
