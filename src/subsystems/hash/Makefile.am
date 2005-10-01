noinst_LTLIBRARIES = libgcrypt-md.la

EXTRA_DIST = README

libgcrypt_md_la_SOURCES = \
core.c \
interface.c \
gcrypt-md-common.h \
gcrypt-md-internal.h \
gcrypt-md.h

libgcrypt_md_la_CFLAGS = \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src \
@GPG_ERROR_CFLAGS@
