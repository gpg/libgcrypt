noinst_LTLIBRARIES = libgcrypt-cipher.la

EXTRA_DIST = README

libgcrypt_cipher_la_SOURCES = \
core.c \
interface.c \
gcrypt-cipher-common.h \
gcrypt-cipher-internal.h \
gcrypt-cipher.h

libgcrypt_cipher_la_CFLAGS = \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src \
@GPG_ERROR_CFLAGS@
