noinst_LTLIBRARIES = libgcrypt-ath.la

EXTRA_DIST = README

libgcrypt_ath_la_CFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src \
@GPG_ERROR_CFLAGS@

libgcrypt_ath_la_SOURCES = \
ath.c \
gcrypt-ath-internal.h gcrypt-ath-common.h
