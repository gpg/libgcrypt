noinst_LTLIBRARIES = libgcrypt-common.la

libgcrypt_common_la_CFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src \
@GPG_ERROR_CFLAGS@

libgcrypt_common_la_LDFLAGS = \
@GPG_ERROR_LDFLAGS@

libgcrypt_common_la_LIBADD = \
@GPG_ERROR_LIBS@

libgcrypt_common_la_SOURCES = \
error.c \
control.c logger.c memory.c \
misc.c \
gcrypt-common-internal.h \
gcrypt-common-common.h \
gcrypt-common.h
