noinst_LTLIBRARIES = libgcrypt-compat.la

EXTRA_DIST = README

libgcrypt_compat_la_SOURCES = \
gcrypt-internal.h \
gcrypt-module.h \
gcrypt.h \
init.c \
global.c \
mpi.c \
random.c \
prime.c \
sexp.c \
module.c \
cipher.c \
md.c \
ac.c \
pubkey.c \
ath.c ath.h \
secmem.c secmem.h

libgcrypt_compat_la_CFLAGS = \
-I$(top_builddir)/src/subsystems/mpi \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src \
-I$(top_srcdir)/src/modules/asym-cipher \
-I$(top_srcdir)/src/modules/sym-cipher \
-I$(top_srcdir)/src/modules/hash \
@GPG_ERROR_CFLAGS@
