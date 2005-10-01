noinst_LTLIBRARIES = libgcrypt-random.la

EXTRA_DIST = README

libgcrypt_random_la_CFLAGS = \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/modules/hash \
-I$(top_srcdir)/src \
@GPG_ERROR_CFLAGS@ \
-DBUILDING_RANDOM_SUBSYSTEM

libgcrypt_random_la_SOURCES = \
interface.c \
core.c \
source-dev.c \
source-egd.c \
source-unix.c \
gcrypt-random-internal.h \
gcrypt-random-common.h \
gcrypt-random.h
