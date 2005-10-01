noinst_LTLIBRARIES = libgcrypt-md-modules.la

libgcrypt_md_modules_la_SOURCES = \
sha1.c sha1.h \
sha256.c sha256.h \
sha512.c sha512.h \
rmd160.c rmd160.h \
crc.c crc.h \
md4.c md4.h \
md5.c md5.h \
tiger.c tiger.h \
whirlpool.c whirlpool.h

libgcrypt_md_modules_la_CFLAGS = \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src \
@GPG_ERROR_CFLAGS@
